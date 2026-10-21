//! Source identity for private checkpoint receipts, selected before dispatch.

use std::{path::PathBuf, sync::Arc};

use microsandbox_db::DbWriteConnection;
use microsandbox_protocol::control::ConfigurationCaptureReceipt;
use microsandbox_runtime::ipc::SandboxLifecycleGuard;
use microsandbox_runtime::retention::{
    CapturedConfiguration, RetainedConfiguration, RetentionOwner, ScriptBackingEvidence,
    select_stopped_configuration,
};

use microsandbox_types::snapshot::saved_config::{
    MAX_SAVED_CONFIG_ENTRIES, MAX_SAVED_SCRIPT_BYTES, MAX_SAVED_SCRIPTS_BYTES,
};

use crate::backend::{ControlSession, LocalBackend};
use crate::sandbox::SandboxConfig;
use crate::{MicrosandboxError, MicrosandboxResult};

use super::stopped_script_backing::StoppedScriptObservation;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Confirmed source and backing retained together through local publication.
/// No Debug/serialization: portable emission must project and apply exclusions explicitly.
pub(crate) struct CapturedSandboxConfiguration {
    // Keep the guarded source verbatim: decoding SandboxConfig supplies defaults for
    // absent fields, and reserializing it would manufacture historical evidence. The
    // owner/generation identify the captured transition, not current mutable state.
    source: RetainedConfiguration,
    configuration: SandboxConfig,
    scripts: Option<ScriptBackingEvidence>,
}

/// No Debug or serialization: the eventual receipt can contain private local configuration.
pub(crate) struct ExpectedConfigurationCapture {
    directory: PathBuf,
    owner: RetentionOwner,
}

/// Retains lifecycle ownership and exact evidence through a stopped disk cut.
/// Raw values remain private and are compared without formatting diagnostics.
pub(crate) struct StoppedConfigurationCapture {
    db: DbWriteConnection,
    directory: PathBuf,
    sandbox_id: i32,
    guard: Arc<SandboxLifecycleGuard>,
    source: Option<RetainedConfiguration>,
    scripts: StoppedScriptObservation,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl CapturedSandboxConfiguration {
    fn new(
        source: RetainedConfiguration,
        scripts: Option<ScriptBackingEvidence>,
    ) -> MicrosandboxResult<Option<Self>> {
        let Some(configuration) = decode_configuration(source.source.as_ref())? else {
            return Ok(None);
        };
        let captured = Self {
            source,
            configuration,
            scripts,
        };
        captured.validate_script_inventory()?;
        Ok(Some(captured))
    }

    pub(crate) fn configuration(&self) -> &SandboxConfig {
        &self.configuration
    }

    fn validate_script_inventory(&self) -> MicrosandboxResult<()> {
        let Some(ScriptBackingEvidence::Observed {
            files,
            runtime_directory,
            scripts_directory,
        }) = &self.scripts
        else {
            return Ok(());
        };
        let expected = self
            .source
            .source
            .as_ref()
            .and_then(|source| source.pointer("/runtime/scripts"))
            .and_then(serde_json::Value::as_object);
        // A runtime's claimed inventory must match its recorded source registration. Body
        // equality is deliberately not required: the guest can have changed the actual files.
        // An older source with no registration field still accepts an empty observation;
        // the original absence stays in `source`, rather than becoming a recorded default.
        let matches = expected.map_or(files.is_empty(), |expected| {
            files.len() == expected.len() && files.keys().all(|name| expected.contains_key(name))
        });
        if files.len() > MAX_SAVED_CONFIG_ENTRIES
            || !matches
            || runtime_directory.mode > 0o777
            || scripts_directory.mode > 0o777
        {
            return Err(invalid(
                "captured script inventory or directory metadata is invalid",
            ));
        }
        let mut total = 0usize;
        for script in files.values() {
            if script.mode > 0o777 || script.content.len() > MAX_SAVED_SCRIPT_BYTES {
                return Err(invalid(
                    "captured script backing exceeds its representation",
                ));
            }
            total = total
                .checked_add(script.content.len())
                .ok_or_else(|| invalid("captured scripts exceed their size bound"))?;
            if total > MAX_SAVED_SCRIPTS_BYTES {
                return Err(invalid("captured scripts exceed their size bound"));
            }
        }
        Ok(())
    }
}

impl ExpectedConfigurationCapture {
    /// Older peers keep the original request and perform no retention catalog/file reads.
    pub(crate) async fn prepare(
        local: &LocalBackend,
        name: &str,
        session: &ControlSession,
    ) -> MicrosandboxResult<Option<Self>> {
        if !session.capabilities().configuration_capture {
            return Ok(None);
        }
        let run = session.run_identity();
        let catalog = local
            .config()
            .home()
            .join(microsandbox_utils::DB_SUBDIR)
            .join(microsandbox_utils::DB_FILENAME);
        let owner = RetentionOwner::for_run(
            local.db().await?.write(),
            &catalog,
            run.sandbox_id,
            run.run_id,
            String::new(),
        )
        .await
        .map_err(|_| invalid("could not establish capture configuration owner"))?;
        Ok(Some(Self {
            directory: local.sandboxes_dir().join(name),
            owner,
        }))
    }

    /// Consume evidence only after the caller verifies the immutable capture and its root.
    /// The source lineage guard must remain held, so removal cannot recycle this directory.
    pub(crate) fn read(
        mut self,
        checkpoint_id: &str,
        capture_root: &str,
        receipt: Option<&ConfigurationCaptureReceipt>,
    ) -> MicrosandboxResult<Option<CapturedSandboxConfiguration>> {
        let receipt =
            receipt.ok_or_else(|| invalid("runtime omitted requested configuration receipt"))?;
        let captured =
            CapturedConfiguration::read(&self.directory, checkpoint_id, capture_root, receipt)
                .map_err(|_| invalid("invalid checkpoint configuration receipt"))?;
        let (source, scripts) = captured.into_parts();
        let Some(source) = source else {
            return Ok(None);
        };
        // The authenticated, run-bound control response supplies the receipt digest and hence
        // boot identity. Catalog file/row incarnations were selected independently before dispatch.
        // Do not compare current generation: a subsequent modify must not invalidate this capture.
        self.owner
            .runtime_boot_id
            .clone_from(&source.owner.runtime_boot_id);
        if source.owner != self.owner
            || source.owner.runtime_boot_id.is_empty()
            || source.generation == 0
        {
            return Err(invalid(
                "checkpoint configuration belongs to another source run",
            ));
        }
        CapturedSandboxConfiguration::new(source, scripts)
    }
}

impl StoppedConfigurationCapture {
    pub(crate) async fn prepare(
        db: DbWriteConnection,
        directory: PathBuf,
        sandbox_id: i32,
        guard: Arc<SandboxLifecycleGuard>,
    ) -> MicrosandboxResult<Self> {
        let source = select_stopped_configuration(&db, &directory, sandbox_id, &guard)
            .await
            .map_err(|_| invalid("could not select stopped capture configuration"))?;
        let configuration =
            decode_configuration(source.as_ref().and_then(|source| source.source.as_ref()))?;
        let scripts = StoppedScriptObservation::observe(&directory, configuration.as_ref());
        Ok(Self {
            scripts,
            db,
            directory,
            sandbox_id,
            guard,
            source,
        })
    }

    pub(crate) fn configuration(&self) -> MicrosandboxResult<Option<SandboxConfig>> {
        decode_configuration(
            self.source
                .as_ref()
                .and_then(|record| record.source.as_ref()),
        )
    }

    /// Lifecycle ownership excludes a runtime restart, but older metadata writers can still
    /// change catalog provenance. Detect an observed change rather than publishing stale evidence.
    pub(crate) async fn finish(self) -> MicrosandboxResult<Option<CapturedSandboxConfiguration>> {
        let current =
            select_stopped_configuration(&self.db, &self.directory, self.sandbox_id, &self.guard)
                .await
                .map_err(|_| invalid("could not revalidate stopped capture configuration"))?;
        let unchanged = match (&self.source, &current) {
            (None, None) => true,
            (Some(before), Some(after)) => {
                before.owner == after.owner
                    && before.generation == after.generation
                    && before.source == after.source
            }
            _ => false,
        };
        if !unchanged {
            return Err(invalid(
                "configuration evidence changed during stopped capture",
            ));
        }
        let scripts = self.scripts.finish();
        match self.source {
            Some(source) => CapturedSandboxConfiguration::new(source, Some(scripts)),
            None => Ok(None),
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn decode_configuration(
    value: Option<&serde_json::Value>,
) -> MicrosandboxResult<Option<SandboxConfig>> {
    value
        .map(|value| serde_json::from_value(value.clone()))
        .transpose()
        // Serde diagnostics can contain literal values. Never forward them from this boundary.
        .map_err(|_| invalid("invalid captured sandbox configuration"))
}

fn invalid(message: &str) -> MicrosandboxError {
    MicrosandboxError::SnapshotIntegrity(message.into())
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use microsandbox_runtime::retention::ScriptBackingUnknown;
    use sea_orm::ConnectionTrait;
    use sha2::{Digest, Sha256};

    use super::*;

    struct Fixture {
        home: tempfile::TempDir,
        owner: RetentionOwner,
        value: serde_json::Value,
    }

    impl Fixture {
        fn new() -> Self {
            let home = tempfile::tempdir().unwrap();
            std::fs::create_dir_all(home.path().join("last-active/captures")).unwrap();
            let owner = RetentionOwner {
                catalog_file: [1, 2],
                sandbox_id: 3,
                sandbox_created_at: Some("created".into()),
                run_id: 4,
                run_started_at: "started".into(),
                runtime_boot_id: "boot".into(),
            };
            let mut config = SandboxConfig::default();
            config.spec.runtime.user = Some("captured-user".into());
            let value = serde_json::json!({
                "schema": 1, "checkpoint_id": "capture_one", "capture_root": "full:root",
                "source": {"owner": owner, "generation": 2,
                    "source": serde_json::to_value(config.clone_for_persistence()).unwrap()},
            });
            Self { home, owner, value }
        }

        fn read(
            &self,
            value: &serde_json::Value,
        ) -> MicrosandboxResult<Option<CapturedSandboxConfiguration>> {
            let bytes = serde_json::to_vec(value).unwrap();
            std::fs::write(
                self.home
                    .path()
                    .join("last-active/captures/capture_one.json"),
                &bytes,
            )
            .unwrap();
            let mut owner = self.owner.clone();
            // Boot identity is authenticated by the control response, never read from current state.
            owner.runtime_boot_id.clear();
            ExpectedConfigurationCapture {
                directory: self.home.path().to_path_buf(),
                owner,
            }
            .read(
                "capture_one",
                "full:root",
                Some(&ConfigurationCaptureReceipt {
                    sha256: hex::encode(Sha256::digest(bytes)),
                }),
            )
        }
    }

    #[test]
    fn receipt_selects_captured_configuration_without_consulting_current_generation() {
        let fixture = Fixture::new();
        // These files deliberately disagree. Neither is authoritative for an immutable capture.
        std::fs::write(
            fixture.home.path().join("last-active/state.json"),
            b"new generation",
        )
        .unwrap();
        std::fs::write(
            fixture.home.path().join("config.json"),
            b"pending desired config",
        )
        .unwrap();
        let selected = fixture.read(&fixture.value).unwrap().unwrap();
        assert_eq!(
            selected.configuration().spec.runtime.user.as_deref(),
            Some("captured-user")
        );
    }

    #[test]
    fn receipt_preserves_field_presence_and_confirmed_generation_without_defaulting_evidence() {
        let fixture = Fixture::new();
        let mut value = fixture.value.clone();
        value["scripts"] = serde_json::json!({
            "state": "observed",
            "runtime_directory": {"uid": 0, "gid": 0, "mode": 493},
            "scripts_directory": {"uid": 0, "gid": 0, "mode": 493},
            "files": {},
        });
        // All three decode successfully, but they are different evidence for portable capture.
        // Missing means not recorded; null and an empty command are deliberate source values.
        for command in [
            None,
            Some(serde_json::Value::Null),
            Some(serde_json::json!([])),
        ] {
            let raw = value["source"]["source"].as_object_mut().unwrap();
            raw.remove("resources");
            raw.remove("init");
            let runtime = raw.get_mut("runtime").unwrap().as_object_mut().unwrap();
            runtime.remove("scripts");
            runtime.remove("cmd");
            if let Some(command) = command {
                runtime.insert("cmd".into(), command);
            }
            let selected = fixture.read(&value).unwrap().unwrap();
            assert!(selected.configuration().spec.resources.cpus > 0);
            assert_eq!(selected.source.generation, 2);
            assert!(selected.source.owner == fixture.owner);
            assert_eq!(
                selected.source.source.as_ref(),
                Some(&value["source"]["source"])
            );
            let source = selected.source.source.as_ref().unwrap();
            assert!(source.get("resources").is_none());
            assert!(source.get("init").is_none());
            assert!(source.pointer("/runtime/scripts").is_none());
        }
        value["scripts"]["files"]["unregistered"] = serde_json::json!({
            "content": "PRIVATE_INVENTED_SCRIPT", "uid": 0, "gid": 0, "mode": 493,
        });
        let error = fixture.read(&value).err().unwrap().to_string();
        assert!(error.contains("captured script inventory"));
        assert!(!error.contains("PRIVATE_INVENTED_SCRIPT"));
    }

    #[test]
    fn configuration_receipt_rejects_cross_catalog_row_and_run_evidence() {
        let fixture = Fixture::new();
        for (field, value) in [
            ("catalog_file", serde_json::json!([8, 9])),
            ("sandbox_id", serde_json::json!(5)),
            ("sandbox_created_at", serde_json::json!("recreated")),
            ("run_id", serde_json::json!(6)),
            ("run_started_at", serde_json::json!("restarted")),
            ("runtime_boot_id", serde_json::json!("")),
        ] {
            let mut changed = fixture.value.clone();
            changed["source"]["owner"][field] = value;
            assert!(fixture.read(&changed).is_err(), "accepted changed {field}");
        }
        let mut changed = fixture.value.clone();
        changed["source"]["generation"] = serde_json::json!(0);
        assert!(fixture.read(&changed).is_err());
        for field in ["checkpoint_id", "capture_root"] {
            let mut changed = fixture.value.clone();
            changed[field] = serde_json::json!("other_capture");
            assert!(fixture.read(&changed).is_err(), "accepted changed {field}");
        }
    }

    #[test]
    fn unknown_evidence_is_not_a_default_and_invalid_values_are_redacted() {
        let fixture = Fixture::new();
        let mut unknown = fixture.value.clone();
        unknown["source"] = serde_json::Value::Null;
        assert!(fixture.read(&unknown).unwrap().is_none());
        let mut unknown = fixture.value.clone();
        unknown["source"]["source"] = serde_json::Value::Null;
        assert!(fixture.read(&unknown).unwrap().is_none());
        let mut invalid = fixture.value.clone();
        invalid["source"]["source"] = serde_json::json!("PRIVATE_SECRET_VALUE");
        let error = fixture.read(&invalid).err().unwrap().to_string();
        assert!(error.contains("invalid captured sandbox configuration"));
        assert!(!error.contains("PRIVATE_SECRET_VALUE"));
        let error = ExpectedConfigurationCapture {
            directory: fixture.home.path().to_path_buf(),
            owner: fixture.owner,
        }
        .read("capture_one", "full:root", None)
        .err()
        .unwrap()
        .to_string();
        assert!(error.contains("omitted requested configuration receipt"));
    }

    struct StoppedFixture {
        home: tempfile::TempDir,
        db: DbWriteConnection,
        guard: Arc<SandboxLifecycleGuard>,
    }

    impl StoppedFixture {
        async fn new() -> Self {
            use microsandbox_runtime::retention::{
                RetentionJournal, RetentionTerminalOrigin, seal_terminal,
            };
            use sea_orm::{DbBackend, Statement};

            let home = tempfile::tempdir().unwrap();
            let path = home.path().join("catalog.db");
            let db = DbWriteConnection::open(
                &path,
                std::time::Duration::from_secs(1),
                std::time::Duration::from_secs(1),
            )
            .await
            .unwrap();
            db.execute_unprepared(
                "CREATE TABLE sandbox (id INTEGER PRIMARY KEY, created_at TEXT, status TEXT, config TEXT, active_config TEXT);
                 CREATE TABLE run (id INTEGER PRIMARY KEY, sandbox_id INTEGER, started_at TEXT, status TEXT, terminated_at TEXT, pid INTEGER);
                 INSERT INTO sandbox VALUES (1, 'created', 'Stopped', 'pending desired config', NULL);
                 INSERT INTO run VALUES (1, 1, 'started', 'Terminated', 'ended', NULL);"
            ).await.unwrap();
            let guard = Arc::new(
                microsandbox_runtime::ipc::try_acquire_lifecycle_guard(home.path(), "source")
                    .unwrap()
                    .unwrap(),
            );
            let owner = RetentionOwner::for_run(&db, &path, 1, 1, "boot".into())
                .await
                .unwrap();
            let mut config = SandboxConfig::default();
            config.spec.runtime.user = Some("last-active-user".into());
            config
                .spec
                .runtime
                .scripts
                .insert("task".into(), "DECLARED_LAST_ACTIVE_SCRIPT".into());
            std::fs::create_dir_all(home.path().join("runtime/scripts")).unwrap();
            std::fs::write(
                home.path().join("runtime/scripts/task"),
                "OBSERVED_LAST_ACTIVE_SCRIPT",
            )
            .unwrap();
            #[cfg(unix)]
            microsandbox_filesystem::PassthroughFs::set_runtime_backing_permissions(
                &std::fs::File::open(home.path().join("runtime/scripts/task")).unwrap(),
                42,
                43,
                0o640,
            )
            .unwrap();
            let source = serde_json::to_value(config.clone_for_persistence()).unwrap();
            db.execute_raw(Statement::from_sql_and_values(
                DbBackend::Sqlite,
                "UPDATE sandbox SET active_config = ?",
                [source.to_string().into()],
            ))
            .await
            .unwrap();
            let mut journal = RetentionJournal::begin_start(home.path(), owner).unwrap();
            journal.confirm(Some(source)).unwrap();
            assert!(
                seal_terminal(
                    &db,
                    home.path(),
                    1,
                    1,
                    Some("boot"),
                    RetentionTerminalOrigin::RuntimeExit
                )
                .await
                .unwrap()
            );
            db.execute_unprepared("UPDATE sandbox SET active_config = NULL")
                .await
                .unwrap();
            Self { home, db, guard }
        }

        async fn select(&self) -> MicrosandboxResult<StoppedConfigurationCapture> {
            StoppedConfigurationCapture::prepare(
                self.db.clone(),
                self.home.path().to_path_buf(),
                1,
                Arc::clone(&self.guard),
            )
            .await
        }
    }

    #[test]
    fn live_receipt_keeps_observed_backing_separate_and_rejects_forged_inventory() {
        let fixture = Fixture::new();
        let mut value = fixture.value.clone();
        value["source"]["source"]["runtime"]["scripts"] =
            serde_json::json!({"task": "DECLARED_SOURCE"});
        value["scripts"] = serde_json::json!({
            "state": "observed",
            "runtime_directory": {"uid": 0, "gid": 0, "mode": 493},
            "scripts_directory": {"uid": 44, "gid": 45, "mode": 456},
            "files": {"task": {"content": "OBSERVED_BACKING", "uid": 42, "gid": 43, "mode": 416}},
        });
        let selected = fixture.read(&value).unwrap().unwrap();
        assert_eq!(
            selected.configuration().spec.runtime.scripts["task"],
            "DECLARED_SOURCE"
        );
        let Some(ScriptBackingEvidence::Observed { files, .. }) = selected.scripts else {
            panic!("discarded observed backing")
        };
        assert_eq!(files["task"].content, "OBSERVED_BACKING");
        assert_eq!(files["task"].mode, 0o640);
        for invalid_scripts in [
            serde_json::json!({"PRIVATE_UNREGISTERED": {"content": "PRIVATE_CONTENT", "uid": 0, "gid": 0, "mode": 493}}),
            serde_json::json!({"task": {"content": "PRIVATE_CONTENT", "uid": 0, "gid": 0, "mode": 4095}}),
            serde_json::json!({}),
        ] {
            let mut invalid = value.clone();
            invalid["scripts"]["files"] = invalid_scripts;
            let error = fixture.read(&invalid).err().unwrap().to_string();
            assert!(!error.contains("PRIVATE"));
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn stopped_script_backing_uses_last_active_inventory_and_observed_bytes() {
        let fixture = StoppedFixture::new().await;
        fixture.db.execute_unprepared(r#"UPDATE sandbox SET config = '{"runtime":{"scripts":{"pending":"PRIVATE_PENDING"}}}'"#).await.unwrap();
        std::fs::write(
            fixture.home.path().join("runtime/scripts/pending"),
            "PRIVATE_UNREGISTERED",
        )
        .unwrap();
        let selected = fixture
            .select()
            .await
            .unwrap()
            .finish()
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            selected.configuration().spec.runtime.scripts["task"],
            "DECLARED_LAST_ACTIVE_SCRIPT"
        );
        let retained =
            select_stopped_configuration(&fixture.db, fixture.home.path(), 1, &fixture.guard)
                .await
                .unwrap()
                .unwrap();
        assert!(selected.source.owner == retained.owner);
        assert_eq!(selected.source.generation, retained.generation);
        assert_eq!(selected.source.source, retained.source);
        let raw = selected.source.source.as_ref().unwrap();
        assert_eq!(
            raw.pointer("/runtime/scripts/task").unwrap(),
            "DECLARED_LAST_ACTIVE_SCRIPT"
        );
        assert!(raw.pointer("/runtime/scripts/pending").is_none());
        let Some(ScriptBackingEvidence::Observed { files, .. }) = selected.scripts else {
            panic!("stopped backing unknown")
        };
        assert_eq!(files.len(), 1);
        assert_eq!(files["task"].content, "OBSERVED_LAST_ACTIVE_SCRIPT");
        assert_eq!(
            (files["task"].uid, files["task"].gid, files["task"].mode),
            (42, 43, 0o640)
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn stopped_script_mutation_and_runtime_replacement_become_unknown() {
        for replace_directory in [false, true] {
            let fixture = StoppedFixture::new().await;
            let selected = fixture.select().await.unwrap();
            if replace_directory {
                std::fs::rename(
                    fixture.home.path().join("runtime"),
                    fixture.home.path().join("old-runtime"),
                )
                .unwrap();
                std::fs::create_dir_all(fixture.home.path().join("runtime/scripts")).unwrap();
            }
            std::fs::write(
                fixture.home.path().join("runtime/scripts/task"),
                "PRIVATE_CHANGED",
            )
            .unwrap();
            let selected = selected.finish().await.unwrap().unwrap();
            let evidence = selected.scripts.unwrap();
            assert!(matches!(
                evidence,
                ScriptBackingEvidence::Unknown {
                    reason: ScriptBackingUnknown::Changed
                }
            ));
            assert!(
                !serde_json::to_string(&evidence)
                    .unwrap()
                    .contains("PRIVATE_CHANGED")
            );
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn stopped_runtime_symlink_and_missing_backing_are_not_desired_defaults() {
        for link_runtime in [false, true] {
            let fixture = StoppedFixture::new().await;
            std::fs::remove_file(fixture.home.path().join("runtime/scripts/task")).unwrap();
            let outside = tempfile::tempdir().unwrap();
            if link_runtime {
                std::fs::remove_dir_all(fixture.home.path().join("runtime")).unwrap();
                std::fs::create_dir(outside.path().join("scripts")).unwrap();
                std::fs::write(outside.path().join("scripts/task"), "PRIVATE_OUTSIDE").unwrap();
                std::os::unix::fs::symlink(outside.path(), fixture.home.path().join("runtime"))
                    .unwrap();
            }
            let selected = fixture
                .select()
                .await
                .unwrap()
                .finish()
                .await
                .unwrap()
                .unwrap();
            let evidence = selected.scripts.unwrap();
            assert!(matches!(evidence, ScriptBackingEvidence::Unknown { .. }));
            let encoded = serde_json::to_string(&evidence).unwrap();
            assert!(!encoded.contains("PRIVATE_OUTSIDE"));
            assert!(!encoded.contains("DECLARED_LAST_ACTIVE_SCRIPT"));
        }
    }

    #[tokio::test]
    async fn stopped_capture_keeps_last_active_separate_from_desired_edits() {
        let fixture = StoppedFixture::new().await;
        let selected = fixture.select().await.unwrap();
        assert_eq!(
            selected
                .configuration()
                .unwrap()
                .unwrap()
                .spec
                .runtime
                .user
                .as_deref(),
            Some("last-active-user")
        );
        fixture
            .db
            .execute_unprepared("UPDATE sandbox SET config = 'another pending config'")
            .await
            .unwrap();
        // Dropping the caller's handle cannot release ownership during an admitted cut.
        drop(fixture.guard);
        assert!(
            microsandbox_runtime::ipc::try_acquire_lifecycle_guard(fixture.home.path(), "source")
                .unwrap()
                .is_none()
        );
        selected.finish().await.unwrap();
        let _released = tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                if let Some(guard) = microsandbox_runtime::ipc::try_acquire_lifecycle_guard(
                    fixture.home.path(),
                    "source",
                )
                .unwrap()
                {
                    break guard;
                }
                tokio::time::sleep(std::time::Duration::from_millis(1)).await;
            }
        })
        .await
        .expect("stopped configuration observer retained lifecycle ownership");
    }

    #[tokio::test]
    async fn stopped_capture_refuses_changed_provenance_after_the_disk_cut() {
        for mutation in [
            "UPDATE sandbox SET active_config = '{\"runtime\":{\"user\":\"PRIVATE_DRIFT\"}}'",
            "INSERT INTO run VALUES (2, 1, 'later', 'Terminated', 'ended', NULL)",
            "UPDATE sandbox SET status = 'Running'",
        ] {
            let fixture = StoppedFixture::new().await;
            let selected = fixture.select().await.unwrap();
            assert!(selected.configuration().unwrap().is_some());
            fixture.db.execute_unprepared(mutation).await.unwrap();
            let error = selected.finish().await.err().unwrap().to_string();
            assert!(error.contains("configuration evidence changed"));
            assert!(!error.contains("PRIVATE_DRIFT"));
        }
    }

    #[tokio::test]
    async fn stopped_capture_missing_legacy_evidence_remains_unknown_and_read_only() {
        let fixture = StoppedFixture::new().await;
        std::fs::remove_dir_all(fixture.home.path().join("last-active")).unwrap();
        let selected = fixture.select().await.unwrap();
        assert!(selected.configuration().unwrap().is_none());
        selected.finish().await.unwrap();
        assert!(!fixture.home.path().join("last-active").exists());
    }

    #[tokio::test]
    async fn stopped_capture_missing_or_corrupt_terminal_evidence_cannot_reuse_confirmation() {
        let fixture = StoppedFixture::new().await;
        let selected = fixture.select().await.unwrap();
        std::fs::remove_file(fixture.home.path().join("last-active/terminal.json")).unwrap();
        assert!(selected.finish().await.is_err());
        assert!(
            fixture
                .select()
                .await
                .unwrap()
                .configuration()
                .unwrap()
                .is_none()
        );
        std::fs::write(
            fixture.home.path().join("last-active/terminal.json"),
            b"PRIVATE_BAD_RECEIPT",
        )
        .unwrap();
        let error = fixture.select().await.err().unwrap().to_string();
        assert!(error.contains("could not select stopped capture configuration"));
        assert!(!error.contains("PRIVATE_BAD_RECEIPT"));
    }
}
