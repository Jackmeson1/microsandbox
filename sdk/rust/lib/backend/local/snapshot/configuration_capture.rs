//! Source identity for private checkpoint receipts, selected before dispatch.

use std::{path::PathBuf, sync::Arc};

use microsandbox_db::DbWriteConnection;
use microsandbox_protocol::control::ConfigurationCaptureReceipt;
use microsandbox_runtime::ipc::SandboxLifecycleGuard;
use microsandbox_runtime::retention::{
    CapturedConfiguration, RetainedConfiguration, RetentionOwner, select_stopped_configuration,
};

use crate::backend::{ControlSession, LocalBackend};
use crate::sandbox::SandboxConfig;
use crate::{MicrosandboxError, MicrosandboxResult};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

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
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

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
    ) -> MicrosandboxResult<Option<SandboxConfig>> {
        let receipt =
            receipt.ok_or_else(|| invalid("runtime omitted requested configuration receipt"))?;
        let captured =
            CapturedConfiguration::read(&self.directory, checkpoint_id, capture_root, receipt)
                .map_err(|_| invalid("invalid checkpoint configuration receipt"))?;
        let Some(source) = captured.source() else {
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
        decode_configuration(source.source.as_ref())
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
        Ok(Self {
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
    pub(crate) async fn finish(self) -> MicrosandboxResult<()> {
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
        Ok(())
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

        fn read(&self, value: &serde_json::Value) -> MicrosandboxResult<Option<SandboxConfig>> {
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
        assert_eq!(selected.spec.runtime.user.as_deref(), Some("captured-user"));
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
