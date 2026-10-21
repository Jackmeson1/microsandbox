//! Private configuration receipts tied to one immutable checkpoint, never archive members.

use std::{
    fs,
    io::{self, Read},
    path::{Path, PathBuf},
};

#[cfg(any(feature = "runner", test))]
use std::io::Write;

#[cfg(feature = "runner")]
use microsandbox_db::DbWriteConnection;
use microsandbox_protocol::control::ConfigurationCaptureReceipt;
use microsandbox_protocol::init_observation::InitObservation;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::script_backing::ScriptBackingEvidence;
#[cfg(feature = "runner")]
use super::script_backing::ScriptBackingObservation;
#[cfg(feature = "runner")]
use super::{LiveConfigurationSelection, RetentionJournal, read_retained_init};
use super::{RetainedConfiguration, invalid};
#[cfg(any(feature = "runner", test))]
use super::{private_directory, sync_directory};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const MAX_CAPTURE_BYTES: u64 = 16 * 1024 * 1024;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Borrowed executor authority, used only after the checkpoint coordinator pauses the VM.
#[cfg(feature = "runner")]
pub(crate) struct ConfigurationCaptureContext<'a> {
    journal: &'a RetentionJournal,
    db: &'a DbWriteConnection,
    runtime_script_root: Option<&'a fs::File>,
}

#[cfg(feature = "runner")]
pub(crate) struct ConfigurationCaptureObservation<'a> {
    sandbox_directory: &'a Path,
    selected: Option<LiveConfigurationSelection<'a>>,
    scripts: ScriptBackingObservation,
    init: Option<InitObservation>,
}

/// Host-private evidence from the checkpoint's paused configuration boundary.
/// Raw source values require portable projection before they may be exported.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapturedConfiguration {
    schema: u32,
    checkpoint_id: String,
    capture_root: String,
    source: Option<RetainedConfiguration>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pending: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    scripts: Option<ScriptBackingEvidence>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    init: Option<InitObservation>,
}

/// Remove an unpublished receipt on error; only checkpoint publication transfers ownership.
#[cfg(any(feature = "runner", test))]
pub(crate) struct PreparedConfigurationReceipt {
    path: PathBuf,
    receipt: ConfigurationCaptureReceipt,
    published: bool,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

#[cfg(feature = "runner")]
impl<'a> ConfigurationCaptureContext<'a> {
    pub(crate) fn new(
        journal: &'a RetentionJournal,
        db: &'a DbWriteConnection,
        runtime_script_root: Option<&'a fs::File>,
    ) -> Self {
        Self {
            journal,
            db,
            runtime_script_root,
        }
    }

    pub(crate) async fn observe(&self) -> io::Result<ConfigurationCaptureObservation<'a>> {
        let selected = self.journal.select_live_configuration(self.db).await?;
        let scripts = ScriptBackingObservation::observe(
            self.runtime_script_root,
            selected
                .as_ref()
                .and_then(|selected| selected.configuration().source.as_ref()),
        );
        let sandbox_directory = self
            .journal
            .directory
            .parent()
            .ok_or_else(|| invalid("missing capture source directory"))?;
        let init = selected
            .as_ref()
            .map(|selected| read_retained_init(sandbox_directory, selected.configuration()))
            .transpose()?
            .flatten();
        Ok(ConfigurationCaptureObservation {
            init,
            scripts,
            sandbox_directory,
            selected,
        })
    }
}

#[cfg(feature = "runner")]
impl ConfigurationCaptureObservation<'_> {
    pub(crate) async fn prepare(
        self,
        checkpoint_id: &str,
        capture_root: &str,
    ) -> io::Result<PreparedConfigurationReceipt> {
        if let Some(selected) = &self.selected
            && !selected.revalidate().await?
        {
            return Err(invalid("configuration changed during checkpoint capture"));
        }
        PreparedConfigurationReceipt::prepare(
            self.sandbox_directory,
            checkpoint_id,
            capture_root,
            self.selected
                .as_ref()
                .map(LiveConfigurationSelection::configuration),
            self.selected
                .as_ref()
                .and_then(LiveConfigurationSelection::pending_configuration),
            Some(self.scripts.finish()),
            self.init,
        )
    }
}

impl CapturedConfiguration {
    /// Private next-start intent selected at the capture boundary, never active evidence.
    /// Older receipts omit it; do not replace that absence with current catalog settings.
    pub fn pending_configuration(&self) -> Option<&serde_json::Value> {
        self.pending.as_ref()
    }

    /// Guest boot selection bound to this capture, not a portable init default or health check.
    pub fn init(&self) -> Option<&InitObservation> {
        self.init.as_ref()
    }

    /// Actual registered-file evidence, distinct from declared scripts in the source config.
    /// This private record is not portable config or proof of full-state handle compatibility.
    pub fn scripts(&self) -> Option<&ScriptBackingEvidence> {
        self.scripts.as_ref()
    }

    /// Consume private evidence without cloning script bodies for the SDK capture pipeline.
    pub fn into_parts(self) -> (Option<RetainedConfiguration>, Option<ScriptBackingEvidence>) {
        (self.source, self.scripts)
    }

    /// Local source at capture, or explicit unavailability. This is never a default config.
    pub fn source(&self) -> Option<&RetainedConfiguration> {
        self.source.as_ref()
    }

    /// Read the exact receipt from the independently selected source sandbox and capture.
    /// The caller must verify the immutable checkpoint first and supply its expected root.
    pub fn read(
        sandbox_directory: &Path,
        checkpoint_id: &str,
        capture_root: &str,
        receipt: &ConfigurationCaptureReceipt,
    ) -> io::Result<Self> {
        let path = receipt_path(sandbox_directory, checkpoint_id)?;
        require_directory(path.parent().expect("receipt parent"))?;
        require_directory(&sandbox_directory.join("last-active"))?;
        let mut options = fs::OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            options.custom_flags(
                windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT,
            );
        }
        let file = options.open(&path)?;
        if !file.metadata()?.is_file() || file.metadata()?.len() > MAX_CAPTURE_BYTES {
            return Err(invalid("invalid configuration capture file"));
        }
        let mut bytes = Vec::new();
        file.take(MAX_CAPTURE_BYTES + 1).read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_CAPTURE_BYTES
            || hex::encode(Sha256::digest(&bytes)) != receipt.sha256
        {
            return Err(invalid("configuration capture digest mismatch"));
        }
        let record: Self = serde_json::from_slice(&bytes)
            .map_err(|_| invalid("invalid configuration capture document"))?;
        if record.schema != 1
            || record.checkpoint_id != checkpoint_id
            || record.capture_root != capture_root
        {
            return Err(invalid("configuration capture identity mismatch"));
        }
        Ok(record)
    }
}

#[cfg(any(feature = "runner", test))]
impl PreparedConfigurationReceipt {
    /// Persist before the checkpoint root becomes visible. The caller owns capture authority.
    pub(crate) fn prepare(
        sandbox_directory: &Path,
        checkpoint_id: &str,
        capture_root: &str,
        source: Option<&RetainedConfiguration>,
        pending: Option<&serde_json::Value>,
        scripts: Option<ScriptBackingEvidence>,
        init: Option<InitObservation>,
    ) -> io::Result<Self> {
        let path = receipt_path(sandbox_directory, checkpoint_id)?;
        let parent = sandbox_directory.join("last-active");
        private_directory(&parent)?;
        let directory = path.parent().expect("receipt parent").to_path_buf();
        private_directory(&directory)?;
        sync_directory(&parent)?;
        let record = CapturedConfiguration {
            schema: 1,
            checkpoint_id: checkpoint_id.into(),
            capture_root: capture_root.into(),
            source: source.cloned(),
            pending: pending.cloned(),
            scripts,
            init,
        };
        let bytes = serde_json::to_vec(&record)
            .map_err(|_| invalid("could not encode configuration capture"))?;
        if bytes.len() as u64 > MAX_CAPTURE_BYTES {
            return Err(invalid("configuration capture exceeds size limit"));
        }
        let receipt = ConfigurationCaptureReceipt {
            sha256: hex::encode(Sha256::digest(&bytes)),
        };
        let mut temporary = tempfile::NamedTempFile::new_in(&directory)?;
        temporary.write_all(&bytes)?;
        temporary.flush()?;
        temporary.as_file().sync_all()?;
        // Never replace another capture's evidence, even on retry after an uncertain outcome.
        temporary
            .persist_noclobber(&path)
            .map_err(|error| error.error)?;
        let prepared = Self {
            path,
            receipt,
            published: false,
        };
        sync_directory(&directory)?;
        Ok(prepared)
    }

    /// The immutable checkpoint is published; keep its private receipt for local recovery.
    pub(crate) fn publish(mut self) -> ConfigurationCaptureReceipt {
        self.published = true;
        self.receipt.clone()
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

#[cfg(any(feature = "runner", test))]
impl Drop for PreparedConfigurationReceipt {
    fn drop(&mut self) {
        if !self.published
            && let Err(error) = fs::remove_file(&self.path)
        {
            tracing::warn!(%error, "unpublished configuration receipt cleanup failed");
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Stable private receipt binding for a disk-only root, distinct from full checkpoint roots.
pub fn disk_configuration_root(
    disk: &microsandbox_image::checkpoint::DiskGenerationManifest,
) -> io::Result<String> {
    let bytes =
        serde_json::to_vec(disk).map_err(|_| invalid("could not fingerprint captured disk"))?;
    Ok(format!("disk:{}", hex::encode(Sha256::digest(bytes))))
}

fn receipt_path(sandbox_directory: &Path, checkpoint_id: &str) -> io::Result<PathBuf> {
    if checkpoint_id.is_empty()
        || checkpoint_id.len() > 128
        || !checkpoint_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Err(invalid("invalid configuration capture identity"));
    }
    Ok(sandbox_directory
        .join("last-active/captures")
        .join(format!("{checkpoint_id}.json")))
}

fn require_directory(path: &Path) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(invalid(
            "configuration capture parent is not a real directory",
        ));
    }
    Ok(())
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::retention::{CapturedScriptBacking, CapturedScriptDirectory, RetentionOwner};

    fn source() -> RetainedConfiguration {
        RetainedConfiguration {
            owner: RetentionOwner {
                catalog_file: [1, 2],
                sandbox_id: 1,
                sandbox_created_at: Some("created".into()),
                run_id: 2,
                run_started_at: "started".into(),
                runtime_boot_id: "boot".into(),
            },
            generation: 3,
            source: Some(serde_json::json!({"env": "PRIVATE_SOURCE_VALUE"})),
        }
    }

    #[test]
    fn receipt_is_private_bound_and_never_overwrites_an_existing_capture() {
        let home = tempfile::tempdir().unwrap();
        let source = source();
        let prepared = PreparedConfigurationReceipt::prepare(
            home.path(),
            "checkpoint_one",
            "full:root",
            Some(&source),
            None,
            None,
            Some(InitObservation::Builtin),
        )
        .unwrap();
        let receipt = prepared.publish();
        let read =
            CapturedConfiguration::read(home.path(), "checkpoint_one", "full:root", &receipt)
                .unwrap();
        assert_eq!(read.source().unwrap().generation, 3);
        assert_eq!(read.init(), Some(&InitObservation::Builtin));
        // Later mutable runtime state cannot replace evidence sealed into this capture digest.
        std::fs::write(home.path().join("last-active/init.json"), b"new runtime").unwrap();
        assert_eq!(
            CapturedConfiguration::read(home.path(), "checkpoint_one", "full:root", &receipt)
                .unwrap()
                .init(),
            Some(&InitObservation::Builtin)
        );
        assert!(
            CapturedConfiguration::read(home.path(), "checkpoint_one", "other:root", &receipt)
                .is_err()
        );
        assert!(
            PreparedConfigurationReceipt::prepare(
                home.path(),
                "checkpoint_one",
                "other:root",
                None,
                None,
                None,
                None,
            )
            .is_err()
        );
        assert!(
            CapturedConfiguration::read(home.path(), "checkpoint_one", "full:root", &receipt)
                .is_ok()
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let path = receipt_path(home.path(), "checkpoint_one").unwrap();
            assert_eq!(
                fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o600
            );
            assert_eq!(
                fs::metadata(home.path().join("last-active/captures"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o700
            );
        }
    }

    #[test]
    fn pending_intent_is_digest_bound_and_missing_legacy_evidence_stays_unknown() {
        let home = tempfile::tempdir().unwrap();
        let pending = serde_json::json!({"runtime":{"user":"PRIVATE_PENDING_USER"}});
        let receipt = PreparedConfigurationReceipt::prepare(
            home.path(),
            "pending",
            "disk:root",
            Some(&source()),
            Some(&pending),
            None,
            None,
        )
        .unwrap()
        .publish();
        let captured =
            CapturedConfiguration::read(home.path(), "pending", "disk:root", &receipt).unwrap();
        assert_eq!(captured.pending_configuration(), Some(&pending));
        assert!(
            captured
                .source()
                .unwrap()
                .source
                .as_ref()
                .unwrap()
                .get("runtime")
                .is_none()
        );
        let path = receipt_path(home.path(), "pending").unwrap();
        let mut value: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        value["pending"]["runtime"]["user"] = "OTHER_PRIVATE_USER".into();
        fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        let error = CapturedConfiguration::read(home.path(), "pending", "disk:root", &receipt)
            .err()
            .unwrap()
            .to_string();
        assert!(error.contains("digest mismatch"));
        assert!(!error.contains("PRIVATE_USER"));
        value.as_object_mut().unwrap().remove("pending");
        let bytes = serde_json::to_vec(&value).unwrap();
        fs::write(&path, &bytes).unwrap();
        let legacy = ConfigurationCaptureReceipt {
            sha256: hex::encode(Sha256::digest(&bytes)),
        };
        assert!(
            CapturedConfiguration::read(home.path(), "pending", "disk:root", &legacy)
                .unwrap()
                .pending_configuration()
                .is_none()
        );
    }

    #[test]
    fn private_receipt_digest_binds_actual_script_evidence() {
        let home = tempfile::tempdir().unwrap();
        let scripts = ScriptBackingEvidence::Observed {
            runtime_directory: CapturedScriptDirectory {
                uid: 0,
                gid: 0,
                mode: 0o755,
            },
            scripts_directory: CapturedScriptDirectory {
                uid: 44,
                gid: 45,
                mode: 0o710,
            },
            files: BTreeMap::from([(
                "task".into(),
                CapturedScriptBacking {
                    content: "ACTUAL_PRIVATE_SCRIPT".into(),
                    uid: 42,
                    gid: 43,
                    mode: 0o640,
                },
            )]),
        };
        let receipt = PreparedConfigurationReceipt::prepare(
            home.path(),
            "with_scripts",
            "full:root",
            Some(&source()),
            None,
            Some(scripts),
            None,
        )
        .unwrap()
        .publish();
        let captured =
            CapturedConfiguration::read(home.path(), "with_scripts", "full:root", &receipt)
                .unwrap();
        let Some(ScriptBackingEvidence::Observed { files, .. }) = captured.scripts() else {
            panic!("missing script evidence")
        };
        assert_eq!(files["task"].content, "ACTUAL_PRIVATE_SCRIPT");
        assert_eq!(
            (files["task"].uid, files["task"].gid, files["task"].mode),
            (42, 43, 0o640)
        );
        let path = receipt_path(home.path(), "with_scripts").unwrap();
        let bytes = fs::read_to_string(&path)
            .unwrap()
            .replace("ACTUAL_PRIVATE_SCRIPT", "FORGED_PRIVATE_SCRIPT");
        fs::write(path, bytes).unwrap();
        let error = CapturedConfiguration::read(home.path(), "with_scripts", "full:root", &receipt)
            .err()
            .unwrap()
            .to_string();
        assert!(error.contains("digest mismatch"));
        assert!(!error.contains("PRIVATE_SCRIPT"));
    }

    #[test]
    fn unpublished_receipt_rolls_back_and_unavailable_source_stays_unknown() {
        let home = tempfile::tempdir().unwrap();
        drop(
            PreparedConfigurationReceipt::prepare(
                home.path(),
                "checkpoint_one",
                "disk:root",
                None,
                None,
                None,
                None,
            )
            .unwrap(),
        );
        assert!(
            !receipt_path(home.path(), "checkpoint_one")
                .unwrap()
                .exists()
        );
        let receipt = PreparedConfigurationReceipt::prepare(
            home.path(),
            "checkpoint_one",
            "disk:root",
            None,
            None,
            None,
            None,
        )
        .unwrap()
        .publish();
        assert!(
            CapturedConfiguration::read(home.path(), "checkpoint_one", "disk:root", &receipt)
                .unwrap()
                .source()
                .is_none(),
        );
        for id in ["", "..", "../state", "a/b", "a\\b"] {
            assert!(
                PreparedConfigurationReceipt::prepare(
                    home.path(),
                    id,
                    "root",
                    None,
                    None,
                    None,
                    None
                )
                .is_err()
            );
        }
    }

    #[test]
    fn changed_and_malformed_receipts_never_expose_source_values() {
        let home = tempfile::tempdir().unwrap();
        let receipt = PreparedConfigurationReceipt::prepare(
            home.path(),
            "checkpoint_one",
            "root",
            Some(&source()),
            None,
            None,
            None,
        )
        .unwrap()
        .publish();
        let path = receipt_path(home.path(), "checkpoint_one").unwrap();
        let bytes = fs::read(&path).unwrap();
        fs::write(&path, b"PRIVATE_BAD_DOCUMENT").unwrap();
        let error = CapturedConfiguration::read(home.path(), "checkpoint_one", "root", &receipt)
            .err()
            .unwrap()
            .to_string();
        assert!(!error.contains("PRIVATE"));
        let wrong = ConfigurationCaptureReceipt {
            sha256: hex::encode(Sha256::digest(b"PRIVATE_BAD_DOCUMENT")),
        };
        let error = CapturedConfiguration::read(home.path(), "checkpoint_one", "root", &wrong)
            .err()
            .unwrap()
            .to_string();
        assert!(!error.contains("PRIVATE"));
        // The bound is enforced before allocation, including a sparse oversized local file.
        let file = fs::OpenOptions::new().write(true).open(&path).unwrap();
        file.set_len(MAX_CAPTURE_BYTES + 1).unwrap();
        assert!(
            CapturedConfiguration::read(home.path(), "checkpoint_one", "root", &receipt).is_err()
        );
        drop(file);
        fs::write(&path, bytes).unwrap();
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(
                &path,
                receipt_path(home.path(), "checkpoint_alias").unwrap(),
            )
            .unwrap();
            assert!(
                CapturedConfiguration::read(home.path(), "checkpoint_alias", "root", &receipt)
                    .is_err()
            );
        }
    }
}
