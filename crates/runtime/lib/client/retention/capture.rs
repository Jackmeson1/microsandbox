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
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[cfg(feature = "runner")]
use super::{LiveConfigurationSelection, RetentionJournal};
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
}

#[cfg(feature = "runner")]
pub(crate) struct ConfigurationCaptureObservation<'a> {
    sandbox_directory: &'a Path,
    selected: Option<LiveConfigurationSelection<'a>>,
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
    pub(crate) fn new(journal: &'a RetentionJournal, db: &'a DbWriteConnection) -> Self {
        Self { journal, db }
    }

    pub(crate) async fn observe(&self) -> io::Result<ConfigurationCaptureObservation<'a>> {
        Ok(ConfigurationCaptureObservation {
            sandbox_directory: self
                .journal
                .directory
                .parent()
                .ok_or_else(|| invalid("missing capture source directory"))?,
            selected: self.journal.select_live_configuration(self.db).await?,
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
        )
    }
}

impl CapturedConfiguration {
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
    use super::*;
    use crate::retention::RetentionOwner;

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
        )
        .unwrap();
        let receipt = prepared.publish();
        let read =
            CapturedConfiguration::read(home.path(), "checkpoint_one", "full:root", &receipt)
                .unwrap();
        assert_eq!(read.source().unwrap().generation, 3);
        assert!(
            CapturedConfiguration::read(home.path(), "checkpoint_one", "other:root", &receipt)
                .is_err()
        );
        assert!(
            PreparedConfigurationReceipt::prepare(
                home.path(),
                "checkpoint_one",
                "other:root",
                None
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
    fn unpublished_receipt_rolls_back_and_unavailable_source_stays_unknown() {
        let home = tempfile::tempdir().unwrap();
        drop(
            PreparedConfigurationReceipt::prepare(home.path(), "checkpoint_one", "disk:root", None)
                .unwrap(),
        );
        assert!(
            !receipt_path(home.path(), "checkpoint_one")
                .unwrap()
                .exists()
        );
        let receipt =
            PreparedConfigurationReceipt::prepare(home.path(), "checkpoint_one", "disk:root", None)
                .unwrap()
                .publish();
        assert!(
            CapturedConfiguration::read(home.path(), "checkpoint_one", "disk:root", &receipt)
                .unwrap()
                .source()
                .is_none()
        );
        for id in ["", "..", "../state", "a/b", "a\\b"] {
            assert!(PreparedConfigurationReceipt::prepare(home.path(), id, "root", None).is_err());
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
