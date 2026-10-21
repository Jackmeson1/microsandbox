//! Source identity for private checkpoint receipts, selected before dispatch.

use std::path::PathBuf;

use microsandbox_protocol::control::ConfigurationCaptureReceipt;
use microsandbox_runtime::retention::{CapturedConfiguration, RetentionOwner};

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
        let Some(value) = source.source.as_ref() else {
            return Ok(None);
        };
        serde_json::from_value(value.clone())
            .map(Some)
            // Serde diagnostics can contain literal values. Never forward them from this boundary.
            .map_err(|_| invalid("invalid captured sandbox configuration"))
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn invalid(message: &str) -> MicrosandboxError {
    MicrosandboxError::SnapshotIntegrity(message.into())
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
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
}
