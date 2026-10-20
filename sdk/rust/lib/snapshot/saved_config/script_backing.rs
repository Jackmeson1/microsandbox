//! Schema-bounded entry into the runtime-reusable filesystem capture primitive.

use std::{collections::BTreeSet, fs::File, path::Path};

use microsandbox_filesystem::{
    CapturedRuntimeScripts, RuntimeBootScript, RuntimeScriptLimits, stage_runtime_boot_scripts,
};
use microsandbox_types::snapshot::saved_config::{
    MAX_SAVED_CONFIG_ENTRIES, MAX_SAVED_SCRIPT_BYTES, MAX_SAVED_SCRIPTS_BYTES,
};
use tempfile::TempDir;

use super::RuntimeConfigurationPlan;
use crate::{MicrosandboxError, MicrosandboxResult};

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl RuntimeConfigurationPlan {
    /// Stage exact selected script bytes for a new boot, without consulting the source.
    ///
    /// This is private preparation only. The caller owns cleanup until adoption and must
    /// still complete destination policy and activation checks. Full-resume plans refuse:
    /// matching bytes/modes cannot prove compatibility with captured open file handles.
    pub fn stage_disk_scripts(&self, parent: &Path) -> MicrosandboxResult<TempDir> {
        if self.inputs().requires_full_identity {
            return Err(MicrosandboxError::InvalidConfig(
                "SCFG_IDENTITY: runtime.scripts: full resume requires captured backing".into(),
            ));
        }
        self.inputs().scripts.require_available("runtime.scripts")?;
        let scripts: Vec<_> = self
            .scripts()
            .iter()
            .map(|(name, script)| RuntimeBootScript {
                name,
                content: &script.content,
                mode: script.mode,
            })
            .collect();
        stage_runtime_boot_scripts(parent, &scripts, script_limits())
            .map_err(|error| MicrosandboxError::InvalidConfig(error.to_string()))
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Capture local observations under an independently held source mutation/capture guard.
/// Nothing is exported or admitted here; sanitization and full-state closure checks remain required.
pub fn capture_runtime_scripts(
    runtime: &File,
    registered: &BTreeSet<String>,
) -> MicrosandboxResult<CapturedRuntimeScripts> {
    CapturedRuntimeScripts::capture(runtime, registered, script_limits())
        .map_err(|error| MicrosandboxError::InvalidConfig(error.to_string()))
}

fn script_limits() -> RuntimeScriptLimits {
    RuntimeScriptLimits {
        max_entries: MAX_SAVED_CONFIG_ENTRIES,
        max_script_bytes: MAX_SAVED_SCRIPT_BYTES,
        max_total_bytes: MAX_SAVED_SCRIPTS_BYTES,
    }
}
