//! Schema-bounded entry into the runtime-reusable filesystem capture primitive.

use std::{collections::BTreeSet, fs::File};

use microsandbox_filesystem::{CapturedRuntimeScripts, RuntimeScriptLimits};
use microsandbox_types::snapshot::saved_config::{
    MAX_SAVED_CONFIG_ENTRIES, MAX_SAVED_SCRIPT_BYTES, MAX_SAVED_SCRIPTS_BYTES,
};

use crate::{MicrosandboxError, MicrosandboxResult};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Capture local observations under an independently held source mutation/capture guard.
/// Nothing is exported or admitted here; sanitization and full-state closure checks remain required.
pub fn capture_runtime_scripts(
    runtime: &File,
    registered: &BTreeSet<String>,
) -> MicrosandboxResult<CapturedRuntimeScripts> {
    CapturedRuntimeScripts::capture(
        runtime,
        registered,
        RuntimeScriptLimits {
            max_entries: MAX_SAVED_CONFIG_ENTRIES,
            max_script_bytes: MAX_SAVED_SCRIPT_BYTES,
            max_total_bytes: MAX_SAVED_SCRIPTS_BYTES,
        },
    )
    .map_err(|error| MicrosandboxError::InvalidConfig(error.to_string()))
}
