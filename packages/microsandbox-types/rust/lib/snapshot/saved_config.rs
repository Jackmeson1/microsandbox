//! Strict, portable saved-configuration values, separate from host launch configuration.
//!
//! This module does not advertise the extension as supported. A reader may only do so
//! once capture, restore, and deferred command binding enforcement are implemented.

mod bindings;
mod runtime;
mod value;

#[cfg(test)]
mod tests;

//--------------------------------------------------------------------------------------------------
// Re-Exports
//--------------------------------------------------------------------------------------------------

pub use bindings::{RuntimeBindingConsumer, RuntimeBindingRequirements};
pub use runtime::{
    MAX_SAVED_CONFIG_BYTES, MAX_SAVED_CONFIG_ENTRIES, MAX_SAVED_SCRIPT_BYTES,
    MAX_SAVED_SCRIPTS_BYTES, SavedHostname, SavedInit, SavedInitSelection, SavedRuntimeConfig,
    SavedScript,
};
pub use value::{SavedOrigin, SavedText, SavedUnknownReason, SavedValue};
