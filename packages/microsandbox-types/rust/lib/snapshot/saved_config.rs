//! Strict, portable saved-configuration values, separate from host launch configuration.
//!
//! This module does not advertise the extension as supported. A reader may only do so
//! once capture, restore, and deferred command binding enforcement are implemented.

mod bindings;
mod network;
mod network_capture;
mod network_validation;
mod runtime;
mod validation;
mod value;

#[cfg(test)]
mod network_tests;
#[cfg(test)]
mod tests;

//--------------------------------------------------------------------------------------------------
// Re-Exports
//--------------------------------------------------------------------------------------------------

pub use bindings::{RuntimeBindingConsumer, RuntimeBindingRequirements};
pub use network::*;
pub use runtime::{SavedHostname, SavedInit, SavedInitSelection, SavedRuntimeConfig, SavedScript};
pub use value::{SavedOrigin, SavedText, SavedUnknownReason, SavedValue};

pub use validation::{
    MAX_SAVED_CONFIG_BYTES, MAX_SAVED_CONFIG_ENTRIES, MAX_SAVED_SCRIPT_BYTES,
    MAX_SAVED_SCRIPTS_BYTES,
};
