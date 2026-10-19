//! Internal saved-default resolution, separate from portable metadata and VM activation.
//!
//! No launch path calls this module until complete policy and deferred-exec enforcement land.

mod runtime;
#[cfg(test)]
mod tests;
mod types;

//--------------------------------------------------------------------------------------------------
// Re-Exports
//--------------------------------------------------------------------------------------------------

pub use runtime::select_runtime_defaults;
pub use types::{
    RuntimeDefaultClear, RuntimeDefaultSelection, RuntimeSelectionContext, SavedCmdPolicy,
    SnapshotConfigMode,
};
