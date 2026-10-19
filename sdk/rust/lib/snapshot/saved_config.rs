//! Internal saved-default resolution, separate from portable metadata and VM activation.
//!
//! No launch path calls this module until complete policy and deferred-exec enforcement land.

mod execution;
#[cfg(test)]
mod execution_tests;
#[cfg(test)]
mod resource_tests;
mod resources;
mod runtime;
#[cfg(test)]
mod tests;
mod types;

//--------------------------------------------------------------------------------------------------
// Re-Exports
//--------------------------------------------------------------------------------------------------

pub use execution::{
    DestinationGuestSecurity, ExecutionDefaultClear, ExecutionDefaultSelection,
    ExecutionRestoreMode, LifetimeDefaultSelection, select_execution_defaults,
};
pub use resources::{
    ResourceDefaultClear, ResourceDefaultSelection, ResourceRestoreMode, select_resource_defaults,
};
pub use runtime::select_runtime_defaults;
pub use types::{
    RuntimeDefaultClear, RuntimeDefaultSelection, RuntimeSelectionContext, SavedCmdPolicy,
    SnapshotConfigMode,
};
