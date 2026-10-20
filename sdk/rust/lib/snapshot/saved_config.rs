//! Internal saved-default resolution, separate from portable metadata and VM activation.
//!
//! No launch path calls this module until complete policy and deferred-exec enforcement land.

mod demand;
#[cfg(test)]
mod demand_tests;
mod execution;
mod execution_assembly;
#[cfg(test)]
mod execution_assembly_tests;
#[cfg(test)]
mod execution_tests;
#[cfg(test)]
mod gateway_input_tests;
mod gateway_inputs;
mod gateway_preparation;
#[cfg(test)]
mod gateway_preparation_tests;
#[cfg(test)]
mod listener_tests;
mod listeners;
mod network_assembly;
#[cfg(test)]
mod network_assembly_tests;
mod network_policy;
#[cfg(test)]
mod network_policy_tests;
mod resource_assembly;
#[cfg(test)]
mod resource_assembly_tests;
#[cfg(test)]
mod resource_tests;
mod resources;
mod runtime;
mod runtime_assembly;
#[cfg(test)]
mod runtime_assembly_tests;
#[cfg(test)]
mod runtime_input_tests;
mod runtime_inputs;
#[cfg(test)]
mod secret_tests;
mod secrets;
mod storage;
#[cfg(test)]
mod storage_tests;
#[cfg(test)]
mod tests;
mod types;

//--------------------------------------------------------------------------------------------------
// Re-Exports
//--------------------------------------------------------------------------------------------------

pub use demand::{
    BindingDemand, BindingDemandContext, BindingDemandPlan, BindingSupplyGaps, plan_binding_demand,
};
pub use execution::{
    DestinationGuestSecurity, ExecutionDefaultClear, ExecutionDefaultSelection,
    ExecutionRestoreMode, LifetimeDefaultSelection, select_execution_defaults,
};
pub use execution_assembly::{ExecutionConfigurationPlan, prepare_execution_configuration};
pub use gateway_inputs::{GatewayInputPlan, select_gateway_inputs};
pub use gateway_preparation::{
    GatewayBindingInput, GatewayConfigurationPlan, prepare_gateway_configuration,
};
pub use listeners::{
    ListenerBindingInput, ListenerInputPlan, ListenerInputSelection, select_listener_inputs,
};
pub use network_assembly::{NetworkPolicyConfigurationPlan, prepare_network_policy_configuration};
pub use network_policy::{
    DestinationNetworkBaseline, NetworkPolicyApproval, NetworkPolicyClear, NetworkPolicySelection,
    select_network_policy_defaults,
};
pub use resource_assembly::{ResourceConfigurationPlan, prepare_resource_configuration};
pub use resources::{
    ResourceDefaultClear, ResourceDefaultSelection, ResourceRestoreMode, select_resource_defaults,
};
pub use runtime::select_runtime_defaults;
pub use runtime_assembly::{
    PreparedCommandDefaults, RuntimeConfigurationPlan, prepare_runtime_configuration,
};
pub use runtime_inputs::{
    PreparedRuntimeInit, PreparedRuntimeScript, PreparedRuntimeValue, RuntimeBindingInput,
    RuntimeInputPlan, prepare_runtime_inputs,
};
pub use secrets::{SecretInputPlan, SecretInputSelection, select_secret_inputs};
pub use storage::{
    MountInputSelection, StorageApprovalRequirement, StorageInputSelection, StorageRelaxation,
    VsockInputSelection, select_storage_inputs,
};
pub use types::{
    RuntimeDefaultClear, RuntimeDefaultSelection, RuntimeSelectionContext, SnapshotConfigMode,
};
