//! Assemble one bounded capture document without publishing it or enabling restore activation.

use std::collections::BTreeMap;

use microsandbox_types::snapshot::saved_config::{
    RuntimeCaptureAction, RuntimeCaptureInput, RuntimeCaptureTarget, SAVED_CONFIG_SCHEMA_VERSION,
    SavedActiveConfig, SavedBindingKind, SavedCaptureProvenance, SavedExecutionConfig,
    SavedNetworkConfig, SavedResourcesConfig, SavedSandboxConfig, SavedStorageConfig, SavedValue,
    collect_binding_uses, project_runtime_capture,
};
use microsandbox_types::snapshot::{Manifest, SnapshotScope};

use super::{
    ExecutionCaptureControls, NetworkCaptureBindings, NetworkCaptureControls,
    ResourceCaptureObservation, RuntimeCaptureSource, StorageCaptureBindings,
};
use crate::{MicrosandboxError, MicrosandboxResult};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Already classified next-start intent, selected under the same capture guard. It must
/// not be manufactured by treating a second desired configuration as observed active state.
/// Runtime text remains nonserializable until the shared exclusions have been applied.
/// Other sections must already have passed their source-aware sanitization/controls.
pub struct PendingCaptureSections<'a> {
    /// Classified requested runtime defaults, with unresolved observations left unknown.
    pub runtime: RuntimeCaptureInput<'a>,
    /// Desired targets may be configured here; they never supply active capacity.
    pub resources: SavedResourcesConfig,
    /// Sanitized next-start network intent and logical requirements only.
    pub network: SavedNetworkConfig,
    /// Sanitized next-start execution intent.
    pub execution: SavedExecutionConfig,
    /// Sanitized future storage requirements, never active captured backing evidence.
    pub storage: SavedStorageConfig,
}

/// One source-side assembly request. The source adapter supplies all active sections;
/// caller observations, descriptor and pending classification must share its capture cut.
/// This request contains no destination resource values or permission to activate them.
pub struct CaptureDocumentRequest<'a> {
    /// Authoritative descriptor from the same capture, including existing owned backing.
    pub manifest: &'a Manifest,
    /// Independently confirmed guest allocation, with explicit unknown/converging reasons.
    pub resources: ResourceCaptureObservation,
    /// Logical network requirements and independently established trust inventory.
    pub network: NetworkCaptureBindings,
    /// Logical external storage requirements and observed backing kinds.
    pub storage: StorageCaptureBindings,
    /// Runtime omissions/bindings apply consistently to active and pending text.
    pub runtime_controls: &'a BTreeMap<RuntimeCaptureTarget, RuntimeCaptureAction>,
    /// Optional active user-label exclusions.
    pub execution_controls: &'a ExecutionCaptureControls,
    /// Optional active network-response exclusions.
    pub network_controls: &'a NetworkCaptureControls,
    /// Separately classified next-start intent; never active fallback.
    pub pending: Option<PendingCaptureSections<'a>>,
    /// Include the optional source-name provenance field. Captured guest hostname is
    /// independent and remains subject to its own runtime exclusion/full-state rules.
    pub include_source_name: bool,
    /// Independently established original geometry, not the requested resize target.
    pub construction_resources: Option<SavedResourcesConfig>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl RuntimeCaptureSource<'_> {
    /// Project one document from this source, deriving its binding inventory from actual
    /// sanitized references. The generation must be supplied by the coherent capture owner;
    /// this pure projection cannot establish freshness, pending classification or backing.
    /// No manifest extension is written and no capability is advertised by this method.
    pub fn project_document(
        &self,
        request: CaptureDocumentRequest<'_>,
        active_generation: SavedValue<String>,
    ) -> MicrosandboxResult<SavedSandboxConfig> {
        let CaptureDocumentRequest {
            manifest,
            resources,
            network,
            storage,
            runtime_controls,
            execution_controls,
            network_controls,
            pending,
            include_source_name,
            construction_resources,
        } = request;
        let (pending_runtime, pending_sections) = match pending {
            Some(PendingCaptureSections {
                runtime,
                resources,
                network,
                execution,
                storage,
            }) => (
                Some(runtime),
                Some(SavedActiveConfig {
                    resources,
                    network,
                    execution,
                    storage,
                    ..Default::default()
                }),
            ),
            None => (None, None),
        };
        let runtime = project_runtime_capture(
            self.input(),
            pending_runtime,
            runtime_controls,
            manifest.scope == SnapshotScope::Full,
        )
        .map_err(manifest_error)?;
        let active = SavedActiveConfig {
            resources: self.project_resources(resources)?,
            runtime: runtime.active,
            network: self.project_network(network, network_controls)?,
            execution: self.project_execution(execution_controls)?,
            storage: self.project_storage(storage, manifest)?,
        };
        let pending = pending_sections
            .zip(runtime.pending)
            .map(|(mut sections, runtime)| {
                sections.runtime = runtime;
                sections
            });
        // Build the inventory from references, not caller declarations. Shared IDs must
        // agree across every family and active/pending section; pending uses do not enter
        // activation demand, which the resolver derives separately from active settings.
        let mut bindings = BTreeMap::new();
        add_bindings(&mut bindings, &active)?;
        if let Some(pending) = &pending {
            add_bindings(&mut bindings, pending)?;
        }
        let document = SavedSandboxConfig {
            schema_version: SAVED_CONFIG_SCHEMA_VERSION,
            active,
            pending,
            bindings,
            provenance: SavedCaptureProvenance {
                producer_version: env!("CARGO_PKG_VERSION").into(),
                source_name: if include_source_name {
                    self.recorded
                        .get("name")
                        .and_then(serde_json::Value::as_str)
                        .map(str::to_owned)
                } else {
                    None
                },
                active_generation,
                construction_resources,
            },
        };
        // Validate the aggregate size, active observations, legacy user/clock projection
        // and owned inventory before any caller can serialize or associate this document.
        document
            .validate_legacy_projections(manifest)
            .map_err(manifest_error)?;
        Ok(document)
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn add_bindings(
    inventory: &mut BTreeMap<String, SavedBindingKind>,
    section: &SavedActiveConfig,
) -> MicrosandboxResult<()> {
    let network_runtime =
        collect_binding_uses(&section.runtime, &section.network).map_err(manifest_error)?;
    let storage = section.storage.binding_uses().map_err(manifest_error)?;
    for (id, usage) in network_runtime.into_iter().chain(storage) {
        if inventory.get(&id).is_some_and(|kind| *kind != usage.kind) {
            return Err(MicrosandboxError::InvalidConfig("SCFG_BINDING: sandbox-config: shared requirement has incompatible destination kinds".into()));
        }
        inventory.insert(id, usage.kind);
    }
    Ok(())
}

fn manifest_error(error: impl std::fmt::Display) -> MicrosandboxError {
    MicrosandboxError::InvalidConfig(error.to_string())
}
