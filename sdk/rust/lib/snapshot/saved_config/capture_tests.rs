//! Whole-document capture keeps active evidence, pending intent and binding kinds distinct.

use std::collections::BTreeMap;

use microsandbox_runtime::retention::{
    CapturedScriptBacking, CapturedScriptDirectory, ScriptBackingEvidence,
};
use microsandbox_types::snapshot::Manifest;
use microsandbox_types::snapshot::saved_config::{
    RuntimeCaptureAction, RuntimeCaptureInput, RuntimeCaptureScript, RuntimeCaptureTarget,
    RuntimeCaptureText, SavedBindingKind, SavedBindingReference, SavedOrigin, SavedResourcesConfig,
    SavedText, SavedUnknownReason, SavedValue, SavedVsockRoute,
};
use microsandbox_types::{GuestClockPolicy, VsockSocketType};
use serde_json::{Value, json};

use super::storage_tests::manifest;
use super::{
    CaptureDocumentRequest, ExecutionCaptureControls, NetworkCaptureBindings,
    NetworkCaptureControls, PendingCaptureSections, ResourceCaptureObservation,
    RuntimeCaptureSource, StorageCaptureBindings,
};
use crate::sandbox::SandboxBuilder;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

#[derive(Default)]
struct Controls {
    runtime: BTreeMap<RuntimeCaptureTarget, RuntimeCaptureAction>,
    execution: ExecutionCaptureControls,
    network: NetworkCaptureControls,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn source() -> Value {
    let mut config = SandboxBuilder::new("PRIVATE_SOURCE_NAME")
        .image("alpine")
        .cmd(["active-default"])
        .background_command(["PRIVATE_INVOCATION"])
        .env("TOKEN", "ordinary")
        .finish(None, None)
        .unwrap();
    config.spec.resources.cpus = 4;
    config.spec.resources.max_cpus = 8;
    config.spec.resources.memory_mib = 1024;
    config.spec.resources.max_memory_mib = 2048;
    config.spec.network.trust_host_cas = false;
    config.spec.labels.insert("team".into(), "work".into());
    serde_json::to_value(config.clone_for_persistence()).unwrap()
}

fn known<T>(value: T, origin: SavedOrigin) -> SavedValue<T> {
    SavedValue::Value { value, origin }
}

fn generation() -> SavedValue<String> {
    known("17".into(), SavedOrigin::Observed)
}

fn request<'a>(descriptor: &'a Manifest, controls: &'a Controls) -> CaptureDocumentRequest<'a> {
    CaptureDocumentRequest {
        manifest: descriptor,
        resources: ResourceCaptureObservation {
            cpus: known(2, SavedOrigin::Observed),
            memory_mib: known(512, SavedOrigin::Observed),
        },
        network: NetworkCaptureBindings::default(),
        storage: StorageCaptureBindings::default(),
        runtime_controls: &controls.runtime,
        execution_controls: &controls.execution,
        network_controls: &controls.network,
        pending: None,
        include_source_name: false,
        construction_resources: None,
    }
}

fn pending(runtime: RuntimeCaptureInput<'_>) -> PendingCaptureSections<'_> {
    PendingCaptureSections {
        runtime,
        resources: SavedResourcesConfig {
            cpus: Some(known(8, SavedOrigin::Configured)),
            ..Default::default()
        },
        network: Default::default(),
        execution: Default::default(),
        storage: Default::default(),
    }
}

// Source-name provenance is optional, but the captured guest hostname is a separate
// intentional field. Check exact value paths so an excluded invocation/env value cannot
// be hidden by a broad allowance for the source name anywhere in the document.
fn assert_only_guest_hostname_has_private_marker(
    document: &microsandbox_types::snapshot::saved_config::SavedSandboxConfig,
) {
    fn visit(value: &Value, path: String, found: &mut Vec<String>) {
        match value {
            Value::String(text) if text.contains("PRIVATE_") => found.push(path),
            Value::Object(fields) => {
                for (key, value) in fields {
                    visit(value, format!("{path}/{key}"), found);
                }
            }
            Value::Array(values) => {
                for (index, value) in values.iter().enumerate() {
                    visit(value, format!("{path}/{index}"), found);
                }
            }
            _ => {}
        }
    }
    let mut found = Vec::new();
    visit(
        &serde_json::to_value(document).unwrap(),
        String::new(),
        &mut found,
    );
    assert_eq!(found, ["/active/runtime/hostname/value/value"]);
    assert!(document.provenance.source_name.is_none());
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[test]
fn capture_document_projects_all_active_sections_without_raw_source_leaks() {
    let raw = source();
    let adapter = RuntimeCaptureSource::from_recorded(&raw, None, None).unwrap();
    let descriptor = manifest(false);
    let before = descriptor.to_canonical_bytes().unwrap();
    let controls = Controls::default();
    let document = adapter
        .project_document(request(&descriptor, &controls), generation())
        .unwrap();
    assert_eq!(
        document
            .active
            .resources
            .cpus
            .as_ref()
            .and_then(SavedValue::value),
        Some(&2)
    );
    assert_eq!(
        document
            .active
            .resources
            .memory_mib
            .as_ref()
            .and_then(SavedValue::value),
        Some(&512)
    );
    assert_eq!(
        document
            .active
            .execution
            .labels
            .as_ref()
            .and_then(SavedValue::value)
            .unwrap()["team"],
        "work"
    );
    assert!(
        document
            .active
            .storage
            .mounts
            .as_ref()
            .and_then(SavedValue::value)
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        document
            .provenance
            .active_generation
            .value()
            .map(String::as_str),
        Some("17")
    );
    assert!(document.bindings.is_empty());
    assert!(document.pending.is_none());
    let encoded = serde_json::to_vec(&document).unwrap();
    let text = std::str::from_utf8(&encoded).unwrap();
    assert_only_guest_hostname_has_private_marker(&document);
    assert!(!text.contains("environment_provenance"));
    assert!(!text.contains("command_provenance"));
    assert!(
        microsandbox_types::snapshot::saved_config::SavedSandboxConfig::from_bytes(&encoded)
            .unwrap()
            == document
    );
    assert_eq!(descriptor.to_canonical_bytes().unwrap(), before);
}

#[test]
fn capture_document_pending_targets_and_bindings_never_supply_active_defaults() {
    let raw = source();
    let adapter = RuntimeCaptureSource::from_recorded(&raw, None, None).unwrap();
    let descriptor = manifest(false);
    let mut controls = Controls::default();
    controls.runtime.insert(
        RuntimeCaptureTarget::EnvKey("FUTURE".into()),
        RuntimeCaptureAction::Bind("future".into()),
    );
    let mut input = request(&descriptor, &controls);
    input.pending = Some(pending(RuntimeCaptureInput {
        cmd: Some(known(
            vec![RuntimeCaptureText::Literal("pending-default")],
            SavedOrigin::Configured,
        )),
        env: Some(known(
            [("FUTURE", RuntimeCaptureText::BindingRequired)].into(),
            SavedOrigin::Configured,
        )),
        ..Default::default()
    }));
    let document = adapter.project_document(input, generation()).unwrap();
    assert_eq!(
        document
            .active
            .resources
            .cpus
            .as_ref()
            .and_then(SavedValue::value),
        Some(&2)
    );
    let pending = document.pending.as_ref().unwrap();
    assert_eq!(
        pending.resources.cpus.as_ref().and_then(SavedValue::value),
        Some(&8)
    );
    assert!(
        matches!(&document.active.runtime.cmd.as_ref().and_then(SavedValue::value).unwrap()[0], SavedText::Literal { value } if value == "active-default")
    );
    assert!(
        matches!(&pending.runtime.cmd.as_ref().and_then(SavedValue::value).unwrap()[0], SavedText::Literal { value } if value == "pending-default")
    );
    assert_eq!(document.bindings["future"], SavedBindingKind::Text);
    assert!(
        !document
            .active_binding_uses()
            .unwrap()
            .contains_key("future")
    );
}

#[test]
fn capture_document_unknown_active_setting_stays_unknown_despite_pending_value() {
    let mut raw = source();
    raw["runtime"].as_object_mut().unwrap().remove("workdir");
    let adapter = RuntimeCaptureSource::from_recorded(&raw, None, None).unwrap();
    let descriptor = manifest(false);
    let controls = Controls::default();
    let mut input = request(&descriptor, &controls);
    input.pending = Some(pending(RuntimeCaptureInput {
        workdir: Some(known("/future", SavedOrigin::Configured)),
        ..Default::default()
    }));
    let document = adapter.project_document(input, generation()).unwrap();
    assert!(matches!(
        document.active.runtime.workdir,
        Some(SavedValue::Unknown {
            reason: SavedUnknownReason::NotRecorded
        })
    ));
    assert_eq!(
        document
            .pending
            .as_ref()
            .unwrap()
            .runtime
            .workdir
            .as_ref()
            .and_then(SavedValue::value)
            .map(String::as_str),
        Some("/future")
    );
}

#[test]
fn capture_document_rejects_cross_family_binding_conflicts_without_echoing_ids() {
    let mut raw = source();
    raw["network"]["dns"] = json!({"rebind_protection": true, "nameservers": ["PRIVATE_RESOLVER"], "query_timeout_ms": 100});
    let adapter = RuntimeCaptureSource::from_recorded(&raw, None, None).unwrap();
    let descriptor = manifest(false);
    let mut controls = Controls::default();
    controls.runtime.insert(
        RuntimeCaptureTarget::EnvKey("TOKEN".into()),
        RuntimeCaptureAction::Bind("shared".into()),
    );
    let mut input = request(&descriptor, &controls);
    input.network.resolvers = vec![SavedBindingReference {
        id: "shared".into(),
    }];
    let error = adapter
        .project_document(input, generation())
        .err()
        .unwrap()
        .to_string();
    assert!(error.contains("SCFG_BINDING"), "{error}");
    assert!(!error.contains("PRIVATE_"));
    let raw = source();
    let adapter = RuntimeCaptureSource::from_recorded(&raw, None, None).unwrap();
    let mut input = request(&descriptor, &controls);
    let mut future = pending(RuntimeCaptureInput::default());
    future.storage.vsock = Some(known(
        vec![SavedVsockRoute {
            port: 456,
            socket_type: VsockSocketType::Stream,
            binding: SavedBindingReference {
                id: "shared".into(),
            },
        }],
        SavedOrigin::Configured,
    ));
    input.pending = Some(future);
    assert!(
        adapter
            .project_document(input, generation())
            .err()
            .unwrap()
            .to_string()
            .contains("SCFG_BINDING")
    );
}

#[test]
fn capture_document_shared_text_inventory_is_derived_and_pending_exclusions_apply() {
    let raw = source();
    let adapter = RuntimeCaptureSource::from_recorded(&raw, None, None).unwrap();
    let descriptor = manifest(false);
    let mut controls = Controls::default();
    controls.runtime.insert(
        RuntimeCaptureTarget::EnvKey("TOKEN".into()),
        RuntimeCaptureAction::Bind("shared".into()),
    );
    controls.runtime.insert(
        RuntimeCaptureTarget::EnvKey("FUTURE".into()),
        RuntimeCaptureAction::Bind("shared".into()),
    );
    controls.runtime.insert(
        RuntimeCaptureTarget::EnvKey("EXCLUDED".into()),
        RuntimeCaptureAction::Omit,
    );
    let mut input = request(&descriptor, &controls);
    input.pending = Some(pending(RuntimeCaptureInput {
        env: Some(known(
            [
                ("FUTURE", RuntimeCaptureText::BindingRequired),
                ("EXCLUDED", RuntimeCaptureText::Literal("PRIVATE_EXCLUDED")),
            ]
            .into(),
            SavedOrigin::Configured,
        )),
        ..Default::default()
    }));
    let document = adapter.project_document(input, generation()).unwrap();
    assert_eq!(document.bindings.len(), 1);
    assert_eq!(document.bindings["shared"], SavedBindingKind::Text);
    assert_only_guest_hostname_has_private_marker(&document);
}

#[test]
fn capture_document_generation_and_source_provenance_remain_explicit() {
    let raw = source();
    let adapter = RuntimeCaptureSource::from_recorded(&raw, None, None).unwrap();
    let descriptor = manifest(false);
    let controls = Controls::default();
    for invalid in [
        SavedValue::Default {},
        known(
            "PRIVATE_REQUESTED_GENERATION".into(),
            SavedOrigin::Configured,
        ),
    ] {
        let error = adapter
            .project_document(request(&descriptor, &controls), invalid)
            .err()
            .unwrap()
            .to_string();
        assert!(error.contains("SCFG_VALUE"));
        assert!(!error.contains("PRIVATE_"));
    }
    let mut input = request(&descriptor, &controls);
    input.include_source_name = true;
    let document = adapter
        .project_document(
            input,
            SavedValue::Unknown {
                reason: SavedUnknownReason::NotObserved,
            },
        )
        .unwrap();
    assert_eq!(
        document.provenance.source_name.as_deref(),
        Some("PRIVATE_SOURCE_NAME")
    );
    assert!(matches!(
        document.provenance.active_generation,
        SavedValue::Unknown { .. }
    ));
}

#[test]
fn capture_document_full_state_exclusions_follow_the_descriptor_scope() {
    let raw = source();
    let adapter = RuntimeCaptureSource::from_recorded(&raw, None, None).unwrap();
    let mut controls = Controls::default();
    controls
        .runtime
        .insert(RuntimeCaptureTarget::Scripts, RuntimeCaptureAction::Omit);
    let descriptor = manifest(true);
    let error = adapter
        .project_document(request(&descriptor, &controls), generation())
        .err()
        .unwrap()
        .to_string();
    assert!(error.contains("SCFG_IDENTITY"));
    let descriptor = manifest(false);
    let document = adapter
        .project_document(request(&descriptor, &controls), generation())
        .unwrap();
    assert!(document.active.runtime.scripts.is_none());
}

#[test]
fn capture_document_detects_legacy_projection_contradiction_without_mutation() {
    let raw = source();
    let adapter = RuntimeCaptureSource::from_recorded(&raw, None, None).unwrap();
    let mut descriptor = manifest(false);
    descriptor.set_guest_clock(GuestClockPolicy::Off).unwrap();
    let before = descriptor.to_canonical_bytes().unwrap();
    let controls = Controls::default();
    assert!(
        adapter
            .project_document(request(&descriptor, &controls), generation())
            .is_err()
    );
    assert_eq!(descriptor.to_canonical_bytes().unwrap(), before);
}

#[test]
fn capture_document_enforces_combined_active_and_pending_script_budget() {
    let content = "x".repeat(63 * 1024);
    let mut raw = source();
    raw["runtime"]["scripts"] = json!({"a": "registered", "b": "registered", "c": "registered"});
    let backing = ScriptBackingEvidence::Observed {
        runtime_directory: CapturedScriptDirectory {
            uid: 0,
            gid: 0,
            mode: 0o755,
        },
        scripts_directory: CapturedScriptDirectory {
            uid: 0,
            gid: 0,
            mode: 0o755,
        },
        files: ["a", "b", "c"]
            .into_iter()
            .map(|name| {
                (
                    name.into(),
                    CapturedScriptBacking {
                        content: content.clone(),
                        uid: 0,
                        gid: 0,
                        mode: 0o644,
                    },
                )
            })
            .collect(),
    };
    let adapter = RuntimeCaptureSource::from_recorded(&raw, None, Some(&backing)).unwrap();
    let descriptor = manifest(false);
    let controls = Controls::default();
    let future = || {
        pending(RuntimeCaptureInput {
            scripts: Some(known(
                ["d", "e"]
                    .into_iter()
                    .map(|name| {
                        (
                            name,
                            RuntimeCaptureScript::Inline {
                                content: &content,
                                mode: 0o644,
                            },
                        )
                    })
                    .collect(),
                SavedOrigin::Configured,
            )),
            ..Default::default()
        })
    };
    let mut input = request(&descriptor, &controls);
    input.pending = Some(future());
    let error = adapter
        .project_document(input, generation())
        .err()
        .unwrap()
        .to_string();
    assert!(error.contains("SCFG_LIMIT"));
    let mut controls = Controls::default();
    controls
        .runtime
        .insert(RuntimeCaptureTarget::Scripts, RuntimeCaptureAction::Omit);
    let mut input = request(&descriptor, &controls);
    input.pending = Some(future());
    let document = adapter.project_document(input, generation()).unwrap();
    assert!(document.active.runtime.scripts.is_none());
    assert!(document.pending.as_ref().unwrap().runtime.scripts.is_none());
}

#[test]
fn capture_document_assembles_raw_pending_intent_without_active_fallback() {
    let active_raw = source();
    let active = RuntimeCaptureSource::from_recorded(&active_raw, None, None).unwrap();
    let config = SandboxBuilder::new("next-start")
        .image("alpine")
        .cmd(["next-default"])
        .init("auto")
        .script("next-task", "echo next-start")
        .finish(None, None)
        .unwrap();
    let pending_raw = serde_json::to_value(config.clone_for_persistence()).unwrap();
    let pending_source = RuntimeCaptureSource::from_recorded(&pending_raw, None, None).unwrap();
    let descriptor = manifest(false);
    let controls = Controls::default();
    let mut request = request(&descriptor, &controls);
    request.pending = Some(PendingCaptureSections {
        runtime: pending_source.pending_input(),
        resources: pending_source.project_pending_resources().unwrap(),
        network: Default::default(),
        execution: Default::default(),
        storage: Default::default(),
    });
    let document = active.project_document(request, generation()).unwrap();
    let encoded = serde_json::to_value(&document).unwrap();
    assert_eq!(
        encoded["pending"]["runtime"]["init"]["value"]["cmd"],
        "auto"
    );
    assert_eq!(
        encoded["pending"]["runtime"]["scripts"]["value"]["next-task"]["kind"],
        "declaration"
    );
    assert_eq!(
        encoded["pending"]["resources"]["cpus"]["origin"],
        "configured"
    );
    assert_eq!(encoded["active"]["resources"]["cpus"]["origin"], "observed");
    assert_eq!(encoded["active"]["runtime"]["init"]["state"], "unknown");
    assert!(document.active.runtime.validate_active().is_ok());
    assert!(document.pending.unwrap().runtime.validate_active().is_err());
}
