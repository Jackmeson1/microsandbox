//! Combined preparation checks cross-family invariants that isolated selectors cannot prove.

use std::collections::BTreeMap;

use microsandbox_types::snapshot::saved_config::{
    MAX_SAVED_CONFIG_BYTES, SavedBindingConsumer, SavedBindingKind, SavedBindingUse,
    SavedBindingUses, SavedSandboxConfig,
};
use microsandbox_types::{
    EnvVar, NetworkSpecPatch, PortProtocol, PublishedPortSpec, SandboxResources,
    SandboxResourcesPatch, SandboxRuntimeOptionsPatch, SandboxSpec, SandboxSpecPatch, SecretSource,
    SecretsConfig, SecurityProfile,
};
use serde_json::{Value, json};
use zeroize::Zeroizing;

use super::*;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn known(value: Value) -> Value {
    json!({"state":"value","origin":"configured","value":value})
}

fn document(active: Value, bindings: Value) -> SavedSandboxConfig {
    SavedSandboxConfig::from_bytes(
        &serde_json::to_vec(&json!({
            "schema_version": 1, "active": active, "bindings": bindings,
            "provenance": {"producer_version":"0.8.0",
                "active_generation":{"state":"unknown","reason":"not_observed"}}
        }))
        .unwrap(),
    )
    .unwrap()
}

fn shared() -> SavedSandboxConfig {
    document(
        json!({
            "runtime": {"env": known(json!({"TOKEN":{"kind":"binding","id":"shared"}}))},
            "network": {"secrets": known(json!({
                "entries": [{
                    "env_var":"TOKEN", "binding":{"id":"shared"}, "placeholder":"PLACEHOLDER",
                    "allowed_hosts":["any"],
                "passthrough_hosts":[],
                    "substitution":{"headers":true,"header_fields":["Authorization"],"query":false,"body":false},
                    "require_tls_identity":true
                }],
                "violation_action":"block"
            }))}
        }),
        json!({"shared":"text"}),
    )
}

fn text(value: &str) -> ConfigurationBindingInput {
    ConfigurationBindingInput::Text(RuntimeBindingInput {
        text: Zeroizing::new(value.into()),
        script_mode: None,
    })
}

fn prepare(
    saved: &SavedSandboxConfig,
    explicit: &SandboxSpecPatch,
    mode: SnapshotConfigMode,
    context: SavedConfigurationContext<'_>,
    bindings: BTreeMap<String, ConfigurationBindingInput>,
) -> crate::MicrosandboxResult<SavedConfigurationPlan> {
    let full = matches!(context, SavedConfigurationContext::Full { .. });
    let mut lower = SandboxSpec::default();
    lower.env = vec![EnvVar {
        key: "TOKEN".into(),
        value: "LOWER_SENTINEL".into(),
    }];
    let baseline = DestinationNetworkBaseline {
        strict: false,
        tls_enabled: false,
        intercepted_ports: vec![],
    };
    prepare_saved_configuration(
        SavedConfigurationRequest {
            saved,
            manifest: &storage_tests::manifest(full),
            lower: &lower,
            lower_resources: &SandboxResourcesPatch::new(),
            explicit,
            clears: &SavedConfigurationClears::default(),
            mode,
            context,
            guest_security: DestinationGuestSecurity {
                baseline: SecurityProfile::default(),
                minimum: SecurityProfile::default(),
            },
            network_baseline: &baseline,
        },
        bindings,
    )
}

fn disk() -> SavedConfigurationContext<'static> {
    SavedConfigurationContext::Disk {
        starts_command: false,
    }
}

fn fails(result: crate::MicrosandboxResult<SavedConfigurationPlan>, code: &str) {
    let error = result.unwrap_err().to_string();
    assert!(error.contains(code), "{error}");
    assert!(!error.contains("SENTINEL"), "{error}");
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[test]
fn one_binding_supplies_identical_command_and_substitution_values_without_mutating_source() {
    let saved = shared();
    let original = serde_json::to_vec(&saved).unwrap();
    let plan = prepare(
        &saved,
        &SandboxSpecPatch::new(),
        SnapshotConfigMode::Saved,
        disk(),
        BTreeMap::from([("shared".into(), text("DESTINATION_SENTINEL"))]),
    )
    .unwrap();
    let command = plan.runtime().command_defaults().unwrap();
    assert_eq!(command.env.len(), 1);
    assert_eq!(command.env[0].value, "DESTINATION_SENTINEL");
    let mut secrets = SecretsConfig::default();
    plan.secrets().apply_to(&mut secrets).unwrap();
    assert_eq!(&*secrets.secrets[0].value, &command.env[0].value);
    let demand = &plan.demand().bindings()["shared"];
    assert!(demand.required_now);
    assert!(demand.consumers.contains(&SavedBindingConsumer::Gateway));
    assert!(demand.consumers.contains(&SavedBindingConsumer::NewCommand));
    assert!(plan.supply_gaps().before_new_command.is_empty());
    assert!(plan.supply_gaps().immediate.is_empty());
    assert_eq!(serde_json::to_vec(&saved).unwrap(), original);
    assert!(!format!("{plan:?} {:?}", plan.bindings()).contains("SENTINEL"));
}

#[test]
fn unresolved_secret_source_cannot_be_used_as_command_text_or_lower_default() {
    let saved = shared();
    let inputs = || {
        BTreeMap::from([(
            "shared".into(),
            ConfigurationBindingInput::TextSource(SecretSource::env("UNAVAILABLE_SENTINEL")),
        )])
    };
    let plan = prepare(
        &saved,
        &SandboxSpecPatch::new(),
        SnapshotConfigMode::Saved,
        disk(),
        inputs(),
    )
    .unwrap();
    assert!(plan.runtime().command_defaults().is_err());
    assert!(plan.supply_gaps().before_new_command.contains("shared"));
    assert!(plan.unresolved_text_sources().contains("shared"));
    let mut secrets = SecretsConfig::default();
    plan.secrets().apply_to(&mut secrets).unwrap();
    assert!(secrets.secrets[0].value.is_empty());
    assert_eq!(
        secrets.secrets[0].source,
        Some(SecretSource::env("UNAVAILABLE_SENTINEL"))
    );
    fails(
        prepare(
            &saved,
            &SandboxSpecPatch::new(),
            SnapshotConfigMode::Saved,
            SavedConfigurationContext::Disk {
                starts_command: true,
            },
            inputs(),
        ),
        "SCFG_BINDING",
    );
    assert!(!format!("{plan:?} {:?}", plan.bindings()).contains("SENTINEL"));
}

#[test]
fn shared_gateway_use_cannot_be_deferred_with_future_command() {
    fails(
        prepare(
            &shared(),
            &SandboxSpecPatch::new(),
            SnapshotConfigMode::Saved,
            disk(),
            BTreeMap::new(),
        ),
        "SCFG_BINDING",
    );
    let command_only = document(
        json!({"runtime":{"env":known(json!({"TOKEN":{"kind":"binding","id":"later"}}))}}),
        json!({"later":"text"}),
    );
    let plan = prepare(
        &command_only,
        &SandboxSpecPatch::new(),
        SnapshotConfigMode::Saved,
        disk(),
        BTreeMap::new(),
    )
    .unwrap();
    assert!(plan.supply_gaps().immediate.is_empty());
    assert!(plan.supply_gaps().before_new_command.contains("later"));
    assert!(plan.runtime().command_defaults().is_err());
}

#[test]
fn explicit_runtime_override_does_not_erase_shared_substitution_requirement() {
    let patch = SandboxSpecPatch::new().env(vec![EnvVar {
        key: "TOKEN".into(),
        value: "EXPLICIT_SENTINEL".into(),
    }]);
    fails(
        prepare(
            &shared(),
            &patch,
            SnapshotConfigMode::Saved,
            disk(),
            BTreeMap::new(),
        ),
        "SCFG_BINDING",
    );
    let plan = prepare(
        &shared(),
        &patch,
        SnapshotConfigMode::Saved,
        disk(),
        BTreeMap::from([("shared".into(), text("BOUND_SENTINEL"))]),
    )
    .unwrap();
    assert_eq!(
        plan.runtime().command_defaults().unwrap().env[0].value,
        "EXPLICIT_SENTINEL"
    );
    assert!(
        !plan.demand().bindings()["shared"]
            .consumers
            .contains(&SavedBindingConsumer::NewCommand)
    );
    let mut secrets = SecretsConfig::default();
    plan.secrets().apply_to(&mut secrets).unwrap();
    assert_eq!(&*secrets.secrets[0].value, "BOUND_SENTINEL");
}

#[test]
fn wrong_unused_and_pending_only_bindings_are_rejected_without_disclosing_values() {
    let saved = shared();
    fails(
        prepare(
            &saved,
            &SandboxSpecPatch::new(),
            SnapshotConfigMode::Saved,
            disk(),
            BTreeMap::from([(
                "shared".into(),
                ConfigurationBindingInput::Gateway(GatewayBindingInput::DnsResolver(
                    "SECRET_SENTINEL".into(),
                )),
            )]),
        ),
        "SCFG_BINDING",
    );
    let mut value = serde_json::to_value(&saved).unwrap();
    value["pending"] = json!({"runtime":{"cmd":known(json!([{"kind":"binding","id":"pending"}]))}});
    value["bindings"]["pending"] = json!("text");
    let saved = SavedSandboxConfig::from_bytes(&serde_json::to_vec(&value).unwrap()).unwrap();
    let plan = prepare(
        &saved,
        &SandboxSpecPatch::new(),
        SnapshotConfigMode::Saved,
        disk(),
        BTreeMap::from([("shared".into(), text("BOUND_SENTINEL"))]),
    )
    .unwrap();
    assert!(!plan.demand().bindings().contains_key("pending"));
    fails(
        prepare(
            &saved,
            &SandboxSpecPatch::new(),
            SnapshotConfigMode::Saved,
            disk(),
            BTreeMap::from([
                ("shared".into(), text("BOUND_SENTINEL")),
                ("pending".into(), text("PENDING_SENTINEL")),
            ]),
        ),
        "SCFG_BINDING",
    );
}

#[test]
fn malformed_original_document_is_rejected_before_fresh_or_explicit_masking() {
    let mut saved = shared();
    saved
        .bindings
        .insert("shared".into(), SavedBindingKind::DnsResolver);
    fails(
        prepare(
            &saved,
            &SandboxSpecPatch::new(),
            SnapshotConfigMode::Fresh,
            disk(),
            BTreeMap::new(),
        ),
        "SCFG_SCHEMA",
    );
}

#[test]
fn fresh_discards_optional_command_defaults_but_retains_gateway_requirements() {
    let plan = prepare(
        &shared(),
        &SandboxSpecPatch::new(),
        SnapshotConfigMode::Fresh,
        disk(),
        BTreeMap::from([("shared".into(), text("BOUND_SENTINEL"))]),
    )
    .unwrap();
    assert_eq!(
        plan.runtime().command_defaults().unwrap().env[0].value,
        "LOWER_SENTINEL"
    );
    assert!(plan.demand().bindings()["shared"].required_now);
    assert!(
        !plan.demand().bindings()["shared"]
            .consumers
            .contains(&SavedBindingConsumer::NewCommand)
    );
}

#[test]
fn full_fresh_preserves_independent_captured_only_bindings_and_geometry() {
    let saved = document(json!({}), json!({}));
    let captured = SavedBindingUses::from([(
        "captured".into(),
        SavedBindingUse {
            kind: SavedBindingKind::Text,
            consumers: [SavedBindingConsumer::NewCommand].into(),
        },
    )]);
    let geometry = SandboxResources {
        cpus: 4,
        max_cpus: 8,
        memory_mib: 1024,
        max_memory_mib: 2048,
        ..Default::default()
    };
    let context = || SavedConfigurationContext::Full {
        resources: &geometry,
        security: SecurityProfile::default(),
        bindings: &captured,
    };
    fails(
        prepare(
            &saved,
            &SandboxSpecPatch::new(),
            SnapshotConfigMode::Fresh,
            context(),
            BTreeMap::new(),
        ),
        "SCFG_BINDING",
    );
    let plan = prepare(
        &saved,
        &SandboxSpecPatch::new(),
        SnapshotConfigMode::Fresh,
        context(),
        BTreeMap::from([("captured".into(), text("CAPTURED_SENTINEL"))]),
    )
    .unwrap();
    assert!(plan.demand().bindings()["captured"].required_now);
    assert!(plan.demand().bindings()["captured"].captured_execution);
    assert!(plan.bindings().contains_key("captured"));
    assert!(plan.resources().requires_full_compatibility());
    assert_eq!(plan.resources().resources().unwrap().memory_mib, 1024);
    assert!(plan.runtime().inputs().requires_full_identity);
    assert!(plan.storage().selection().requires_full_identity);
    assert!(plan.gateway().selection().requires_full_compatibility);
}

#[test]
fn listener_bindings_disambiguate_before_explicit_matching_and_retain_demand() {
    let port = |id: &str| json!({"binding":{"id":id},"guest_port":80,"protocol":"tcp"});
    let saved = document(
        json!({"network":{"ports":known(json!([port("one"),port("two")]))}}),
        json!({"one":"listener","two":"listener"}),
    );
    let patch =
        SandboxSpecPatch::new().network(NetworkSpecPatch::new().ports(vec![PublishedPortSpec {
            host_bind: "127.0.0.1".into(),
            host_port: 8082,
            guest_port: 80,
            protocol: PortProtocol::Tcp,
        }]));
    let plan = prepare(
        &saved,
        &patch,
        SnapshotConfigMode::Saved,
        disk(),
        BTreeMap::from([(
            "one".into(),
            ConfigurationBindingInput::Listener(ListenerBindingInput {
                host_bind: "127.0.0.1".parse().unwrap(),
                host_port: 8081,
            }),
        )]),
    )
    .unwrap();
    assert!(plan.demand().bindings().contains_key("one"));
    assert!(!plan.demand().bindings().contains_key("two"));
    let mut native = microsandbox_types::NetworkSpec::default();
    plan.listeners().apply_to(&mut native).unwrap();
    assert_eq!(
        native.ports.iter().map(|p| p.host_port).collect::<Vec<_>>(),
        [8081, 8082]
    );
}

#[test]
fn registry_is_bounded_before_cloning_shared_values() {
    fails(
        prepare(
            &shared(),
            &SandboxSpecPatch::new(),
            SnapshotConfigMode::Saved,
            disk(),
            BTreeMap::from([(
                "shared".into(),
                text(&"x".repeat(MAX_SAVED_CONFIG_BYTES + 1)),
            )]),
        ),
        "SCFG_LIMIT",
    );
}

#[test]
fn late_preparation_failure_cannot_modify_explicit_destination_or_source() {
    let saved = shared();
    let patch = SandboxSpecPatch::new()
        .runtime(SandboxRuntimeOptionsPatch::new().entrypoint(vec!["EXPLICIT_SENTINEL".into()]))
        .resources(SandboxResourcesPatch::new().cpus(4).max_cpus(2));
    let source_bytes = serde_json::to_vec(&saved).unwrap();
    let explicit_before = format!("{patch:?}");
    fails(
        prepare(
            &saved,
            &patch,
            SnapshotConfigMode::Saved,
            disk(),
            BTreeMap::from([("shared".into(), text("BOUND_SENTINEL"))]),
        ),
        "SCFG_VALUE",
    );
    assert_eq!(serde_json::to_vec(&saved).unwrap(), source_bytes);
    assert_eq!(format!("{patch:?}"), explicit_before);
}
