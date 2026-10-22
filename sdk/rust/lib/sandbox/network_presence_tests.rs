//! Real serializer shapes must retain declared omissions without inventing old intent.

use microsandbox_types::snapshot::saved_config::{SavedNetworkConfig, SavedValue};
use microsandbox_types::{NetworkSpec, OutboundProxy};
use serde_json::{Value, json};

use super::{SandboxBuilder, SandboxConfig, SandboxConfigPatch};
use crate::snapshot::saved_config::{
    NetworkCaptureControls, NetworkCaptureSection, RuntimeCaptureSource,
};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn declared() -> SandboxConfig {
    let mut patch = SandboxConfigPatch::new();
    patch.spec.network = serde_json::from_value::<NetworkSpec>(json!({
        "trust_host_cas": false,
        "outbound_proxy": {"protocol":"socks5", "address":"127.0.0.1:1080"},
        "tls": {"enabled":true},
        "secrets": {"secrets":[{
            "env_var":"TOKEN", "source":{"kind":"env","var":"PRIVATE_HOST_ENV"},
            "placeholder":"token-placeholder", "allowed_hosts":[{"exact":"example.com"}]
        }]},
        "rate_limiter":{"egress":{"bandwidth":{"size":4096,"refill_time_ms":100}}}
    }))
    .unwrap()
    .into();
    SandboxBuilder::new("network-presence")
        .image("alpine")
        .overlay(patch)
        .finish(None, None)
        .unwrap()
}

fn raw(config: &SandboxConfig) -> Value {
    serde_json::to_value(config.clone_for_persistence()).unwrap()
}

fn project(raw: &Value) -> SavedNetworkConfig {
    let source = RuntimeCaptureSource::from_recorded(raw, None, None).unwrap();
    let bindings = source
        .network_requirements(NetworkCaptureSection::Active, vec![])
        .unwrap();
    source
        .project_network(bindings, &NetworkCaptureControls::default())
        .unwrap()
}

fn unknown<T>(value: &Option<SavedValue<T>>) -> bool {
    matches!(value, Some(SavedValue::Unknown { .. }))
}

fn assert_known(saved: &SavedNetworkConfig) {
    assert!(saved.http.as_ref().unwrap().value().is_some());
    assert!(saved.secrets.as_ref().unwrap().value().is_some());
    assert!(saved.rate_limiter.as_ref().unwrap().value().is_some());
    assert!(saved.outbound_proxy.as_ref().unwrap().value().is_some());
}

fn assert_unknown(saved: &SavedNetworkConfig) {
    assert!(unknown(&saved.http));
    assert!(unknown(&saved.secrets));
    assert!(unknown(&saved.rate_limiter));
    assert!(unknown(&saved.outbound_proxy));
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[test]
fn declared_nested_defaults_survive_the_actual_serializer_without_private_values() {
    let record = raw(&declared());
    for path in [
        "/network/http/deny_message",
        "/network/outbound_proxy/credentials",
        "/network/secrets/passthrough_hosts",
        "/network/secrets/secrets/0/violation_action",
        "/network/secrets/secrets/0/substitution/header_fields",
        "/network/rate_limiter/ingress",
        "/network/rate_limiter/egress/ops",
    ] {
        assert!(record.pointer(path).is_none(), "{path}");
    }
    let hint = record["field_presence"].to_string();
    assert!(!hint.contains("PRIVATE_"));
    assert!(!hint.contains("127.0.0.1"));
    assert!(!hint.contains("token-placeholder"));
    assert!(!hint.contains("example.com"));
    let saved = project(&record);
    assert_known(&saved);
    assert!(
        saved
            .outbound_proxy
            .as_ref()
            .unwrap()
            .value()
            .unwrap()
            .credentials
            .is_none()
    );
    let secrets = saved.secrets.as_ref().unwrap().value().unwrap();
    assert_eq!(secrets.entries[0].env_var, "TOKEN");
    assert!(secrets.entries[0].substitution.header_fields.is_empty());
    let encoded = serde_json::to_string(&saved).unwrap();
    assert!(!encoded.contains("PRIVATE_"));
    assert!(!encoded.contains("field_presence"));
    let decoded: SandboxConfig = serde_json::from_value(record).unwrap();
    assert_known(&project(&raw(&SandboxBuilder::from(decoded)
        .finish(None, None)
        .unwrap())));
}

#[test]
fn old_records_and_historical_replacements_cannot_borrow_new_presence() {
    let mut record = raw(&declared());
    record.as_object_mut().unwrap().remove("field_presence");
    assert_unknown(&project(&record));
    let mut old: SandboxConfig = serde_json::from_value(record).unwrap();
    for _ in 0..2 {
        old = SandboxBuilder::from(old).finish(None, None).unwrap();
        assert_unknown(&project(&raw(&old)));
    }
    let replaced = SandboxBuilder::from(declared())
        .overlay(SandboxConfigPatch::from(old))
        .finish(None, None)
        .unwrap();
    assert_unknown(&project(&raw(&replaced)));
}

#[test]
fn missing_recorded_parents_retire_nested_evidence_before_reconstruction() {
    for (parent, field, family) in [
        ("/network", "http", "http"),
        ("/network", "outbound_proxy", "proxy"),
        ("/network", "secrets", "secrets"),
        ("/network/rate_limiter", "egress", "rates"),
        ("/network/secrets/secrets/0", "substitution", "secrets"),
    ] {
        let mut record = raw(&declared());
        record
            .pointer_mut(parent)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .remove(field);
        let decoded: SandboxConfig = serde_json::from_value(record.clone()).unwrap();
        let rebuilt = raw(&SandboxBuilder::from(decoded).finish(None, None).unwrap());
        for input in [&record, &rebuilt] {
            let saved = project(input);
            let missing = match family {
                "http" => unknown(&saved.http),
                "proxy" => unknown(&saved.outbound_proxy),
                "secrets" => unknown(&saved.secrets),
                _ => unknown(&saved.rate_limiter),
            };
            assert!(missing, "{parent}/{field}");
        }
    }
}

#[test]
fn missing_enclosing_secret_policy_stays_unknown_after_repeated_saves() {
    for explicit_passthrough in [false, true] {
        let mut record = raw(&declared());
        if explicit_passthrough {
            // An explicit empty list no longer needs its own omission hint. Per-entry
            // hints must not certify the parent policy that serde supplies on decode.
            record["network"]["secrets"]["passthrough_hosts"] = json!([]);
        }
        record["network"]["secrets"]
            .as_object_mut()
            .unwrap()
            .remove("violation_action");
        for rewrite in 0..3 {
            assert!(
                unknown(&project(&record).secrets),
                "explicit passthrough: {explicit_passthrough}, rewrite: {rewrite}"
            );
            let decoded: SandboxConfig = serde_json::from_value(record).unwrap();
            record = raw(&SandboxBuilder::from(decoded).finish(None, None).unwrap());
        }
    }
}

#[test]
fn changed_values_retire_evidence_and_cannot_revive_it_after_omission() {
    for (parent, field, replacement, family) in [
        (
            "/network/http",
            "deny_message",
            json!("PRIVATE_MESSAGE"),
            "http",
        ),
        (
            "/network/outbound_proxy",
            "credentials",
            json!({"username":"PRIVATE_USER", "password":{"kind":"env","var":"PRIVATE_PASSWORD"}}),
            "proxy",
        ),
        (
            "/network/secrets/secrets/0/substitution",
            "header_fields",
            json!(["Authorization"]),
            "secrets",
        ),
        (
            "/network/rate_limiter/egress",
            "ops",
            json!({"size":100,"refill_time_ms":100,"one_time_burst":0}),
            "rates",
        ),
    ] {
        let mut record = raw(&declared());
        record.pointer_mut(parent).unwrap()[field] = replacement;
        let changed: SandboxConfig = serde_json::from_value(record).unwrap();
        let mut rewritten = raw(&changed);
        rewritten
            .pointer_mut(parent)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .remove(field);
        let saved = project(&rewritten);
        assert!(
            match family {
                "http" => unknown(&saved.http),
                "proxy" => unknown(&saved.outbound_proxy),
                "secrets" => unknown(&saved.secrets),
                _ => unknown(&saved.rate_limiter),
            },
            "{parent}/{field}"
        );
    }
}

#[test]
fn unknown_nested_hint_is_ignored_without_breaking_config_decode() {
    let mut record = raw(&declared());
    let original = record["network"].clone();
    record["field_presence"]["nested_network"] = json!([{"kind":"future_default"}]);
    let decoded: SandboxConfig = serde_json::from_value(record.clone()).unwrap();
    assert!(decoded.field_presence.is_none());
    assert_eq!(raw(&decoded)["network"], original);
    assert_unknown(&project(&record));
}

#[test]
fn explicit_no_auth_proxy_establishes_only_that_nested_default() {
    let mut record = raw(&declared());
    record.as_object_mut().unwrap().remove("field_presence");
    let old: SandboxConfig = serde_json::from_value(record).unwrap();
    let mut patch = SandboxConfigPatch::new();
    patch.spec.network.outbound_proxy = Some(Some(OutboundProxy::Socks4 {
        address: "127.0.0.1:1080".into(),
        user_id: None,
    }));
    let config = SandboxBuilder::from(old)
        .overlay(patch)
        .finish(None, None)
        .unwrap();
    let saved = project(&raw(&config));
    assert!(saved.outbound_proxy.as_ref().unwrap().value().is_some());
    assert!(unknown(&saved.http));
    assert!(unknown(&saved.secrets));
    assert!(unknown(&saved.rate_limiter));
}

#[test]
fn omitted_required_rate_bucket_fields_cannot_be_reconstructed_as_evidence() {
    let mut record = raw(&declared());
    record
        .pointer_mut("/network/rate_limiter/egress/bandwidth")
        .unwrap()
        .as_object_mut()
        .unwrap()
        .remove("one_time_burst");
    assert!(unknown(&project(&record).rate_limiter));
    let decoded: SandboxConfig = serde_json::from_value(record).unwrap();
    let rebuilt = SandboxBuilder::from(decoded).finish(None, None).unwrap();
    assert!(unknown(&project(&raw(&rebuilt)).rate_limiter));
}

#[test]
#[ignore = "requires actual old/new runtime records from saved-presence-evidence.py"]
fn live_network_default_evidence_projects_without_reinventing_old_intent() {
    let root = std::path::PathBuf::from(std::env::var_os("MSB_NESTED_PRESENCE_FIXTURES").unwrap());
    for (name, known) in [
        ("current-source.json", true),
        ("runtime-modified-source.json", true),
        ("old-modified-config.json", false),
        ("new-after-old-source.json", false),
    ] {
        let recorded: Value =
            serde_json::from_slice(&std::fs::read(root.join(name)).unwrap()).unwrap();
        let saved = project(&recorded);
        assert_eq!(
            saved.http.as_ref().unwrap().value().is_some(),
            known,
            "{name}"
        );
        assert_eq!(unknown(&saved.http), !known, "{name}");
        let config: SandboxConfig = serde_json::from_value(recorded).unwrap();
        let rebuilt = SandboxBuilder::from(config).finish(None, None).unwrap();
        assert_eq!(unknown(&project(&raw(&rebuilt)).http), !known, "{name}");
    }
}
