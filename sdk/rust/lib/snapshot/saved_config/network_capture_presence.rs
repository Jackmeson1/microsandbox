//! Presence checks for raw retained network records; serde defaults are not capture evidence.

use serde_json::Value;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(super) fn complete_field(raw: &Value, field: &str) -> bool {
    raw.get(field).is_some_and(|value| complete(value, field))
}

pub(super) fn complete(raw: &Value, field: &str) -> bool {
    match field {
        "dns" => fields(
            raw,
            &["rebind_protection", "nameservers", "query_timeout_ms"],
        ),
        "policy" => {
            fields(raw, &["default_egress", "default_ingress", "rules"])
                && array(raw.get("rules"), |rule| {
                    fields(
                        rule,
                        &["direction", "destination", "protocols", "ports", "action"],
                    )
                })
        }
        "ports" => array(Some(raw), |port| fields(port, &["guest_port", "protocol"])),
        "tls" => {
            fields(
                raw,
                &[
                    "enabled",
                    "intercepted_ports",
                    "bypass",
                    "verify_upstream",
                    "block_quic_on_intercept",
                    "upstream_ca_cert",
                    "scoped_verify_upstream",
                ],
            ) && raw
                .get("scoped_upstream_ca_cert")
                .or_else(|| raw.get("scoped_upstream_ca_certs"))
                .is_some()
                && raw
                    .get("intercept_ca")
                    .or_else(|| raw.get("ca"))
                    .is_some_and(|ca| fields(ca, &["cert_path", "key_path"]))
        }
        "secrets" => {
            fields(raw, &["passthrough_hosts", "secrets", "violation_action"])
                && array(raw.get("secrets"), |secret| {
                    fields(
                        secret,
                        &[
                            "env_var",
                            "placeholder",
                            "allowed_hosts",
                            "substitution",
                            "passthrough_hosts",
                            "violation_action",
                            "require_tls_identity",
                        ],
                    ) && secret.get("substitution").is_some_and(|substitution| {
                        fields(substitution, &["headers", "header_fields", "query", "body"])
                    })
                })
        }
        "outbound_proxy" => match raw.get("protocol").and_then(Value::as_str) {
            Some("http_connect") => fields(raw, &["address"]),
            Some("socks4") => fields(raw, &["address", "user_id"]),
            Some("socks5") => fields(raw, &["address", "credentials"]),
            _ => false,
        },
        "http" => fields(
            raw,
            &[
                "deny_response",
                "deny_response_format",
                "deny_message",
                "network_deny_message",
                "secret_deny_message",
            ],
        ),
        // Optional dimensions must be explicitly present (null is meaningful). An
        // absent ingress/bucket/burst could have been omitted by an older producer.
        "rate_limiter" => {
            fields(raw, &["egress", "ingress"])
                && ["egress", "ingress"].iter().all(|direction| {
                    nullable(raw.get(direction), |rate| {
                        fields(rate, &["bandwidth", "ops"])
                            && ["bandwidth", "ops"].iter().all(|bucket| {
                                nullable(rate.get(bucket), |bucket| {
                                    fields(bucket, &["size", "refill_time_ms", "one_time_burst"])
                                })
                            })
                    })
                })
        }
        _ => false,
    }
}

fn fields(raw: &Value, names: &[&str]) -> bool {
    names.iter().all(|name| raw.get(*name).is_some())
}

fn array(raw: Option<&Value>, predicate: impl Fn(&Value) -> bool) -> bool {
    raw.and_then(Value::as_array)
        .is_some_and(|values| values.iter().all(predicate))
}

fn nullable(raw: Option<&Value>, predicate: impl FnOnce(&Value) -> bool) -> bool {
    raw.is_some_and(|value| value.is_null() || predicate(value))
}
