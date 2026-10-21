//! Host-private evidence for serializer-omitted defaults. Never portable snapshot metadata.

use std::collections::BTreeSet;
use std::fmt;

use microsandbox_types::{NetworkSpec, SandboxSpec, SandboxSpecPatch, TransparentHugePagePolicy};
use serde::{Deserialize, Serialize};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const ABSENT_NETWORK_FIELDS: [AbsentNetworkField; 10] = [
    AbsentNetworkField::Policy,
    AbsentNetworkField::Dns,
    AbsentNetworkField::Tls,
    AbsentNetworkField::Secrets,
    AbsentNetworkField::MaxConnections,
    AbsentNetworkField::MaxInboundTcpConnections,
    AbsentNetworkField::MaxUdpConnections,
    AbsentNetworkField::TcpAcceptQueueSize,
    AbsentNetworkField::RateLimiter,
    AbsentNetworkField::OutboundProxy,
];

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Only these optional subdocuments/scalars may be certified absent. Adding a new setting
/// does not grant an old record knowledge of it. Concrete nested settings still need their
/// own recorded fields; this list cannot certify missing descendants of a present object.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum AbsentNetworkField {
    Policy,
    Dns,
    Tls,
    Secrets,
    MaxConnections,
    MaxInboundTcpConnections,
    MaxUdpConnections,
    TcpAcceptQueueSize,
    RateLimiter,
    OutboundProxy,
}

/// The stored values are nonsecret defaults, not hashes of credentials or raw config.
/// Every use compares them with the current typed value; omission alone proves nothing.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct FieldPresence {
    thp: Option<TransparentHugePagePolicy>,
    absent_network: BTreeSet<AbsentNetworkField>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl AbsentNetworkField {
    fn key(self) -> &'static str {
        match self {
            Self::Policy => "policy",
            Self::Dns => "dns",
            Self::Tls => "tls",
            Self::Secrets => "secrets",
            Self::MaxConnections => "max_connections",
            Self::MaxInboundTcpConnections => "max_inbound_tcp_connections",
            Self::MaxUdpConnections => "max_udp_connections",
            Self::TcpAcceptQueueSize => "tcp_accept_queue_size",
            Self::RateLimiter => "rate_limiter",
            Self::OutboundProxy => "outbound_proxy",
        }
    }

    fn is_absent(self, network: &NetworkSpec) -> bool {
        match self {
            Self::Policy => network.policy.is_none(),
            Self::Dns => network.dns.is_none(),
            Self::Tls => network.tls.is_none(),
            Self::Secrets => network.secrets.is_none(),
            Self::MaxConnections => network.max_tcp_connections.is_none(),
            Self::MaxInboundTcpConnections => network.max_inbound_tcp_connections.is_none(),
            Self::MaxUdpConnections => network.max_udp_connections.is_none(),
            Self::TcpAcceptQueueSize => network.tcp_accept_queue_size.is_none(),
            Self::RateLimiter => network.rate_limiter.is_none(),
            Self::OutboundProxy => network.outbound_proxy.is_none(),
        }
    }
}

impl FieldPresence {
    pub(crate) fn declared(spec: &SandboxSpec) -> Self {
        let absent_network = ABSENT_NETWORK_FIELDS
            .into_iter()
            .filter(|field| field.is_absent(&spec.network))
            .collect();
        Self {
            thp: Some(spec.resources.thp),
            absent_network,
        }
    }

    pub(crate) fn declare_thp(&mut self, policy: TransparentHugePagePolicy) {
        self.thp = Some(policy);
    }

    pub(crate) fn overlay(&mut self, other: Self) {
        if other.thp.is_some() {
            self.thp = other.thp;
        }
        self.absent_network.extend(other.absent_network);
    }

    pub(crate) fn knows_thp(&self, spec: &SandboxSpec) -> bool {
        self.thp == Some(spec.resources.thp)
    }

    pub(crate) fn knows_absent_network(&self, key: &str, spec: &SandboxSpec) -> bool {
        self.absent_network
            .iter()
            .any(|field| field.key() == key && field.is_absent(&spec.network))
    }

    pub(crate) fn retain_matching(&mut self, spec: &SandboxSpec) {
        if !self.knows_thp(spec) {
            self.thp = None;
        }
        self.absent_network
            .retain(|field| field.is_absent(&spec.network));
    }

    /// A missing parent is not a serializer-omitted child. Discard its evidence before
    /// decoding synthesizes a default parent that a subsequent writer might persist.
    pub(crate) fn retain_recorded_parents(&mut self, resources: bool, network: bool) {
        if !resources {
            self.thp = None;
        }
        if !network {
            self.absent_network.clear();
        }
    }

    /// Only an actual nullable clear establishes absence. Ordinary patch omissions inherit
    /// values and must not be promoted to declarations during historical reconstruction.
    pub(crate) fn apply_explicit(&mut self, patch: &SandboxSpecPatch) {
        if let Some(thp) = patch.resources.thp {
            self.thp = Some(thp);
        }
        if matches!(patch.network.outbound_proxy, Some(None)) {
            self.absent_network
                .insert(AbsentNetworkField::OutboundProxy);
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl fmt::Debug for FieldPresence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FieldPresence")
            .finish_non_exhaustive()
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(all(test, feature = "local"))]
mod tests {
    use microsandbox_types::snapshot::saved_config::{SavedUnknownReason, SavedValue};
    use serde_json::{Value, json};

    use super::*;
    use crate::sandbox::SandboxBuilder;
    use crate::snapshot::saved_config::{
        NetworkCaptureBindings, NetworkCaptureControls, ResourceCaptureObservation,
        RuntimeCaptureSource,
    };
    use crate::{SandboxConfig, SandboxConfigPatch};

    fn build() -> SandboxConfig {
        SandboxBuilder::new("presence")
            .image("alpine")
            .finish(None, None)
            .unwrap()
    }

    fn raw(config: &SandboxConfig) -> Value {
        serde_json::to_value(config.clone_for_persistence()).unwrap()
    }

    fn thp(value: &Value) -> Option<SavedValue<TransparentHugePagePolicy>> {
        RuntimeCaptureSource::from_recorded(value, None, None)
            .unwrap()
            .project_resources(ResourceCaptureObservation::default())
            .unwrap()
            .thp
    }

    #[test]
    fn fresh_defaults_have_value_bound_evidence_without_changing_source_fields() {
        let config = build();
        let record = raw(&config);
        assert!(record.pointer("/resources/thp").is_none());
        assert!(record.pointer("/network/dns").is_none());
        assert_eq!(
            thp(&record).unwrap().value(),
            Some(&TransparentHugePagePolicy::Madvise)
        );
        let source = RuntimeCaptureSource::from_recorded(&record, None, None).unwrap();
        let network = source
            .project_network(
                NetworkCaptureBindings::default(),
                &NetworkCaptureControls::default(),
            )
            .unwrap();
        assert!(matches!(network.dns, Some(SavedValue::Default {})));
        assert!(matches!(network.tls, Some(SavedValue::Default {})));
        assert!(matches!(
            network.outbound_proxy,
            Some(SavedValue::Default {})
        ));
        assert!(
            !serde_json::to_string(&network)
                .unwrap()
                .contains("field_presence")
        );
        let metadata = record["field_presence"].to_string();
        assert!(!metadata.contains("presence"));
        assert!(!metadata.contains("alpine"));
    }

    #[test]
    fn old_records_remain_unknown_through_decode_reconstruction_and_persistence() {
        let mut record = raw(&build());
        record.as_object_mut().unwrap().remove("field_presence");
        let old: SandboxConfig = serde_json::from_value(record.clone()).unwrap();
        let reconstructed = SandboxBuilder::from(old).finish(None, None).unwrap();
        for record in [record, raw(&reconstructed)] {
            assert!(matches!(
                thp(&record),
                Some(SavedValue::Unknown {
                    reason: SavedUnknownReason::NotRecorded
                })
            ));
            let source = RuntimeCaptureSource::from_recorded(&record, None, None).unwrap();
            let network = source
                .project_network(
                    NetworkCaptureBindings::default(),
                    &NetworkCaptureControls::default(),
                )
                .unwrap();
            assert!(matches!(
                network.dns,
                Some(SavedValue::Unknown {
                    reason: SavedUnknownReason::NotRecorded
                })
            ));
        }
    }

    #[test]
    fn valid_retained_evidence_survives_reconstruction_but_changes_cannot_borrow_it() {
        let config: SandboxConfig = serde_json::from_value(raw(&build())).unwrap();
        let rebuilt = SandboxBuilder::from(config).finish(None, None).unwrap();
        assert_eq!(
            thp(&raw(&rebuilt)).unwrap().value(),
            Some(&TransparentHugePagePolicy::Madvise)
        );
        let never = SandboxBuilder::new("presence")
            .image("alpine")
            .thp(TransparentHugePagePolicy::Never)
            .finish(None, None)
            .unwrap();
        let mut changed = raw(&never);
        // An older writer omitting the changed default must not revive the old Never claim.
        changed["resources"].as_object_mut().unwrap().remove("thp");
        assert!(matches!(
            thp(&changed),
            Some(SavedValue::Unknown {
                reason: SavedUnknownReason::NotRecorded
            })
        ));
        let decoded: SandboxConfig = serde_json::from_value(changed).unwrap();
        assert!(decoded.field_presence.as_ref().unwrap().thp.is_none());
        let mut direct = build();
        direct.spec.resources.thp = TransparentHugePagePolicy::Never;
        assert!(
            direct
                .clone_for_persistence()
                .field_presence
                .unwrap()
                .thp
                .is_none()
        );
    }

    #[test]
    fn concrete_nested_fields_cannot_be_certified_by_an_old_absence_marker() {
        let mut record = raw(&build());
        record["network"]["dns"] = json!({});
        let source = RuntimeCaptureSource::from_recorded(&record, None, None).unwrap();
        let network = source
            .project_network(
                NetworkCaptureBindings::default(),
                &NetworkCaptureControls::default(),
            )
            .unwrap();
        assert!(matches!(
            network.dns,
            Some(SavedValue::Unknown {
                reason: SavedUnknownReason::NotRecorded
            })
        ));
        let config: SandboxConfig = serde_json::from_value(record).unwrap();
        assert!(
            !config
                .field_presence
                .as_ref()
                .unwrap()
                .knows_absent_network("dns", &config.spec)
        );
    }

    #[test]
    fn missing_parent_or_malformed_future_evidence_does_not_certify_defaults_or_break_decode() {
        for hint in [
            json!({"future":true}),
            json!({"absent_network":["future"]}),
            json!({"thp":"future"}),
            json!("wrong-shape"),
        ] {
            let mut record = raw(&build());
            record["field_presence"] = hint;
            let config: SandboxConfig = serde_json::from_value(record.clone()).unwrap();
            assert!(config.field_presence.is_none());
            assert!(matches!(thp(&record), Some(SavedValue::Unknown { .. })));
        }
        let mut record = raw(&build());
        record.as_object_mut().unwrap().remove("resources");
        record.as_object_mut().unwrap().remove("network");
        let decoded: SandboxConfig = serde_json::from_value(record.clone()).unwrap();
        let rebuilt = SandboxBuilder::from(decoded).finish(None, None).unwrap();
        for record in [record, raw(&rebuilt)] {
            assert!(matches!(thp(&record), Some(SavedValue::Unknown { .. })));
            let source = RuntimeCaptureSource::from_recorded(&record, None, None).unwrap();
            let network = source
                .project_network(
                    NetworkCaptureBindings::default(),
                    &NetworkCaptureControls::default(),
                )
                .unwrap();
            assert!(matches!(network.dns, Some(SavedValue::Unknown { .. })));
        }
    }

    #[test]
    fn explicit_default_and_nullable_clear_establish_only_the_declared_fields() {
        let mut record = raw(&build());
        record.as_object_mut().unwrap().remove("field_presence");
        let old: SandboxConfig = serde_json::from_value(record).unwrap();
        let mut clear = SandboxConfigPatch::new();
        clear.spec.network.outbound_proxy = Some(None);
        let config = SandboxBuilder::from(old)
            .thp(TransparentHugePagePolicy::Madvise)
            .overlay(clear)
            .finish(None, None)
            .unwrap();
        let record = raw(&config);
        assert_eq!(
            thp(&record).unwrap().value(),
            Some(&TransparentHugePagePolicy::Madvise)
        );
        let source = RuntimeCaptureSource::from_recorded(&record, None, None).unwrap();
        let network = source
            .project_network(
                NetworkCaptureBindings::default(),
                &NetworkCaptureControls::default(),
            )
            .unwrap();
        assert!(matches!(
            network.outbound_proxy,
            Some(SavedValue::Default {})
        ));
        assert!(matches!(network.dns, Some(SavedValue::Unknown { .. })));
    }

    #[test]
    fn explicit_full_spec_is_a_new_declaration_and_raw_patch_reconstruction_is_not() {
        let mut record = raw(&build());
        record.as_object_mut().unwrap().remove("field_presence");
        let old: SandboxConfig = serde_json::from_value(record).unwrap();
        let patch = SandboxConfigPatch::from_present_fields(old.clone());
        let config = SandboxBuilder::from(old.clone())
            .overlay(patch)
            .finish(None, None)
            .unwrap();
        assert!(matches!(
            thp(&raw(&config)),
            Some(SavedValue::Unknown { .. })
        ));
        let declaration = serde_json::to_string(&old.spec).unwrap();
        let config = SandboxBuilder::from_spec_json(&declaration)
            .unwrap()
            .finish(None, None)
            .unwrap();
        assert_eq!(
            thp(&raw(&config)).unwrap().value(),
            Some(&TransparentHugePagePolicy::Madvise)
        );
    }

    #[test]
    #[ignore = "requires MSB_PRESENCE_CAPTURE_FIXTURES from saved-presence-evidence.py"]
    fn runtime_presence_records_preserve_known_and_unknown_fields() {
        let directory = std::path::PathBuf::from(
            std::env::var_os("MSB_PRESENCE_CAPTURE_FIXTURES").expect("live fixture directory"),
        );
        for (name, known) in [
            ("current-source", true),
            ("runtime-modified-source", true),
            ("old-modified-config", false),
            ("new-after-old-source", false),
        ] {
            let record: Value = serde_json::from_slice(
                &std::fs::read(directory.join("current").join(format!("{name}.json"))).unwrap(),
            )
            .unwrap();
            let source = RuntimeCaptureSource::from_recorded(&record, None, None).unwrap();
            let network = source
                .project_network(
                    NetworkCaptureBindings::default(),
                    &NetworkCaptureControls::default(),
                )
                .unwrap();
            if known {
                assert_eq!(
                    thp(&record).unwrap().value(),
                    Some(&TransparentHugePagePolicy::Madvise)
                );
                assert!(
                    matches!(network.dns, Some(SavedValue::Default {})),
                    "{name}"
                );
            } else {
                assert!(
                    matches!(thp(&record), Some(SavedValue::Unknown { .. })),
                    "{name}"
                );
                assert!(
                    matches!(network.dns, Some(SavedValue::Unknown { .. })),
                    "{name}"
                );
            }
        }
    }
}
