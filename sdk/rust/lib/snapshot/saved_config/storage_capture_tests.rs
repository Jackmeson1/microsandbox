//! Capture preserves complete guest inventories without reusing source resource authority.

use microsandbox_types::snapshot::saved_config::{
    SavedBindRootKind, SavedBindingReference, SavedExternalMountCapture, SavedMount,
    SavedNamedStorage, SavedStorageConfig, SavedUnknownReason, SavedValue,
};
use microsandbox_types::{
    DiskImageFormat, HostPermissions, MountOptions, OwnedVolumeStorage, StatVirtualization,
    VolumeMount, VsockRouteSpec, VsockSocketType,
};
use serde_json::{Value, json};

use super::storage_tests::{manifest, owned};
use super::{RuntimeCaptureSource, StorageCaptureBindings};
use crate::sandbox::SandboxBuilder;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn reference(id: &str) -> SavedBindingReference {
    SavedBindingReference { id: id.into() }
}

fn source() -> Value {
    let mut config = SandboxBuilder::new("source")
        .image("alpine")
        .finish(None, None)
        .unwrap();
    config.spec.mounts = vec![
        VolumeMount::Tmpfs {
            guest: "/data/child".into(),
            size_mib: Some(32),
            options: MountOptions::default(),
        },
        VolumeMount::Bind {
            host: "/PRIVATE_HOST_PATH".into(),
            guest: "/data".into(),
            options: MountOptions::default(),
            stat_virtualization: StatVirtualization::Strict,
            host_permissions: HostPermissions::Private,
            follow_root_symlinks: false,
            quota_mib: Some(0),
        },
        VolumeMount::Named {
            name: "PRIVATE_VOLUME_NAME".into(),
            guest: "/named".into(),
            create: None,
            options: MountOptions::default(),
            stat_virtualization: StatVirtualization::Strict,
            host_permissions: HostPermissions::Private,
            follow_root_symlinks: false,
        },
        VolumeMount::DiskImage {
            host: "/PRIVATE_DISK_PATH".into(),
            guest: "/disk".into(),
            format: DiskImageFormat::Raw,
            fstype: Some("ext4".into()),
            options: MountOptions::default(),
        },
        VolumeMount::Owned {
            guest: "/owned".into(),
            storage: OwnedVolumeStorage::Directory { quota_mib: None },
            options: MountOptions::default(),
            stat_virtualization: StatVirtualization::Strict,
            host_permissions: HostPermissions::Private,
        },
    ];
    config.spec.vsock.routes = vec![
        VsockRouteSpec {
            host_socket: "/PRIVATE_STREAM_SOCKET".into(),
            port: 456,
            socket_type: VsockSocketType::Stream,
        },
        VsockRouteSpec {
            host_socket: "/PRIVATE_DATAGRAM_SOCKET".into(),
            port: 456,
            socket_type: VsockSocketType::Dgram,
        },
    ];
    let mut raw = serde_json::to_value(config.clone_for_persistence()).unwrap();
    // These fixtures explicitly record absence. Current serializers omit these fields;
    // without separate evidence the production adapter must keep that omission unknown.
    for mount in raw["mounts"].as_array_mut().unwrap() {
        mount["options"]["override_uid"] = Value::Null;
        mount["options"]["override_gid"] = Value::Null;
    }
    raw
}

fn bindings() -> StorageCaptureBindings {
    StorageCaptureBindings {
        mounts: [
            (
                "/data".into(),
                SavedExternalMountCapture::Bind {
                    binding: reference("bind"),
                    root_kind: SavedBindRootKind::Directory,
                },
            ),
            (
                "/named".into(),
                SavedExternalMountCapture::Named {
                    binding: reference("named"),
                    storage: SavedNamedStorage::Disk { capacity_mib: 128 },
                },
            ),
            (
                "/disk".into(),
                SavedExternalMountCapture::DiskImage {
                    binding: reference("disk"),
                },
            ),
        ]
        .into(),
        routes: vec![reference("stream"), reference("datagram")],
    }
}

fn capture(
    raw: &Value,
    bindings: StorageCaptureBindings,
) -> crate::MicrosandboxResult<SavedStorageConfig> {
    let mut descriptor = manifest(false);
    descriptor.set_owned_volumes(vec![owned("/owned")]).unwrap();
    RuntimeCaptureSource::from_recorded(raw, None, None)?.project_storage(bindings, &descriptor)
}

fn unknown<T>(value: &Option<SavedValue<T>>) -> bool {
    matches!(
        value,
        Some(SavedValue::Unknown {
            reason: SavedUnknownReason::NotRecorded
        })
    )
}

fn assert_error(raw: &Value, bindings: StorageCaptureBindings, code: &str) {
    let error = capture(raw, bindings).unwrap_err().to_string();
    assert!(error.contains(code), "{error}");
    assert!(!error.contains("PRIVATE_"), "{error}");
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[test]
fn storage_capture_preserves_guest_semantics_and_excludes_host_resources() {
    let saved = capture(&source(), bindings()).unwrap();
    let mounts = saved.mounts.as_ref().and_then(SavedValue::value).unwrap();
    assert_eq!(
        mounts.iter().map(SavedMount::guest).collect::<Vec<_>>(),
        ["/data", "/disk", "/named", "/owned", "/data/child"]
    );
    assert!(matches!(
        &mounts[0],
        SavedMount::Bind {
            quota_mib: Some(0),
            follow_root_symlinks: false,
            ..
        }
    ));
    assert!(matches!(
        &mounts[2],
        SavedMount::Named {
            storage: SavedNamedStorage::Disk { capacity_mib: 128 },
            ..
        }
    ));
    let routes = saved.vsock.as_ref().and_then(SavedValue::value).unwrap();
    assert_eq!(routes[0].socket_type, VsockSocketType::Stream);
    assert_eq!(routes[1].socket_type, VsockSocketType::Dgram);
    assert!(!serde_json::to_string(&saved).unwrap().contains("PRIVATE_"));
    assert_eq!(saved.binding_uses().unwrap().len(), 5);
}

#[test]
fn storage_capture_owned_inventory_must_match_authoritative_descriptor() {
    let raw = source();
    let adapter = RuntimeCaptureSource::from_recorded(&raw, None, None).unwrap();
    let empty = manifest(false);
    let before = empty.to_canonical_bytes().unwrap();
    let error = adapter
        .project_storage(bindings(), &empty)
        .unwrap_err()
        .to_string();
    assert!(error.contains("SCFG_IDENTITY"));
    assert_eq!(empty.to_canonical_bytes().unwrap(), before);
    let mut descriptor = manifest(true);
    descriptor
        .set_owned_volumes(vec![owned("/owned"), owned("/missing")])
        .unwrap();
    assert!(
        adapter
            .project_storage(bindings(), &descriptor)
            .unwrap_err()
            .to_string()
            .contains("SCFG_IDENTITY")
    );
}

#[test]
fn storage_capture_cannot_substitute_external_requirements_for_owned_or_tmpfs() {
    for guest in ["/owned", "/data/child"] {
        let mut supplied = bindings();
        supplied.mounts.insert(
            guest.into(),
            SavedExternalMountCapture::DiskImage {
                binding: reference("extra"),
            },
        );
        assert_error(&source(), supplied, "SCFG_BINDING");
    }
}

#[test]
fn storage_capture_requires_exact_external_kind_and_observed_named_storage() {
    for index in 0..5 {
        let mut supplied = bindings();
        match index {
            0 => {
                supplied.mounts.remove("/named");
            }
            1 => {
                supplied.mounts.insert(
                    "/named".into(),
                    SavedExternalMountCapture::DiskImage {
                        binding: reference("wrong"),
                    },
                );
            }
            2 => {
                supplied.mounts.insert(
                    "/PRIVATE_UNMATCHED".into(),
                    SavedExternalMountCapture::DiskImage {
                        binding: reference("extra"),
                    },
                );
            }
            3 => {
                supplied.mounts.remove("/data");
            }
            _ => {
                supplied.mounts.remove("/disk");
            }
        }
        assert_error(&source(), supplied, "SCFG_BINDING");
    }
    let mut supplied = bindings();
    supplied.mounts.insert(
        "/named".into(),
        SavedExternalMountCapture::Named {
            binding: reference("named"),
            storage: SavedNamedStorage::Disk { capacity_mib: 0 },
        },
    );
    assert_error(&source(), supplied, "SCFG_VALUE");
}

#[test]
fn storage_capture_missing_evidence_never_becomes_empty_inventory() {
    let mut raw = source();
    raw.as_object_mut().unwrap().remove("mounts");
    raw.as_object_mut().unwrap().remove("vsock");
    let saved = capture(&raw, StorageCaptureBindings::default()).unwrap();
    assert!(unknown(&saved.mounts));
    assert!(unknown(&saved.vsock));
    assert_error(&raw, bindings(), "SCFG_BINDING");
    raw["mounts"] = json!([]);
    raw["vsock"] = json!({"routes": []});
    // A known empty list cannot erase the descriptor's owned backing requirement.
    assert_error(&raw, StorageCaptureBindings::default(), "SCFG_IDENTITY");
    let saved = RuntimeCaptureSource::from_recorded(&raw, None, None)
        .unwrap()
        .project_storage(StorageCaptureBindings::default(), &manifest(false))
        .unwrap();
    assert!(
        saved
            .mounts
            .as_ref()
            .and_then(SavedValue::value)
            .unwrap()
            .is_empty()
    );
    assert!(
        saved
            .vsock
            .as_ref()
            .and_then(SavedValue::value)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn storage_capture_partial_mount_is_unknown_as_a_whole() {
    for pointer in [
        "/mounts/1/options/override_uid",
        "/mounts/1/options/noexec",
        "/mounts/1/follow_root_symlinks",
        "/mounts/1/quota_mib",
        "/mounts/2/host_permissions",
        "/mounts/3/fstype",
        "/mounts/0/size_mib",
    ] {
        let mut raw = source();
        let (parent, key) = pointer.rsplit_once('/').unwrap();
        raw.pointer_mut(parent)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .remove(key);
        let mut supplied = bindings();
        supplied.mounts.clear();
        let saved = capture(&raw, supplied).unwrap();
        assert!(unknown(&saved.mounts), "{pointer}");
        assert!(saved.vsock.as_ref().and_then(SavedValue::value).is_some());
        assert_error(&raw, bindings(), "SCFG_BINDING");
    }
}

#[test]
fn storage_capture_socket_types_cannot_default_or_silently_drop_routes() {
    let mut raw = source();
    raw["vsock"]["routes"][0]
        .as_object_mut()
        .unwrap()
        .remove("socket_type");
    let mut supplied = bindings();
    supplied.routes.clear();
    assert!(unknown(&capture(&raw, supplied).unwrap().vsock));
    assert_error(&raw, bindings(), "SCFG_BINDING");
    for extra in [false, true] {
        let mut supplied = bindings();
        if extra {
            supplied.routes.push(reference("extra"));
        } else {
            supplied.routes.pop();
        }
        assert_error(&source(), supplied, "SCFG_BINDING");
    }
}

#[test]
fn storage_capture_rejects_duplicate_or_noncanonical_guest_and_socket_identity() {
    let mut raw = source();
    raw["mounts"][0]["guest"] = json!("/owned");
    assert_error(&raw, bindings(), "SCFG_IDENTITY");
    let mut raw = source();
    raw["mounts"][0]["guest"] = json!("/data/../PRIVATE_ESCAPE");
    assert_error(&raw, bindings(), "SCFG_VALUE");
    let mut raw = source();
    raw["vsock"]["routes"][1]["socket_type"] = json!("stream");
    assert_error(&raw, bindings(), "SCFG_IDENTITY");
    raw["vsock"]["routes"][1]["socket_type"] = json!("dgram");
    raw["vsock"]["routes"][1]["port"] = json!(123);
    assert_error(&raw, bindings(), "SCFG_VALUE");
}

#[test]
fn storage_capture_rejects_incompatible_binding_reuse() {
    let mut supplied = bindings();
    supplied.routes[0] = reference("bind");
    assert_error(&source(), supplied, "SCFG_BINDING");
}
