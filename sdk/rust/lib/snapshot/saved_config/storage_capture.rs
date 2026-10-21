//! Guarded storage projection with explicit observed backing and no source-host lookup.

use std::collections::BTreeMap;

use microsandbox_types::snapshot::Manifest;
use microsandbox_types::snapshot::saved_config::{
    MAX_SAVED_CONFIG_ENTRIES, SavedBindingReference, SavedExternalMountCapture, SavedMount,
    SavedOrigin, SavedStorageConfig, SavedUnknownReason, SavedValue, SavedVsockRoute,
};
use serde_json::Value;

use super::RuntimeCaptureSource;
use crate::{MicrosandboxError, MicrosandboxResult};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Logical replacements and independently observed storage, acquired under the same source
/// guard as the configuration and descriptor. This never contains source paths or volume names.
#[derive(Default)]
pub struct StorageCaptureBindings {
    /// Exact canonical guest path to external backing requirement. Owned/tmpfs mounts need none.
    /// Named storage must reflect the active volume, not transient creation/ensure metadata.
    pub mounts: BTreeMap<String, SavedExternalMountCapture>,
    /// One logical endpoint per recorded socket route, in original source order.
    pub routes: Vec<SavedBindingReference>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl RuntimeCaptureSource<'_> {
    /// Produce a complete known inventory or preserve it as unknown. A partially recorded
    /// mount list must not become a shorter list that silently drops required resources.
    /// The authoritative descriptor retains owned backing; this projection cannot replace it.
    /// This method performs no filesystem access, named-volume lookup or socket connection.
    pub fn project_storage(
        &self,
        mut bindings: StorageCaptureBindings,
        manifest: &Manifest,
    ) -> MicrosandboxResult<SavedStorageConfig> {
        if bindings.mounts.len() > MAX_SAVED_CONFIG_ENTRIES
            || bindings.routes.len() > MAX_SAVED_CONFIG_ENTRIES
            || self.config.spec.mounts.len() > MAX_SAVED_CONFIG_ENTRIES
            || self.config.spec.vsock.routes.len() > MAX_SAVED_CONFIG_ENTRIES
        {
            return Err(error("SCFG_LIMIT", "too many storage resources"));
        }
        let mounts = if self
            .recorded
            .get("mounts")
            .and_then(Value::as_array)
            .is_some_and(|mounts| mounts.iter().all(complete_mount))
        {
            let mut mounts = self
                .config
                .spec
                .mounts
                .iter()
                .map(|source| {
                    let external = bindings.mounts.remove(source.guest());
                    SavedMount::from_source(source, external).map_err(manifest_error)
                })
                .collect::<MicrosandboxResult<Vec<_>>>()?;
            // Guest paths must already be canonical (validated by from_source). Sort only
            // the portable inventory; never normalize or re-resolve a source host path.
            mounts.sort_by(|a, b| {
                (a.guest().split('/').count(), a.guest())
                    .cmp(&(b.guest().split('/').count(), b.guest()))
            });
            configured(mounts)
        } else {
            unknown()
        };
        if !bindings.mounts.is_empty() {
            return Err(error(
                "SCFG_BINDING",
                "mount requirements do not match a complete recorded inventory",
            ));
        }
        let routes = if self
            .recorded
            .pointer("/vsock/routes")
            .and_then(Value::as_array)
            .is_some_and(|routes| {
                routes
                    .iter()
                    .all(|route| fields(route, &["port", "socket_type"]))
            }) {
            if bindings.routes.len() != self.config.spec.vsock.routes.len() {
                return Err(error(
                    "SCFG_BINDING",
                    "each recorded socket route needs one endpoint requirement",
                ));
            }
            configured(
                self.config
                    .spec
                    .vsock
                    .routes
                    .iter()
                    .zip(bindings.routes)
                    .map(|(source, binding)| {
                        SavedVsockRoute::from_source(source, binding).map_err(manifest_error)
                    })
                    .collect::<MicrosandboxResult<Vec<_>>>()?,
            )
        } else {
            if !bindings.routes.is_empty() {
                return Err(error(
                    "SCFG_BINDING",
                    "socket requirements do not match a complete recorded inventory",
                ));
            }
            unknown()
        };
        let result = SavedStorageConfig {
            mounts: Some(mounts),
            vsock: Some(routes),
        };
        result
            .validate_owned_projection(manifest)
            .map_err(manifest_error)?;
        // An ID reused for incompatible mount/socket kinds must fail at capture,
        // before a later document assembly could mistakenly unify its consumers.
        result.binding_uses().map_err(manifest_error)?;
        Ok(result)
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn complete_mount(raw: &Value) -> bool {
    let Some(kind) = raw.get("type").and_then(Value::as_str) else {
        return false;
    };
    if raw.get("guest").is_none() {
        return false;
    }
    // Owned mounts refer to the independently validated descriptor inventory; their
    // backing/options are authoritative there and are deliberately not duplicated.
    if kind == "Owned" {
        return true;
    }
    if !raw.get("options").is_some_and(|options| {
        fields(
            options,
            &[
                "readonly",
                "noexec",
                "nosuid",
                "nodev",
                "override_uid",
                "override_gid",
            ],
        )
    }) {
        return false;
    }
    match kind {
        "Bind" => fields(
            raw,
            &[
                "stat_virtualization",
                "host_permissions",
                "follow_root_symlinks",
                "quota_mib",
            ],
        ),
        "Named" => fields(
            raw,
            &[
                "stat_virtualization",
                "host_permissions",
                "follow_root_symlinks",
            ],
        ),
        "Tmpfs" => fields(raw, &["size_mib"]),
        "DiskImage" => fields(raw, &["format", "fstype"]),
        _ => false,
    }
}

fn fields(raw: &Value, names: &[&str]) -> bool {
    names.iter().all(|name| raw.get(*name).is_some())
}

fn configured<T>(value: T) -> SavedValue<T> {
    SavedValue::Value {
        value,
        origin: SavedOrigin::Configured,
    }
}

fn unknown<T>() -> SavedValue<T> {
    SavedValue::Unknown {
        reason: SavedUnknownReason::NotRecorded,
    }
}

fn manifest_error(error: impl std::fmt::Display) -> MicrosandboxError {
    MicrosandboxError::InvalidConfig(error.to_string())
}

fn error(code: &str, detail: &str) -> MicrosandboxError {
    MicrosandboxError::InvalidConfig(format!("{code}: storage: {detail}"))
}
