//! Retained group/checkpoint receivers. Names are for selection, never backend recovery.

use std::collections::HashMap;
use std::os::raw::{c_char, c_uchar};
use std::sync::{
    Arc, Mutex, OnceLock, RwLock,
    atomic::{AtomicU64, Ordering},
};

use microsandbox::{Checkpoint, Snapshot, SnapshotCaptureOptions};
use serde_json::{Value, json};

use crate::{FfiError, cstr, get, run_c, snapshot_handle_json, snapshot_json, verify_report_json};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

#[derive(Clone)]
enum Object {
    Group(Snapshot),
    Source(Arc<microsandbox::sandbox::SandboxHandle>),
    Checkpoint(Box<Checkpoint>),
}

#[derive(serde::Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
enum Request {
    Load {
        name: String,
        files: Vec<std::path::PathBuf>,
        options: crate::SnapshotLoadOptsJson,
    },
    Get {
        name: String,
    },
    List,
    LookupSource {
        name: String,
    },
    ListSources {
        options: crate::SandboxListOpts,
    },
    CaptureSource {
        name: String,
        options: CaptureOptions,
    },
    Open {
        reference: String,
        reference_kind: Option<String>,
    },
    Head,
    Members,
    Member {
        name: String,
    },
    SetHead {
        name: String,
    },
    ClearHead,
    Capture {
        options: CaptureOptions,
    },
    Create {
        sandbox: u64,
        name: String,
        options: CaptureOptions,
    },
    Save {
        path: String,
        options: crate::SnapshotSaveOptsJson,
    },
    Verify,
    Remove {
        force: bool,
    },
    Spawn {
        name: String,
        options: Box<crate::restore::RestoreOptions>,
    },
}

#[derive(Default, serde::Deserialize)]
#[serde(default, deny_unknown_fields)]
struct CaptureOptions {
    name: Option<String>,
    destination: Option<String>,
    labels: HashMap<String, String>,
    full: bool,
    record_integrity: bool,
    guest_flush: Option<microsandbox::snapshot::GuestFlush>,
}

/// Objects become caller-owned only after the entire result reaches its output buffer.
/// Cancellation, serialization errors, and small buffers must not leak native receivers.
#[derive(Default)]
struct PendingObjects(Mutex<Vec<u64>>, Mutex<Vec<u64>>);

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl CaptureOptions {
    fn build(self) -> SnapshotCaptureOptions {
        let mut options = SnapshotCaptureOptions::default();
        if let Some(name) = self.name {
            options = options.name(name);
        }
        if let Some(destination) = self.destination {
            options = options.dest_dir(destination);
        }
        if self.full {
            options = options.full();
        }
        if self.record_integrity {
            options = options.record_integrity();
        }
        if let Some(flush) = self.guest_flush {
            options = options.guest_flush(flush);
        }
        for (key, value) in self.labels {
            options = options.label(key, value);
        }
        options
    }
}

impl PendingObjects {
    fn insert(&self, object: Object) -> Result<Value, FfiError> {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        let mut value = match &object {
            Object::Group(group) => json!({"name": group.name()}),
            Object::Source(source) => serde_json::from_str(&crate::sandbox_handle_json(source))
                .map_err(|e| FfiError::internal(e.to_string()))?,
            Object::Checkpoint(checkpoint) => snapshot_json(checkpoint),
        };
        let mut pending = self
            .0
            .lock()
            .map_err(|_| FfiError::internal("pending objects lock poisoned"))?;
        objects()
            .write()
            .map_err(|_| FfiError::internal("snapshot objects lock poisoned"))?
            .insert(id, object);
        pending.push(id);
        value["object_handle"] = json!(id);
        Ok(value)
    }

    fn sandbox(&self, sandbox: microsandbox::Sandbox) -> Result<Value, FfiError> {
        let mut value = json!({"name": sandbox.name(), "id": sandbox.id().to_string(), "backend_kind": sandbox.backend_kind().as_str()});
        let mut pending = self
            .1
            .lock()
            .map_err(|_| FfiError::internal("pending sandboxes lock poisoned"))?;
        let handle = crate::register(sandbox)?;
        pending.push(handle);
        value["handle"] = json!(handle);
        Ok(value)
    }

    fn publish(&self) {
        if let Ok(mut pending) = self.1.lock() {
            pending.clear();
        }
        if let Ok(mut pending) = self.0.lock() {
            pending.clear();
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Drop for PendingObjects {
    fn drop(&mut self) {
        if let Ok(pending) = self.1.get_mut() {
            for handle in pending.drain(..) {
                let _ = crate::remove(handle);
            }
        }
        if let (Ok(pending), Ok(mut objects)) = (self.0.get_mut(), objects().write()) {
            for id in pending.drain(..) {
                objects.remove(&id);
            }
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn objects() -> &'static RwLock<HashMap<u64, Object>> {
    static OBJECTS: OnceLock<RwLock<HashMap<u64, Object>>> = OnceLock::new();
    OBJECTS.get_or_init(|| RwLock::new(HashMap::new()))
}

fn object(id: u64) -> Result<Object, FfiError> {
    objects()
        .read()
        .map_err(|_| FfiError::internal("snapshot objects lock poisoned"))?
        .get(&id)
        .cloned()
        .ok_or_else(|| FfiError::invalid_handle(id))
}

fn group(id: u64) -> Result<Snapshot, FfiError> {
    match object(id)? {
        Object::Group(group) => Ok(group),
        _ => Err(FfiError::invalid_argument(
            "operation requires a snapshot group receiver",
        )),
    }
}

fn checkpoint(id: u64) -> Result<Checkpoint, FfiError> {
    match object(id)? {
        Object::Checkpoint(checkpoint) => Ok(*checkpoint),
        _ => Err(FfiError::invalid_argument(
            "operation requires a checkpoint receiver",
        )),
    }
}

async fn dispatch(id: u64, request: Request, pending: &PendingObjects) -> Result<Value, FfiError> {
    match request {
        Request::Load {
            name,
            files,
            options,
        } => {
            let result = Snapshot::load_with(name, &files, |_| microsandbox::LoadOpts {
                dest: options.dest,
                base: options.base,
                group: options.group,
                set_head: options.set_head,
            })
            .await?;
            Ok(json!({
                "operation_id": result.operation_id,
                "snapshot": pending.insert(Object::Group(result.snapshot))?,
                "checkpoints": result.checkpoints.iter().map(snapshot_handle_json).collect::<Vec<_>>(),
                "added": result.added, "reused": result.reused,
                "head_update": result.head_update, "warnings": result.warnings,
            }))
        }
        Request::LookupSource { name } => pending.insert(Object::Source(Arc::new(
            microsandbox::Sandbox::get(&name).await?,
        ))),
        Request::ListSources { options } => {
            let page = microsandbox::Sandbox::list_with(|mut list| {
                if let Some(limit) = options.limit {
                    list = list.limit(limit);
                }
                if let Some(cursor) = options.cursor {
                    list = list.cursor(cursor);
                }
                list.labels(options.labels)
            })
            .await?;
            let sources = page
                .sandboxes
                .into_iter()
                .map(|source| pending.insert(Object::Source(Arc::new(source))))
                .collect::<Result<Vec<_>, _>>()?;
            Ok(json!({"sandboxes": sources, "next_cursor": page.next_cursor}))
        }
        Request::CaptureSource { name, options } => {
            let Object::Source(source) = object(id)? else {
                return Err(FfiError::invalid_argument(
                    "capture requires a sandbox receiver",
                ));
            };
            let result = source.snapshot_with(&name, |_| options.build()).await?;
            Ok(
                json!({"snapshot": pending.insert(Object::Group(result.snapshot))?,
                "checkpoint": pending.insert(Object::Checkpoint(Box::new(result.checkpoint)))?, "head_update":result.head_update}),
            )
        }
        Request::Open {
            reference,
            reference_kind,
        } => {
            let reference = crate::parse_snapshot_reference(
                reference,
                reference_kind.as_deref().unwrap_or(""),
            )?;
            pending.insert(Object::Checkpoint(Box::new(
                Checkpoint::open_ref(reference).await?,
            )))
        }
        Request::Get { name } => pending.insert(Object::Group(Snapshot::get(name).await?)),
        Request::List => Snapshot::list()
            .await?
            .into_iter()
            .map(|group| pending.insert(Object::Group(group)))
            .collect::<Result<Vec<_>, _>>()
            .map(Value::Array),
        Request::Head => match group(id)?.head().await? {
            Some(member) => pending.insert(Object::Checkpoint(Box::new(member))),
            None => Ok(Value::Null),
        },
        Request::Members => Ok(Value::Array(
            group(id)?
                .checkpoints()
                .await?
                .iter()
                .map(snapshot_handle_json)
                .collect(),
        )),
        Request::Member { name } => pending.insert(Object::Checkpoint(Box::new(
            group(id)?.get_checkpoint(name).await?,
        ))),
        Request::SetHead { name } => serde_json::to_value(group(id)?.set_head(name).await?)
            .map_err(|e| FfiError::internal(e.to_string())),
        Request::ClearHead => serde_json::to_value(group(id)?.clear_head().await?)
            .map_err(|e| FfiError::internal(e.to_string())),
        Request::Capture { options } => {
            let result = group(id)?.checkpoint_with(|_| options.build()).await?;
            Ok(
                json!({"checkpoint": pending.insert(Object::Checkpoint(Box::new(result.checkpoint)))?, "head_update": result.head_update}),
            )
        }
        Request::Create {
            sandbox,
            name,
            options,
        } => {
            let result = get(sandbox)?
                .snapshot_with(&name, |_| options.build())
                .await?;
            Ok(
                json!({"snapshot": pending.insert(Object::Group(result.snapshot))?,
                "checkpoint": pending.insert(Object::Checkpoint(Box::new(result.checkpoint)))?, "head_update": result.head_update}),
            )
        }
        Request::Save { path, options } => {
            checkpoint(id)?
                .save_to(
                    std::path::Path::new(&path),
                    microsandbox::snapshot::SaveOpts {
                        since: options.since,
                        last_layers: options.last_layers,
                        with_parents: options.with_parents,
                        with_image: options.with_image,
                        plain_tar: options.plain_tar,
                    },
                )
                .await?;
            Ok(json!({"ok": true}))
        }
        Request::Remove { force } => {
            let result = checkpoint(id)?
                .remove_with(|options| if force { options.force() } else { options })
                .await?;
            serde_json::to_value(result).map_err(|error| FfiError::internal(error.to_string()))
        }
        Request::Verify => match object(id)? {
            Object::Group(group) => serde_json::to_value(group.verify().await?)
                .map_err(|error| FfiError::internal(error.to_string())),
            Object::Checkpoint(checkpoint) => Ok(verify_report_json(checkpoint.verify().await?)),
            Object::Source(_) => Err(FfiError::invalid_argument(
                "verification requires a group or checkpoint receiver",
            )),
        },
        Request::Spawn { name, options } => {
            let builder = crate::restore::builder(name, &options)?;
            let checkpoint = match object(id)? {
                Object::Checkpoint(checkpoint) => *checkpoint,
                Object::Source(_) => {
                    return Err(FfiError::invalid_argument(
                        "spawn requires a group or checkpoint receiver",
                    ));
                }
                Object::Group(group) => group.head().await?.ok_or_else(|| {
                    FfiError::invalid_argument("snapshot group has no selected head")
                })?,
            };
            let sandbox = if let Some(progress) = options.creation_progress {
                crate::creation_progress::spawn_checkpoint(checkpoint, builder, progress).await?
            } else {
                checkpoint.spawn_sandbox_with(|_| builder).await?
            };
            pending.sandbox(sandbox)
        }
    }
}

/// Execute only the explicitly tagged operation against a retained receiver.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msb_snapshot_object(
    cancel_id: u64,
    handle: u64,
    request: *const c_char,
    buf: *mut c_uchar,
    buf_len: usize,
) -> *mut c_char {
    let pending = Arc::new(PendingObjects::default());
    let operation_pending = pending.clone();
    let result = run_c(cancel_id, buf, buf_len, || {
        let request = serde_json::from_str::<Request>(&unsafe { cstr(request) }?)
            .map_err(|e| FfiError::invalid_argument(format!("invalid snapshot operation: {e}")))?;
        Ok(Box::pin(async move {
            Ok(dispatch(handle, request, &operation_pending)
                .await?
                .to_string())
        }))
    });
    if result.is_null() {
        pending.publish();
    }
    result
}

/// Release a receiver, without deleting its persistent artifact or group.
#[unsafe(no_mangle)]
pub extern "C" fn msb_snapshot_object_close(handle: u64) {
    if let Ok(mut objects) = objects().write() {
        objects.remove(&handle);
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    async fn empty_group(home: &std::path::Path) -> microsandbox::backend::LocalBackend {
        let local = microsandbox::backend::LocalBackend::builder()
            .home(home)
            .build()
            .await
            .unwrap();
        let group = local.snapshots_dir().join("history");
        std::fs::create_dir_all(&group).unwrap();
        std::fs::write(
            group.join("group.json"),
            r#"{"schema":"microsandbox.snapshot-group/1","head":null}"#,
        )
        .unwrap();
        local
    }

    #[tokio::test]
    async fn unpublished_receivers_are_released_and_published_receivers_keep_their_backend() {
        let a = tempfile::tempdir().unwrap();
        let b = tempfile::tempdir().unwrap();
        let first = empty_group(a.path()).await;
        let second = empty_group(b.path()).await;
        let selected =
            microsandbox::with_backend(first, async { Snapshot::get("history").await.unwrap() })
                .await;
        let abandoned;
        {
            let pending = PendingObjects::default();
            abandoned = pending
                .insert(Object::Group(selected.clone()))
                .unwrap_or_else(|error| panic!("{}", error.message))["object_handle"]
                .as_u64()
                .unwrap();
            assert!(object(abandoned).is_ok());
            // The call failed before handing its JSON result to Go (for example a
            // too-small output buffer). No finalizer can own this receiver yet.
        }
        assert!(object(abandoned).is_err());
        let published;
        {
            let pending = PendingObjects::default();
            published = pending
                .insert(Object::Group(selected))
                .unwrap_or_else(|error| panic!("{}", error.message))["object_handle"]
                .as_u64()
                .unwrap();
            pending.publish();
        }
        let receiver = group(published).unwrap_or_else(|error| panic!("{}", error.message));
        msb_snapshot_object_close(published);
        assert!(object(published).is_err());
        // Closing another Go reference cannot invalidate an operation that already
        // cloned its receiver. Nor may an ambient backend switch retarget it.
        std::fs::remove_dir_all(a.path().join("snapshots/history")).unwrap();
        microsandbox::with_backend(second, async {
            assert!(
                Snapshot::get("history")
                    .await
                    .unwrap()
                    .head()
                    .await
                    .unwrap()
                    .is_none()
            );
            assert!(receiver.head().await.is_err());
        })
        .await;
    }

    #[test]
    fn operation_and_capture_options_refuse_unknown_fields() {
        for json in [
            r#"{"op":"capture","options":{"sandbox":"other"}}"#,
            r#"{"op":"get","name":"history","backend":"other"}"#,
            r#"{"op":"capture","options":{"guest_flush":"maybe"}}"#,
        ] {
            assert!(serde_json::from_str::<Request>(json).is_err(), "{json}");
        }
    }
}
