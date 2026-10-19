//! Group-oriented history and capture APIs. Immutable artifacts are `Checkpoint` values.

use std::fmt;
use std::path::PathBuf;
use std::sync::Arc;

use crate::backend::Backend;
use crate::{MicrosandboxError, MicrosandboxResult, Sandbox};

use super::{
    Checkpoint, GuestFlush, HeadUpdate, LoadOpts, SnapshotConfig, SnapshotHandle, SnapshotId,
    SnapshotReference,
};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A named checkpoint history. Opening a group does not freeze its mutable head.
#[derive(Clone)]
pub struct Snapshot {
    pub(crate) backend: Arc<dyn Backend>,
    pub(crate) name: String,
    pub(crate) reference: SnapshotReference,
}

/// The newly created group and the exact checkpoint produced by its initial capture.
#[derive(Debug, Clone)]
pub struct SnapshotCreateResult {
    /// Created history, bound to the source sandbox's stable identity.
    pub snapshot: Snapshot,
    /// Initial immutable member, even if another capture has since advanced the head.
    pub checkpoint: Checkpoint,
    /// Head outcome recorded by this capture operation.
    pub head_update: HeadUpdate,
}

/// One capture's artifact and head outcome; no second mutable-head lookup is performed.
#[derive(Debug, Clone)]
pub struct CheckpointCaptureResult {
    /// The exact captured member.
    pub checkpoint: Checkpoint,
    /// Whether and why this operation advanced the head.
    pub head_update: HeadUpdate,
}

/// The committed result of one atomic archive batch, independent of subsequent head changes.
#[derive(Debug, Clone)]
pub struct SnapshotImportResult {
    /// Identifier for this import attempt, also carried by structured import errors.
    pub operation_id: String,
    /// Destination history, including when it has no selected head.
    pub snapshot: Snapshot,
    /// Every unique member supplied by the batch, including bundled dependencies, in ID order.
    pub checkpoints: Vec<SnapshotHandle>,
    /// Members newly installed by this operation, in ID order.
    pub added: Vec<SnapshotId>,
    /// Identical members already installed at commit time, in ID order.
    pub reused: Vec<SnapshotId>,
    /// Head decision made by this operation, including ambiguous headless imports.
    pub head_update: HeadUpdate,
    /// Cleanup still needed after a confirmed successful commit.
    pub warnings: Vec<String>,
}

/// Capture controls shared by initial group creation and subsequent checkpoint capture.
/// The receiver selects the source; options cannot silently rebind an existing group.
#[derive(Debug, Clone)]
pub struct SnapshotCaptureOptions {
    pub(crate) name: String,
    pub(crate) destination: Option<PathBuf>,
    pub(crate) labels: Vec<(String, String)>,
    pub(crate) full: bool,
    pub(crate) record_integrity: bool,
    pub(crate) guest_flush: GuestFlush,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl Snapshot {
    /// Inspect group metadata and the exact saved source association without capturing.
    pub async fn inspect(&self) -> MicrosandboxResult<super::SnapshotGroupInfo> {
        self.backend
            .snapshots()
            .inspect_group(&self.reference)
            .await
    }

    /// Remove this whole history, refusing surviving external dependents and active readers.
    pub async fn remove(&self) -> MicrosandboxResult<super::SnapshotRemoveResult> {
        self.backend.snapshots().remove_group(&self.reference).await
    }

    /// Verify every member, including a headless history. Shared physical payloads are hashed
    /// once per algorithm. Corruption returns an error containing the complete group report.
    pub async fn verify(&self) -> MicrosandboxResult<super::SnapshotGroupVerifyReport> {
        self.backend.snapshots().verify_group(&self.reference).await
    }

    /// Reopen a named history through the active backend, including a headless history.
    pub async fn get(name: impl AsRef<str>) -> MicrosandboxResult<Self> {
        let backend = crate::backend::default_backend();
        backend
            .snapshots()
            .get_group(backend.clone(), name.as_ref())
            .await
    }

    /// List installed groups. Standalone artifacts are not invented into groups.
    pub async fn list() -> MicrosandboxResult<Vec<Self>> {
        let backend = crate::backend::default_backend();
        backend.snapshots().list_groups(backend.clone()).await
    }

    /// Atomically import an archive set into a named history, resolving dependencies together.
    pub async fn load(
        group: impl AsRef<str>,
        files: &[PathBuf],
    ) -> MicrosandboxResult<SnapshotImportResult> {
        Self::load_with(group, files, |options| options).await
    }

    /// Configure archive dependencies, destination, and head policy for one atomic import.
    pub async fn load_with(
        group: impl AsRef<str>,
        files: &[PathBuf],
        configure: impl FnOnce(LoadOpts) -> LoadOpts,
    ) -> MicrosandboxResult<SnapshotImportResult> {
        let backend = crate::backend::default_backend();
        backend
            .snapshots()
            .load_group(
                backend.clone(),
                group.as_ref(),
                files,
                configure(LoadOpts::default()),
            )
            .await
    }

    /// Local history name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Read the selected checkpoint once. An explicitly cleared head returns `None`.
    pub async fn head(&self) -> MicrosandboxResult<Option<Checkpoint>> {
        self.backend
            .snapshots()
            .read_head(self.backend.clone(), &self.reference)
            .await
    }

    /// Select one existing member. Selecting the current head is an explicit no-op.
    pub async fn set_head(&self, member: impl AsRef<str>) -> MicrosandboxResult<HeadUpdate> {
        self.backend
            .snapshots()
            .change_head(&self.reference, Some(member.as_ref()))
            .await
    }

    /// Clear head selection while preserving all members. Clearing again is a no-op.
    pub async fn clear_head(&self) -> MicrosandboxResult<HeadUpdate> {
        self.backend
            .snapshots()
            .change_head(&self.reference, None)
            .await
    }

    /// List immutable members in stable ID order.
    pub async fn checkpoints(&self) -> MicrosandboxResult<Vec<SnapshotHandle>> {
        self.backend
            .snapshots()
            .group_members(self.backend.clone(), &self.reference)
            .await
    }

    /// Open one member by its group-local name or stable ID, without changing the head.
    pub async fn get_checkpoint(&self, member: impl AsRef<str>) -> MicrosandboxResult<Checkpoint> {
        self.backend
            .snapshots()
            .get_checkpoint(self.backend.clone(), &self.reference, member.as_ref())
            .await
    }

    /// Capture the bound source using a generated member name and default disk-only policy.
    pub async fn checkpoint(&self) -> MicrosandboxResult<CheckpointCaptureResult> {
        self.checkpoint_with(|options| options).await
    }

    /// Capture the bound source. Imported and orphaned groups refuse capture before guest work.
    pub async fn checkpoint_with(
        &self,
        configure: impl FnOnce(SnapshotCaptureOptions) -> SnapshotCaptureOptions,
    ) -> MicrosandboxResult<CheckpointCaptureResult> {
        let options = configure(SnapshotCaptureOptions::default());
        // Keep a non-default store attached to the receiver across later cwd changes.
        let destination = match &self.reference {
            SnapshotReference::Path(path) => std::path::Path::new(path).parent().map(PathBuf::from),
            _ => None,
        };
        if options.destination.is_some() {
            return Err(MicrosandboxError::InvalidConfig(
                "an existing group's capture destination is fixed by the receiver".into(),
            ));
        }
        let mut config = options.into_config(self.name.clone(), String::new());
        config.dest_dir = destination;
        let checkpoint = self
            .backend
            .snapshots()
            .checkpoint(self.backend.clone(), config)
            .await?;
        let head_update = captured_head(&checkpoint)?;
        Ok(CheckpointCaptureResult {
            checkpoint,
            head_update,
        })
    }

    /// Spawn a persistent sandbox from the head selected at the start of this call.
    pub async fn spawn_sandbox(&self) -> MicrosandboxResult<Sandbox> {
        self.spawn_sandbox_with(|options| options).await
    }

    /// Configure the destination while keeping source selection on this group receiver.
    pub async fn spawn_sandbox_with(
        &self,
        configure: impl FnOnce(crate::sandbox::RestoreBuilder) -> crate::sandbox::RestoreBuilder,
    ) -> MicrosandboxResult<Sandbox> {
        let checkpoint = self.head().await?.ok_or_else(|| {
            MicrosandboxError::InvalidConfig(format!(
                "snapshot group '{}' has no selected head",
                self.name
            ))
        })?;
        checkpoint.spawn_sandbox_with(configure).await
    }

    /// Spawn the selected head with default destination options and progress.
    #[cfg(feature = "local")]
    pub async fn spawn_sandbox_with_progress(
        &self,
    ) -> MicrosandboxResult<(
        crate::CreationProgressHandle,
        tokio::task::JoinHandle<MicrosandboxResult<Sandbox>>,
    )> {
        self.spawn_sandbox_with_progress_with(|options| options)
            .await
    }

    /// Select the head once and report preparation and activation progress for that member.
    #[cfg(feature = "local")]
    pub async fn spawn_sandbox_with_progress_with(
        &self,
        configure: impl FnOnce(crate::sandbox::RestoreBuilder) -> crate::sandbox::RestoreBuilder,
    ) -> MicrosandboxResult<(
        crate::CreationProgressHandle,
        tokio::task::JoinHandle<MicrosandboxResult<Sandbox>>,
    )> {
        let checkpoint = self.head().await?.ok_or_else(|| {
            MicrosandboxError::InvalidConfig(format!(
                "snapshot group '{}' has no selected head",
                self.name
            ))
        })?;
        checkpoint.spawn_sandbox_with_progress_with(configure).await
    }

    /// Retained read/select wrapper for the released `group[:member]` syntax.
    #[deprecated(note = "use Snapshot::get(group), then head() or set_head(member)")]
    pub async fn group_head(selector: &str) -> MicrosandboxResult<HeadUpdate> {
        Checkpoint::group_head(selector).await
    }

    pub(crate) async fn create_for(
        backend: Arc<dyn Backend>,
        source: &str,
        source_id: crate::sandbox::SandboxId,
        name: &str,
        options: SnapshotCaptureOptions,
    ) -> MicrosandboxResult<SnapshotCreateResult> {
        let config = options.into_config(name.into(), source.into());
        let checkpoint = backend
            .snapshots()
            .create_group(backend.clone(), config, source_id)
            .await?;
        let head_update = captured_head(&checkpoint)?;
        let reference = match checkpoint.reference() {
            SnapshotReference::Path(path) => SnapshotReference::Path(
                std::path::Path::new(&path)
                    .parent()
                    .ok_or_else(|| {
                        MicrosandboxError::InvalidConfig(
                            "captured checkpoint has no group directory".into(),
                        )
                    })?
                    .to_string_lossy()
                    .into_owned(),
            ),
            _ => SnapshotReference::Auto(name.into()),
        };
        let snapshot = Self {
            backend,
            name: name.into(),
            reference,
        };
        Ok(SnapshotCreateResult {
            snapshot,
            checkpoint,
            head_update,
        })
    }
}

impl SnapshotCaptureOptions {
    /// Choose the first member's local name. Omit it for a generated name.
    pub fn initial_checkpoint(self, name: impl Into<String>) -> Self {
        self.name(name)
    }
    /// Choose a subsequent member's local name.
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = name.into();
        self
    }
    /// Capture full execution state rather than disk only.
    pub fn full(mut self) -> Self {
        self.full = true;
        self
    }
    /// Record persistent payload integrity evidence.
    pub fn record_integrity(mut self) -> Self {
        self.record_integrity = true;
        self
    }
    /// Choose guest writeback behavior.
    pub fn guest_flush(mut self, policy: GuestFlush) -> Self {
        self.guest_flush = policy;
        self
    }
    /// Add a label to the captured member.
    pub fn label(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.labels.push((key.into(), value.into()));
        self
    }
    /// Select the store root for a newly created group.
    pub fn dest_dir(mut self, path: impl Into<PathBuf>) -> Self {
        self.destination = Some(path.into());
        self
    }

    fn into_config(self, group: String, source_sandbox: String) -> SnapshotConfig {
        SnapshotConfig {
            name: self.name,
            group: Some(group),
            source_sandbox,
            dest_dir: self.destination,
            labels: self.labels,
            full: self.full,
            record_integrity: self.record_integrity,
            guest_flush: self.guest_flush,
            force: false,
        }
    }
}

impl Checkpoint {
    /// Spawn a persistent sandbox from this exact immutable member on its owning backend.
    pub async fn spawn_sandbox(&self) -> MicrosandboxResult<Sandbox> {
        self.spawn_sandbox_with(|options| options).await
    }

    /// Configure a new destination without resolving the group's mutable head again.
    pub async fn spawn_sandbox_with(
        &self,
        configure: impl FnOnce(crate::sandbox::RestoreBuilder) -> crate::sandbox::RestoreBuilder,
    ) -> MicrosandboxResult<Sandbox> {
        let builder = self.spawn_builder(configure);
        crate::backend::with_backend(self.backend.clone(), builder.restore()).await
    }

    /// Spawn this member with default destination options and progress.
    #[cfg(feature = "local")]
    pub async fn spawn_sandbox_with_progress(
        &self,
    ) -> MicrosandboxResult<(
        crate::CreationProgressHandle,
        tokio::task::JoinHandle<MicrosandboxResult<Sandbox>>,
    )> {
        self.spawn_sandbox_with_progress_with(|options| options)
            .await
    }

    /// Spawn this member with preparation and activation progress on its owning backend.
    #[cfg(feature = "local")]
    pub async fn spawn_sandbox_with_progress_with(
        &self,
        configure: impl FnOnce(crate::sandbox::RestoreBuilder) -> crate::sandbox::RestoreBuilder,
    ) -> MicrosandboxResult<(
        crate::CreationProgressHandle,
        tokio::task::JoinHandle<MicrosandboxResult<Sandbox>>,
    )> {
        let builder = self.spawn_builder(configure);
        crate::backend::with_backend(self.backend.clone(), async move {
            builder.restore_with_progress()
        })
        .await
    }

    fn spawn_builder(
        &self,
        configure: impl FnOnce(crate::sandbox::RestoreBuilder) -> crate::sandbox::RestoreBuilder,
    ) -> crate::sandbox::RestoreBuilder {
        let mut builder = configure(Sandbox::restore_ref(self.reference()));
        // A callback can return a completely different builder. The receiver still owns
        // source selection; only destination choices may be taken from that builder.
        builder.inner = builder.inner.with_snapshot_reference(self.reference());
        if builder
            .inner
            .config
            .spec
            .name
            .as_deref()
            .is_none_or(str::is_empty)
        {
            // Keep generated names within the ordinary destination reservation path:
            // even an unlikely collision must refuse, never replace an existing sandbox.
            builder = builder.name(format!("msb-{:032x}", rand::random::<u128>()));
        }
        builder
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Default for SnapshotCaptureOptions {
    fn default() -> Self {
        Self {
            name: String::new(),
            destination: None,
            labels: Vec::new(),
            full: false,
            record_integrity: false,
            guest_flush: GuestFlush::Auto,
        }
    }
}

impl fmt::Debug for Snapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Snapshot")
            .field("name", &self.name)
            .field("reference", &self.reference)
            .finish_non_exhaustive()
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn captured_head(checkpoint: &Checkpoint) -> MicrosandboxResult<HeadUpdate> {
    checkpoint.head_update().cloned().ok_or_else(|| {
        MicrosandboxError::SnapshotIntegrity(
            "capture completed without an operation-specific head outcome".into(),
        )
    })
}
