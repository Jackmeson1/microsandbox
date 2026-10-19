//! Call-time import admission for language bindings that schedule Rust work later.

use std::path::PathBuf;
use std::sync::Arc;

use crate::backend::{Backend, default_backend};
use crate::{MicrosandboxError, MicrosandboxResult};

use super::{LoadOpts, SnapshotHandle, SnapshotImportResult};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Internal binding transport: own the selected backend and local path meanings before
/// releasing the language thread. This is neither persisted data nor a public import result.
#[doc(hidden)]
pub struct PreparedSnapshotImport {
    backend: Arc<dyn Backend>,
    files: Vec<PathBuf>,
    options: LoadOpts,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl PreparedSnapshotImport {
    pub fn new(files: Vec<PathBuf>, options: LoadOpts) -> MicrosandboxResult<Self> {
        Self::with_backend(default_backend(), files, options)
    }

    fn with_backend(
        backend: Arc<dyn Backend>,
        files: Vec<PathBuf>,
        options: LoadOpts,
    ) -> MicrosandboxResult<Self> {
        let request = Self {
            backend,
            files,
            options,
        };
        #[cfg(feature = "local")]
        let request = request.anchor_local()?;
        Ok(request)
    }

    #[cfg(feature = "local")]
    fn anchor_local(mut self) -> MicrosandboxResult<Self> {
        if self.backend.kind() == crate::backend::BackendKind::Local {
            self.files = self
                .files
                .into_iter()
                .map(std::path::absolute)
                .collect::<std::io::Result<_>>()?;
            self.options.dest = self.options.dest.map(std::path::absolute).transpose()?;
            self.options.base = self
                .options
                .base
                .map(crate::backend::local::snapshot::anchor_archive_selector)
                .transpose()?;
        }
        Ok(self)
    }

    pub async fn group(self, name: String) -> MicrosandboxResult<SnapshotImportResult> {
        #[cfg(feature = "local")]
        if let Some(local) = self.backend.as_local() {
            return crate::backend::local::snapshot::load_group_admitted(
                local,
                self.backend.clone(),
                &name,
                &self.files,
                self.options,
            )
            .await;
        }
        self.backend
            .snapshots()
            .load_group(self.backend.clone(), &name, &self.files, self.options)
            .await
    }

    pub async fn checkpoints(self) -> MicrosandboxResult<Vec<SnapshotHandle>> {
        #[cfg(feature = "local")]
        if let Some(local) = self.backend.as_local() {
            return crate::backend::local::snapshot::load_many_admitted(
                local,
                self.backend.clone(),
                &self.files,
                self.options,
            )
            .await;
        }
        self.backend
            .snapshots()
            .load_many(self.backend.clone(), &self.files, self.options)
            .await
    }

    pub async fn checkpoint(self) -> MicrosandboxResult<SnapshotHandle> {
        self.checkpoints().await?.into_iter().next().ok_or_else(|| {
            MicrosandboxError::Runtime("snapshot import returned no checkpoint".into())
        })
    }

    /// Preserve the old single-archive dispatch for backends that implement `load`
    /// without implementing the optional batch interface. An explicit base uses batch.
    pub async fn legacy_checkpoint(self) -> MicrosandboxResult<SnapshotHandle> {
        if self.options.base.is_some() {
            return self.checkpoint().await;
        }
        let path = self.files.first().ok_or_else(|| {
            MicrosandboxError::InvalidConfig("snapshot import requires an archive".into())
        })?;
        self.backend
            .snapshots()
            .load(self.backend.clone(), path, self.options.dest.as_deref())
            .await
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(all(test, feature = "local"))]
#[path = "import_tests.rs"]
mod tests;
