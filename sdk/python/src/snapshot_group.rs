//! Python group histories, with immutable members and operation-specific capture results.

use std::collections::HashMap;
use std::path::PathBuf;

use microsandbox::{Snapshot as RustGroup, SnapshotCaptureOptions};
use pyo3::prelude::*;
use pyo3::types::PyDict;

use crate::error::to_py_err;
use crate::snapshot::{PySnapshot, PySnapshotHandle, guest_flush_policy, head_update_to_py};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

#[pyclass(name = "SnapshotGroup")]
pub struct PySnapshotGroup {
    inner: RustGroup,
}

#[pyclass(name = "SnapshotCreateResult")]
pub struct PySnapshotCreateResult {
    inner: microsandbox::SnapshotCreateResult,
}

#[pyclass(name = "CheckpointCaptureResult")]
pub struct PyCheckpointCaptureResult {
    inner: microsandbox::CheckpointCaptureResult,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

#[pymethods]
impl PySnapshotGroup {
    #[staticmethod]
    fn get<'py>(py: Python<'py>, name: String) -> PyResult<Bound<'py, PyAny>> {
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            Ok(Self {
                inner: RustGroup::get(name).await.map_err(to_py_err)?,
            })
        })
    }

    #[staticmethod]
    fn list<'py>(py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            Ok(RustGroup::list()
                .await
                .map_err(to_py_err)?
                .into_iter()
                .map(|inner| Self { inner })
                .collect::<Vec<_>>())
        })
    }

    /// Spawn from the head selected by this operation, preserving the group's backend.
    #[pyo3(signature = (*, name = None, **kwargs))]
    fn spawn_sandbox<'py>(
        &self,
        py: Python<'py>,
        name: Option<String>,
        kwargs: Option<&Bound<'py, PyDict>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let builder = crate::helpers::restore_builder_from_reference(
            microsandbox::SnapshotReference::auto(""),
            name.unwrap_or_default(),
            kwargs,
        )?;
        let inner = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            Ok(crate::sandbox::PySandbox::from_rust(
                inner
                    .spawn_sandbox_with(|_| builder)
                    .await
                    .map_err(to_py_err)?,
            ))
        })
    }

    #[pyo3(signature = (*, name = None, **kwargs))]
    fn spawn_sandbox_with_progress<'py>(
        &self,
        py: Python<'py>,
        name: Option<String>,
        kwargs: Option<&Bound<'py, PyDict>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let builder = crate::helpers::restore_builder_from_reference(
            microsandbox::SnapshotReference::auto(""),
            name.unwrap_or_default(),
            kwargs,
        )?;
        let inner = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let (progress, task) = inner
                .spawn_sandbox_with_progress_with(|_| builder)
                .await
                .map_err(to_py_err)?;
            Ok(crate::sandbox::PyPullSession::new(progress, task))
        })
    }

    #[getter]
    fn name(&self) -> &str {
        self.inner.name()
    }

    fn head<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let group = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            Ok(group
                .head()
                .await
                .map_err(to_py_err)?
                .map(PySnapshot::from_rust))
        })
    }

    fn get_checkpoint<'py>(&self, py: Python<'py>, member: String) -> PyResult<Bound<'py, PyAny>> {
        let group = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            Ok(PySnapshot::from_rust(
                group.get_checkpoint(member).await.map_err(to_py_err)?,
            ))
        })
    }

    fn checkpoints<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let group = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            Ok(group
                .checkpoints()
                .await
                .map_err(to_py_err)?
                .into_iter()
                .map(PySnapshotHandle::from_rust)
                .collect::<Vec<_>>())
        })
    }

    fn set_head<'py>(&self, py: Python<'py>, member: String) -> PyResult<Bound<'py, PyAny>> {
        let group = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let update = group.set_head(member).await.map_err(to_py_err)?;
            Python::with_gil(|py| head_update_to_py(py, &update))
        })
    }

    fn clear_head<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let group = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let update = group.clear_head().await.map_err(to_py_err)?;
            Python::with_gil(|py| head_update_to_py(py, &update))
        })
    }

    #[pyo3(signature = (*, name=None, labels=None, full=false, record_integrity=false, guest_flush=None))]
    #[allow(clippy::too_many_arguments)]
    fn checkpoint<'py>(
        &self,
        py: Python<'py>,
        name: Option<String>,
        labels: Option<HashMap<String, String>>,
        full: bool,
        record_integrity: bool,
        guest_flush: Option<String>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let group = self.inner.clone();
        let options = capture_options(name, None, labels, full, record_integrity, guest_flush)?;
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            Ok(PyCheckpointCaptureResult {
                inner: group
                    .checkpoint_with(|_| options)
                    .await
                    .map_err(to_py_err)?,
            })
        })
    }
}

#[pymethods]
impl PySnapshotCreateResult {
    #[getter]
    fn snapshot(&self) -> PySnapshotGroup {
        PySnapshotGroup {
            inner: self.inner.snapshot.clone(),
        }
    }
    #[getter]
    fn checkpoint(&self) -> PySnapshot {
        PySnapshot::from_rust(self.inner.checkpoint.clone())
    }
    #[getter]
    fn head_update(&self, py: Python<'_>) -> PyResult<Py<PyDict>> {
        head_update_to_py(py, &self.inner.head_update)
    }
}

#[pymethods]
impl PyCheckpointCaptureResult {
    #[getter]
    fn checkpoint(&self) -> PySnapshot {
        PySnapshot::from_rust(self.inner.checkpoint.clone())
    }
    #[getter]
    fn head_update(&self, py: Python<'_>) -> PyResult<Py<PyDict>> {
        head_update_to_py(py, &self.inner.head_update)
    }
}

impl PySnapshotCreateResult {
    pub(crate) fn from_rust(inner: microsandbox::SnapshotCreateResult) -> Self {
        Self { inner }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(crate) fn capture_options(
    name: Option<String>,
    destination: Option<PathBuf>,
    labels: Option<HashMap<String, String>>,
    full: bool,
    record_integrity: bool,
    guest_flush: Option<String>,
) -> PyResult<SnapshotCaptureOptions> {
    let mut options =
        SnapshotCaptureOptions::default().guest_flush(guest_flush_policy(guest_flush)?);
    if let Some(name) = name {
        options = options.name(name);
    }
    if let Some(destination) = destination {
        options = options.dest_dir(destination);
    }
    if full {
        options = options.full();
    }
    if record_integrity {
        options = options.record_integrity();
    }
    for (key, value) in labels.unwrap_or_default() {
        options = options.label(key, value);
    }
    Ok(options)
}
