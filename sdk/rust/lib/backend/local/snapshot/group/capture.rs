//! Ownership of an unpublished group's first capture, including cancellation cleanup.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use microsandbox_utils::process_lock;

use super::super::source::Source;
use super::super::writer::WriterLease;
use super::{MicrosandboxError, MicrosandboxResult};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const OWNER_FILENAME: &str = ".capture-owner";

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Clones retain name ownership until every capture/publication worker has finished.
#[derive(Clone)]
pub(crate) struct CaptureReservation {
    inner: Arc<Reservation>,
}

struct Reservation {
    directory: PathBuf,
    token: String,
    writer: WriterLease,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl CaptureReservation {
    pub(crate) fn directory(&self) -> &Path {
        &self.inner.directory
    }

    pub(crate) fn writer(&self) -> WriterLease {
        self.inner.writer.clone()
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Drop for Reservation {
    fn drop(&mut self) {
        // Keep external writer ownership until rollback is complete. Cleanup only
        // recognizes this attempt's token and never removes a published checkpoint.
        if let Err(error) = retire_empty(&self.directory, &self.token) {
            tracing::warn!(%error, path = %self.directory.display(), "initial capture cleanup remains recoverable");
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(super) fn claim(
    root: &Path,
    name: &str,
    source: Source,
) -> MicrosandboxResult<CaptureReservation> {
    super::validate_group_name(name)?;
    fs::create_dir_all(root)?;
    super::require_directory(root)?;
    let creation = process_lock::open_lock_file(&root.join(".groups.lock"))?;
    process_lock::lock_exclusive(&creation)?;
    let directory = root.canonicalize()?.join(name);
    let writer = WriterLease::try_reserve(&directory)?
        .ok_or_else(|| MicrosandboxError::SnapshotAlreadyExists(name.into()))?;
    if super::path_exists(&directory)? {
        super::require_directory(&directory)?;
        // A terminated creator may have left an unpublished reservation. Recover
        // only a marked attempt while owning its stable writer key, never by name alone.
        if super::path_exists(&directory.join(OWNER_FILENAME))? {
            let token: String = serde_json::from_slice(&super::read_regular(
                &directory.join(OWNER_FILENAME),
                128,
            )?)?;
            retire_empty(&directory, &token)?;
        }
        if super::path_exists(&directory)? {
            return Err(MicrosandboxError::SnapshotAlreadyExists(name.into()));
        }
    }
    let staged = tempfile::Builder::new()
        .prefix(".group-new-")
        .tempdir_in(root)?;
    let token = format!("{:032x}", rand::random::<u128>());
    super::write_json(
        staged.path(),
        super::CREATING_FILENAME,
        &super::CREATING_SCHEMA,
    )?;
    super::write_json(
        staged.path(),
        super::super::source::SOURCE_FILENAME,
        &source,
    )?;
    super::write_json(staged.path(), OWNER_FILENAME, &token)?;
    process_lock::create_new_lock_file(&staged.path().join(".group.lock"))?.sync_all()?;
    super::sync_directory(staged.path())?;
    fs::rename(staged.path(), &directory)?;
    let reservation = CaptureReservation {
        inner: Arc::new(Reservation {
            directory,
            token,
            writer,
        }),
    };
    // Construct rollback ownership before this fallible flush. Cancellation or a
    // flush error must not strand an empty, apparently successful history.
    super::sync_directory(root)?;
    Ok(reservation)
}

fn retire_empty(directory: &Path, token: &str) -> MicrosandboxResult<()> {
    if !super::path_exists(directory)? {
        return Ok(());
    }
    if !super::path_exists(&directory.join(OWNER_FILENAME))? {
        return Ok(());
    }
    let current: String =
        serde_json::from_slice(&super::read_regular(&directory.join(OWNER_FILENAME), 128)?)?;
    if current != token {
        return Ok(());
    }
    let lock = process_lock::open_existing_lock_file(&directory.join(".group.lock"))?;
    if !process_lock::try_lock_exclusive(&lock)? {
        return Err(super::integrity(
            "capture reservation is still in use; cleanup will retry".into(),
        ));
    }
    super::transaction::recover(directory)?;
    if super::path_exists(&directory.join(super::GROUP_FILENAME))?
        || !super::read_members(directory, true)?.is_empty()
    {
        // Published state wins, including a successful capture followed by source
        // recovery failure. Never undo that publication while unwinding an error.
        fs::remove_file(directory.join(OWNER_FILENAME))?;
        super::sync_directory(directory)?;
        return Ok(());
    }
    if !super::is_creating(directory)? {
        return Ok(());
    }
    let parent = directory
        .parent()
        .ok_or_else(|| super::integrity("capture group has no parent".into()))?;
    let retired = parent.join(format!(".capture-aborted-{:032x}", rand::random::<u128>()));
    fs::rename(directory, &retired)?;
    super::sync_directory(parent)?;
    drop(lock);
    fs::remove_dir_all(retired)?;
    super::sync_directory(parent)?;
    Ok(())
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::super::tests::{descriptor, id, stage};
    use super::*;

    async fn source(home: &Path) -> Source {
        let local = crate::test_support::local_backend_builder(home)
            .build()
            .await
            .unwrap();
        Source::capture(local.db().await.unwrap().write(), 1, "source")
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn reservation_is_hidden_and_last_worker_drop_releases_its_name() {
        let root = tempfile::tempdir().unwrap();
        let source = source(&root.path().join("home")).await;
        let directory = root.path().join("snapshots");
        let reservation = claim(&directory, "history", source.clone()).unwrap();
        let worker = reservation.clone();
        assert!(
            !reservation
                .directory()
                .join(super::super::GROUP_FILENAME)
                .exists()
        );
        assert!(
            WriterLease::try_acquire(reservation.directory())
                .unwrap()
                .is_none()
        );
        drop(reservation);
        assert!(directory.join("history").is_dir());
        assert!(claim(&directory, "history", source.clone()).is_err());
        // An unrelated group need not wait for this capture to finish.
        drop(claim(&directory, "other", source.clone()).unwrap());
        drop(worker);
        assert!(!directory.join("history").exists());
        drop(claim(&directory, "history", source).unwrap());
        assert!(!directory.join("history").exists());
    }

    #[tokio::test]
    async fn published_checkpoint_survives_reservation_error_cleanup() {
        let root = tempfile::tempdir().unwrap();
        let source = source(&root.path().join("home")).await;
        let reservation = claim(root.path(), "history", source).unwrap();
        let directory = reservation.directory().to_path_buf();
        let staged = stage(root.path(), &[descriptor(1, None)]);
        let update = super::super::publish_admitted(
            &directory,
            staged.path(),
            &BTreeMap::new(),
            &id(1),
            reservation.writer(),
        )
        .await
        .unwrap();
        assert_eq!(update.head, Some(id(1).to_string()));
        // Same drop path runs when publication succeeded but source recovery failed.
        drop(reservation);
        assert!(directory.join(id(1).as_str()).is_dir());
        assert_eq!(
            super::super::read_group(&directory).unwrap().head,
            Some(id(1).to_string())
        );
        assert!(!directory.join(OWNER_FILENAME).exists());
    }

    #[tokio::test]
    async fn cleanup_never_deletes_a_different_attempt_at_the_same_name() {
        let root = tempfile::tempdir().unwrap();
        let source = source(&root.path().join("home")).await;
        let reservation = claim(root.path(), "history", source).unwrap();
        let directory = reservation.directory().to_path_buf();
        super::super::write_json(&directory, OWNER_FILENAME, &"another-owner").unwrap();
        drop(reservation);
        assert!(directory.exists());
        assert_eq!(
            serde_json::from_slice::<String>(&fs::read(directory.join(OWNER_FILENAME)).unwrap())
                .unwrap(),
            "another-owner"
        );
    }

    #[test]
    fn abandoned_empty_reservation_is_recovered_before_retry() {
        // Model a terminated creator after all of its descriptors have closed.
        // Concurrent subprocess tests can briefly inherit its lock across fork,
        // so run this immediate-reclaim assertion in its own process.
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "backend::local::snapshot::group::capture::tests::abandoned_reservation_worker",
                "--ignored",
                "--nocapture",
            ])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[tokio::test]
    #[ignore = "subprocess-only immediate reservation recovery"]
    async fn abandoned_reservation_worker() {
        let root = tempfile::tempdir().unwrap();
        let source = source(&root.path().join("home")).await;
        let reservation = claim(root.path(), "history", source.clone()).unwrap();
        let directory = reservation.directory().to_path_buf();
        let records = [
            OWNER_FILENAME,
            super::super::CREATING_FILENAME,
            super::super::super::source::SOURCE_FILENAME,
        ]
        .map(|name| (name, fs::read(directory.join(name)).unwrap()));
        drop(reservation);
        // Reconstruct the on-disk state left by a killed creator after the OS
        // releases its writer lock. No live lease is silently bypassed.
        fs::create_dir(&directory).unwrap();
        for (name, bytes) in records {
            fs::write(directory.join(name), bytes).unwrap();
        }
        process_lock::create_new_lock_file(&directory.join(".group.lock")).unwrap();
        let retried = claim(root.path(), "history", source).unwrap();
        assert!(
            !retried
                .directory()
                .join(super::super::GROUP_FILENAME)
                .exists()
        );
        drop(retried);
        assert!(!directory.exists());
    }

    #[test]
    fn cancelled_creation_waiter_does_not_leave_a_group() {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .max_blocking_threads(1)
            .build()
            .unwrap()
            .block_on(async {
                let root = tempfile::tempdir().unwrap();
                let source = source(&root.path().join("home")).await;
                let directory = root.path().join("snapshots");
                let (started, ready) = tokio::sync::oneshot::channel();
                let (release, wait) = std::sync::mpsc::channel();
                let blocker = tokio::task::spawn_blocking(move || {
                    started.send(()).unwrap();
                    wait.recv_timeout(std::time::Duration::from_secs(5))
                        .unwrap();
                });
                ready.await.unwrap();
                let mut creation = Box::pin(super::super::ensure_new_capture(
                    &directory,
                    "cancelled",
                    source,
                ));
                assert!(futures::poll!(creation.as_mut()).is_pending());
                drop(creation);
                release.send(()).unwrap();
                blocker.await.unwrap();
                tokio::task::spawn_blocking(|| {}).await.unwrap();
                assert!(!directory.join("cancelled").exists());
            });
    }
}
