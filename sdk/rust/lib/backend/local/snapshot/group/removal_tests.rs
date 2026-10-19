//! Head selection, reader ownership, cancellation and crash recovery for member removal.

use std::fs;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use microsandbox_image::snapshot::DESCRIPTOR_FILENAME;
use microsandbox_image::storage_lease::StorageLease;
use sea_orm::EntityTrait;

use super::super as group;
use crate::backend::local::snapshot::{deletion, lease, store, writer::WriterLease};
use crate::db::entity::snapshot;
use crate::{HeadUpdateReason, test_support};
use group::tests::{add, id};

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[tokio::test]
async fn removal_never_selects_unrelated_or_cross_group_history() {
    for parent in [None, Some(99), Some(3)] {
        let root = tempfile::tempdir().unwrap();
        let directory = group::ensure(root.path(), Some("history")).await.unwrap();
        let other = group::ensure(root.path(), Some("other")).await.unwrap();
        add(&other, 3, None).await;
        add(&directory, 1, None).await;
        add(&directory, 2, parent).await;
        group::change_head(&directory, Some(id(2).as_str()))
            .await
            .unwrap();
        let path = directory.join(id(2).as_str());
        let pin = lease::deletion(&path).unwrap().unwrap();
        let removed = group::remove_member_leased(&path, pin)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(removed.head_update.reason, HeadUpdateReason::Cleared);
        assert!(removed.head_update.changed);
        assert_eq!(removed.head_update.head, None);
        assert_eq!(group::read_group(&directory).unwrap().head, None);
        assert!(directory.join(id(1).as_str()).is_dir());
        assert!(other.join(id(3).as_str()).is_dir());
        // Later selection cannot rewrite this operation's returned facts.
        group::change_head(&directory, Some(id(1).as_str()))
            .await
            .unwrap();
        assert_eq!(removed.head_update.head, None);
    }
}

#[tokio::test]
async fn non_head_removal_keeps_the_selected_head() {
    let root = tempfile::tempdir().unwrap();
    let directory = group::ensure(root.path(), Some("history")).await.unwrap();
    add(&directory, 1, None).await;
    add(&directory, 2, None).await;
    let before = group::read_group(&directory).unwrap().head;
    let path = directory.join(id(2).as_str());
    let pin = lease::deletion(&path).unwrap().unwrap();
    let removed = group::remove_member_leased(&path, pin)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(removed.head_update.reason, HeadUpdateReason::Unchanged);
    assert!(!removed.head_update.changed);
    assert_eq!(removed.head_update.head, before);
    assert_eq!(group::read_group(&directory).unwrap().head, before);
}

#[tokio::test]
async fn removal_refuses_target_readers_and_preserves_surviving_reader_identity() {
    let root = tempfile::tempdir().unwrap();
    let directory = group::ensure(root.path(), Some("history")).await.unwrap();
    add(&directory, 1, None).await;
    add(&directory, 2, Some(1)).await;
    let first = directory.join(id(1).as_str());
    let second = directory.join(id(2).as_str());
    let target_reader = lease::reader(&second).unwrap();
    let survivor_reader = lease::reader(&first).unwrap();
    let survivor_namespace = StorageLease::shared(&first).unwrap();
    assert!(
        group::remove_member(&second)
            .await
            .unwrap_err()
            .to_string()
            .contains("active operation")
    );
    assert_eq!(
        group::read_group(&directory).unwrap().head.as_deref(),
        Some(id(2).as_str())
    );
    drop(target_reader);
    // Concurrent process tests can briefly inherit locks during fork/exec. Wait for
    // release, but keep the actual deletion and preservation assertions strict.
    let deadline = Instant::now() + Duration::from_secs(3);
    let pin = loop {
        if let Some(pin) = lease::deletion(&second).unwrap() {
            break pin;
        }
        assert!(Instant::now() < deadline, "target reader did not release");
        tokio::time::sleep(Duration::from_millis(1)).await;
    };
    group::remove_member_leased(&second, pin).await.unwrap();
    assert!(!second.exists());
    assert!(first.join(DESCRIPTOR_FILENAME).exists());
    assert!(lease::deletion(&first).unwrap().is_none());
    drop(survivor_namespace);
    assert!(lease::deletion(&first).unwrap().is_none());
    drop(survivor_reader);
}

#[cfg(unix)]
#[tokio::test]
async fn failed_private_staging_changes_neither_head_nor_members() {
    let root = tempfile::tempdir().unwrap();
    let directory = group::ensure(root.path(), Some("history")).await.unwrap();
    add(&directory, 1, None).await;
    add(&directory, 2, Some(1)).await;
    let first = directory.join(id(1).as_str());
    let second = directory.join(id(2).as_str());
    // A source tree that cannot be staged must fail before publication, even though
    // head fallback was already calculated. Do not rewrite any immutable descriptor.
    std::os::unix::fs::symlink("absent", first.join("unacceptable-link")).unwrap();
    let before = fs::read(directory.join(group::GROUP_FILENAME)).unwrap();
    let error = group::remove_member(&second).await.unwrap_err();
    assert!(error.to_string().contains("regular files"), "{error}");
    assert_eq!(
        fs::read(directory.join(group::GROUP_FILENAME)).unwrap(),
        before
    );
    assert!(first.is_dir());
    assert!(second.is_dir());
    assert!(!directory.join(".snapshot-deletions").exists());
    assert!(!fs::read_dir(root.path()).unwrap().any(|entry| {
        entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".group-generation-")
    }));
}

#[tokio::test]
async fn cancelling_removal_keeps_worker_ownership_until_atomic_publication() {
    let root = tempfile::tempdir().unwrap();
    let directory = group::ensure(root.path(), Some("history")).await.unwrap();
    add(&directory, 1, None).await;
    add(&directory, 2, Some(1)).await;
    let second = directory.join(id(2).as_str());
    let pin = lease::deletion(&second).unwrap().unwrap();
    let lock = group::lock_group(&directory).unwrap();
    let worker_path = second.clone();
    let (started, ready) = tokio::sync::oneshot::channel();
    let job = tokio::spawn(async move {
        let mut removal = Box::pin(group::remove_member_leased(&worker_path, pin));
        // The first poll dispatches the blocking worker. It cannot complete while
        // the test owns the group lock; readiness does not depend on scheduler timing.
        std::future::poll_fn(|cx| {
            assert!(std::future::Future::poll(removal.as_mut(), cx).is_pending());
            std::task::Poll::Ready(())
        })
        .await;
        started.send(()).unwrap();
        removal.await
    });
    ready.await.unwrap();
    job.abort();
    assert!(job.await.unwrap_err().is_cancelled());
    assert!(WriterLease::try_acquire(&directory).unwrap().is_none());
    assert!(StorageLease::try_exclusive(&second).unwrap().is_none());
    drop(lock);
    let deadline = Instant::now() + Duration::from_secs(5);
    while second.exists() || WriterLease::try_acquire(&directory).unwrap().is_none() {
        assert!(
            Instant::now() < deadline,
            "cancelled worker failed to finish"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert_eq!(
        group::read_group(&directory).unwrap().head.as_deref(),
        Some(id(1).as_str())
    );
    assert!(directory.join(".snapshot-deletions").exists());
}

#[tokio::test]
#[ignore = "subprocess worker invoked by removal crash qualification"]
async fn removal_crash_worker() {
    let directory = std::path::PathBuf::from(std::env::var_os("MSB_TEST_REMOVAL_GROUP").unwrap());
    group::remove_member(&directory.join(id(2).as_str()))
        .await
        .unwrap();
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[tokio::test]
async fn killed_remover_leaves_old_or_complete_group_and_recovers_catalog() {
    crash_cases(None).await;
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[tokio::test]
#[ignore = "requires a released CLI in MSB_TEST_LEGACY_CLI"]
async fn released_reader_observes_complete_group_after_removal_crash() {
    let executable = std::env::var_os("MSB_TEST_LEGACY_CLI").unwrap();
    crash_cases(Some(Path::new(&executable))).await;
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
async fn crash_cases(legacy_cli: Option<&Path>) {
    for boundary in ["prepared", "exchanged", "committed"] {
        let home = tempfile::tempdir().unwrap();
        let local = test_support::local_backend_builder(home.path())
            .build()
            .await
            .unwrap();
        group::ensure(&local.snapshots_dir(), Some("history"))
            .await
            .unwrap();
        // Exercise a surviving parent alias on Linux too, not only macOS's /var alias.
        // Once the member disappears, catalog recovery must keep its original key.
        let alias = home.path().join("snapshot-alias");
        std::os::unix::fs::symlink(local.snapshots_dir(), &alias).unwrap();
        let directory = alias.join("history");
        add(&directory, 1, None).await;
        add(&directory, 2, Some(1)).await;
        let first = directory.join(id(1).as_str());
        let second = directory.join(id(2).as_str());
        for path in [&first, &second] {
            let checkpoint = store::open_snapshot(&local, path.to_str().unwrap())
                .await
                .unwrap();
            store::index_upsert(&local, path, checkpoint.digest(), checkpoint.manifest())
                .await
                .unwrap();
        }
        let key = store::canonical_path(&second).display().to_string();
        assert!(
            snapshot::Entity::find_by_id(key)
                .one(local.db().await.unwrap().read())
                .await
                .unwrap()
                .is_some()
        );
        deletion::register_parent(&local, &directory).unwrap();
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "backend::local::snapshot::group::removal::tests::removal_crash_worker",
                "--ignored",
                "--nocapture",
            ])
            .env("MSB_TEST_REMOVAL_GROUP", &directory)
            .env("MSB_TEST_REMOVAL_BOUNDARY", boundary)
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let output = child.stdout.take().unwrap();
        let (sender, receiver) = mpsc::channel();
        let reader = std::thread::spawn(move || {
            for line in BufReader::new(output).lines() {
                if line.unwrap().contains("ATOMIC_REMOVAL_BOUNDARY_READY") {
                    let _ = sender.send(());
                    break;
                }
            }
        });
        let reached = receiver.recv_timeout(Duration::from_secs(20));
        let _ = child.kill();
        child.wait().unwrap();
        reader.join().unwrap();
        reached.expect("removal did not reach its publication boundary");
        let removed = boundary != "prepared";
        let expected_head = if removed { 1 } else { 2 };
        // Inspect the visible files BEFORE any new-runtime recovery. An old reader
        // does not understand our journal and must still see the complete chosen view.
        assert_eq!(
            group::read_members(&directory, true).unwrap().len(),
            if removed { 1 } else { 2 }
        );
        assert_eq!(
            group::read_group(&directory).unwrap().head.as_deref(),
            Some(id(expected_head).as_str())
        );
        if let Some(cli) = legacy_cli {
            for (path, present) in [(&first, true), (&second, !removed)] {
                let result = Command::new(cli)
                    .env("MSB_HOME", home.path().join("legacy"))
                    .args(["snapshot", "inspect"])
                    .arg(path)
                    .output()
                    .unwrap();
                assert_eq!(
                    result.status.success(),
                    present,
                    "boundary={boundary}: {} {}",
                    String::from_utf8_lossy(&result.stdout),
                    String::from_utf8_lossy(&result.stderr)
                );
            }
        }
        let key = store::canonical_path(&second).display().to_string();
        assert!(
            snapshot::Entity::find_by_id(key.clone())
                .one(local.db().await.unwrap().read())
                .await
                .unwrap()
                .is_some()
        );
        deletion::recover_parent(&local, &directory).await.unwrap();
        deletion::recover_parent(&local, &directory).await.unwrap();
        assert_eq!(
            snapshot::Entity::find_by_id(key)
                .one(local.db().await.unwrap().read())
                .await
                .unwrap()
                .is_none(),
            removed
        );
        let parent =
            snapshot::Entity::find_by_id(store::canonical_path(&first).display().to_string())
                .one(local.db().await.unwrap().read())
                .await
                .unwrap()
                .unwrap();
        assert_eq!(parent.child_count, if removed { 0 } else { 1 });
        assert_eq!(
            group::read_group(&directory).unwrap().head.as_deref(),
            Some(id(expected_head).as_str())
        );
    }
}
