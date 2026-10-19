//! Executable qualification of the proposed complete-directory publication mechanism.
//!
//! This module is deliberately test-only until namespace leases, catalog publication and
//! all supported platforms have a compatible commit mechanism. It must not silently replace
//! the importer with a partially qualified Unix-only implementation.

use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::path::Path;
use std::sync::atomic::AtomicUsize;
#[cfg(any(target_os = "macos", target_os = "linux"))]
use std::sync::atomic::Ordering;
#[cfg(any(target_os = "macos", target_os = "linux"))]
use std::{
    io::{BufRead, BufReader, Write},
    process::{Command, Stdio},
    sync::mpsc,
    time::Duration,
};

use microsandbox_image::storage_lease;
#[cfg(any(target_os = "macos", target_os = "linux"))]
use microsandbox_image::storage_lease::StorageLease;
#[cfg(any(target_os = "macos", target_os = "linux"))]
use microsandbox_utils::process_lock;

use super::super::metadata::METADATA_FILENAME;
use super::{
    GROUP_FILENAME, MEMBER_FILENAME, MicrosandboxResult, integrity, read_members,
    require_directory, sync_directory, write_group, write_member_name,
};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

static LIVE_PUBLICATIONS: AtomicUsize = AtomicUsize::new(0);

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A private complete view. Dropping it removes links, never the source payloads.
struct Generation {
    directory: tempfile::TempDir,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl Generation {
    /// The caller must retain group ownership and source reader pins while staging.
    fn prepare(
        group: &Path,
        incoming: &Path,
        aliases: &BTreeMap<String, String>,
        head: Option<String>,
    ) -> MicrosandboxResult<Self> {
        require_directory(group)?;
        require_directory(incoming)?;
        let root = group
            .parent()
            .ok_or_else(|| integrity("group has no parent".into()))?;
        let directory = tempfile::Builder::new()
            .prefix(".group-generation-")
            .tempdir_in(root)?;
        let mut members = read_members(group, true)?;
        for (id, member) in read_members(incoming, false)? {
            if let Some(existing) = members.get(&id) {
                if existing.digest != member.digest {
                    return Err(integrity(format!("conflicting descriptor for {id}")));
                }
            } else {
                members.insert(id, member);
            }
        }
        super::apply_aliases(&mut members, aliases)?;
        super::validate_ancestry(&members)?;
        if let Some(head) = &head
            && !members.contains_key(head)
        {
            return Err(integrity("staged head is not a member".into()));
        }
        // Seed every published member's namespace before copying the lock directory.
        // An older reader may first acquire its namespace lease after preparation;
        // that lease must refer to the same file in both directory generations.
        let _namespaces = members
            .keys()
            .map(|id| storage_lease::StorageLease::shared(&group.join(id)))
            .collect::<std::io::Result<Vec<_>>>()?;
        for (id, member) in members {
            let destination = directory.path().join(id);
            link_tree(&member.path, &destination)?;
            write_member_name(&destination, member.name.as_deref())?;
            sync_directory(&destination)?;
        }
        // Mutable metadata has a distinct inode; truncating the staged copy must never
        // change the published generation. The group lock instead MUST keep its identity.
        write_group(directory.path(), head)?;
        let source = group.join(super::super::source::SOURCE_FILENAME);
        if source.try_exists()? {
            // Binding is immutable local metadata, not an archive dependency. Preserve
            // it across publication without ever importing another host's association.
            if !fs::symlink_metadata(&source)?.is_file() {
                return Err(integrity(
                    "group source metadata is not a regular file".into(),
                ));
            }
            fs::hard_link(
                source,
                directory.path().join(super::super::source::SOURCE_FILENAME),
            )?;
        }
        fs::hard_link(
            group.join(".group.lock"),
            directory.path().join(".group.lock"),
        )?;
        if group.join(".msb-leases").exists() {
            link_tree(
                &group.join(".msb-leases"),
                &directory.path().join(".msb-leases"),
            )?;
        }
        // An interrupted deletion may still own a catalog row. Its journal is
        // part of the recoverable group state, even though it is not a member.
        // Writer admission excludes cleanup while these paths are copied, and
        // hard-linking its locks preserves ownership across the exchange.
        if group.join(".snapshot-deletions").exists() {
            link_tree(
                &group.join(".snapshot-deletions"),
                &directory.path().join(".snapshot-deletions"),
            )?;
        }
        sync_directory(directory.path())?;
        Ok(Self { directory })
    }

    fn path(&self) -> &Path {
        self.directory.path()
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(super) fn requested(group: &Path) -> bool {
    std::env::var_os("MSB_TEST_GENERATION_GROUP")
        .and_then(|path| fs::canonicalize(path).ok())
        .as_deref()
        == Some(group)
}

pub(super) fn publish_for_live_test(
    group: &Path,
    input: &Path,
    incoming: &BTreeMap<String, super::Member>,
    aliases: &BTreeMap<String, String>,
    head: Option<String>,
    operation: &super::IndexedPublication,
) -> MicrosandboxResult<()> {
    let prepared = Generation::prepare(group, input, aliases, head)?;
    super::transaction::stage_generation_index(prepared.path(), incoming, operation)?;
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        operation.outcome.store(
            crate::SnapshotImportOutcome::Unknown as u8,
            Ordering::Release,
        );
        exchange(group, prepared.path())?;
        operation.outcome.store(
            crate::SnapshotImportOutcome::Committed as u8,
            Ordering::Release,
        );
        LIVE_PUBLICATIONS.fetch_add(1, Ordering::Relaxed);
        eprintln!("GENERATION_TEST_COMMIT {}", group.display());
        Ok(())
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        Err(integrity(
            "directory-generation live qualification has no publisher for this platform".into(),
        ))
    }
}

/// No payload-copy fallback: same-filesystem hard-link failure is visible to the caller.
/// This is a qualification helper, not an approved filesystem-support restriction.
fn link_tree(source: &Path, destination: &Path) -> MicrosandboxResult<()> {
    require_directory(source)?;
    fs::create_dir(destination)?;
    let source_root = source.to_path_buf();
    let mut pending = vec![(source.to_path_buf(), destination.to_path_buf())];
    let mut directories = Vec::new();
    while let Some((source, destination)) = pending.pop() {
        directories.push(destination.clone());
        for entry in fs::read_dir(&source)? {
            let entry = entry?;
            let target = destination.join(entry.file_name());
            let kind = entry.file_type()?;
            if kind.is_dir() {
                fs::create_dir(&target)?;
                pending.push((entry.path(), target));
            } else if kind.is_file() {
                // Only artifact-root sidecars are mutable. Payloads with these names in
                // nested directories must retain their original identity as well.
                if source == source_root
                    && matches!(
                        entry.file_name().to_str(),
                        Some(MEMBER_FILENAME | METADATA_FILENAME)
                    )
                {
                    // Bound metadata copies to the established largest sidecar limit.
                    if entry.metadata()?.len() > 1024 * 1024 {
                        return Err(integrity("staged metadata exceeds its size limit".into()));
                    }
                    fs::copy(entry.path(), &target)?;
                    OpenOptions::new().write(true).open(&target)?.sync_all()?;
                } else {
                    fs::hard_link(entry.path(), target)?;
                }
            } else {
                return Err(integrity(format!(
                    "staging requires regular files and directories: {}",
                    entry.path().display()
                )));
            }
        }
    }
    // Persist children before their containing directories. Shared payload bytes were
    // already made durable by capture/import; no payload read or rewrite is needed here.
    for directory in directories.iter().rev() {
        sync_directory(directory)?;
    }
    Ok(())
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn exchange(left: &Path, right: &Path) -> std::io::Result<()> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let left_name = CString::new(left.as_os_str().as_bytes())?;
    let right_name = CString::new(right.as_os_str().as_bytes())?;
    // SAFETY: both C strings remain valid for the duration of the synchronous syscall.
    #[cfg(target_os = "macos")]
    let result =
        unsafe { libc::renamex_np(left_name.as_ptr(), right_name.as_ptr(), libc::RENAME_SWAP) };
    #[cfg(target_os = "linux")]
    let result = unsafe {
        libc::renameat2(
            libc::AT_FDCWD,
            left_name.as_ptr(),
            libc::AT_FDCWD,
            right_name.as_ptr(),
            libc::RENAME_EXCHANGE,
        )
    };
    if result != 0 {
        return Err(std::io::Error::last_os_error());
    }
    sync_directory(left.parent().expect("qualified group parent"))
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn publish_new(source: &Path, destination: &Path) -> std::io::Result<()> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let source_name = CString::new(source.as_os_str().as_bytes())?;
    let destination_name = CString::new(destination.as_os_str().as_bytes())?;
    // Refuse collisions in the syscall itself. An existence check followed by ordinary
    // rename could replace a concurrently created empty directory on Unix.
    #[cfg(target_os = "macos")]
    let result = unsafe {
        libc::renamex_np(
            source_name.as_ptr(),
            destination_name.as_ptr(),
            libc::RENAME_EXCL,
        )
    };
    #[cfg(target_os = "linux")]
    let result = unsafe {
        libc::renameat2(
            libc::AT_FDCWD,
            source_name.as_ptr(),
            libc::AT_FDCWD,
            destination_name.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    if result != 0 {
        return Err(std::io::Error::last_os_error());
    }
    sync_directory(destination.parent().expect("qualified group parent"))
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

use super::tests::{add, descriptor, id, stage};

/// A sibling subprocess test can inherit any open descriptor between fork and
/// exec. Keep negative ownership checks immediate, but allow bounded release of
/// such copies after the tested owner closes. A leaked owner still fails here.
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn assert_released(mut acquire: impl FnMut() -> bool) {
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while !acquire() {
        assert!(
            std::time::Instant::now() < deadline,
            "ownership was not released"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[tokio::test]
#[ignore = "live VM test: requires isolated home, runtime and real a/b/c archives from the qualification workload"]
async fn live_archive_import_restore_and_guest_content() {
    use crate::{Sandbox, Snapshot, backend::LocalBackend, snapshot::LoadOpts};

    let home = std::path::PathBuf::from(
        std::env::var_os("MSB_TEST_LIVE_HOME").expect("MSB_TEST_LIVE_HOME"),
    );
    let archives = std::path::PathBuf::from(
        std::env::var_os("MSB_TEST_LIVE_ARCHIVES").expect("MSB_TEST_LIVE_ARCHIVES"),
    );
    let prototype = std::env::var_os("MSB_TEST_GENERATION_GROUP").is_some();
    let backend = LocalBackend::builder().home(&home).build().await.unwrap();
    crate::with_backend(backend, async {
        let options = || LoadOpts { group: Some("qualified".into()), ..Default::default() };
        let started = std::time::Instant::now();
        let base = Snapshot::load_many(&[archives.join("a.msb")], options()).await.unwrap();
        assert_eq!(base.len(), 1);
        let base_head = Snapshot::group_head("qualified").await.unwrap().head;
        eprintln!("LIVE_BASE_IMPORTED seconds={:.3}", started.elapsed().as_secs_f64());

        let invalid = home.join("invalid-final.msb");
        fs::write(&invalid, b"not a snapshot archive").unwrap();
        let error = Snapshot::load_many(&[archives.join("b.msb"), invalid], options()).await.unwrap_err();
        let crate::MicrosandboxError::SnapshotImport(error) = error else { panic!("missing structured import failure: {error}") };
        assert_eq!(error.outcome, crate::SnapshotImportOutcome::NotCommitted);
        assert_eq!(Snapshot::group_head("qualified").await.unwrap().head, base_head);
        assert_eq!(Snapshot::list().await.unwrap().len(), 1);
        eprintln!("LIVE_INVALID_FINAL_REJECTED unchanged_members=1");

        let appended = Snapshot::load_many(&[archives.join("c.msb"), archives.join("b.msb")], options()).await.unwrap();
        assert_eq!(appended.len(), 2);
        assert_eq!(Snapshot::group_head("qualified").await.unwrap().head, appended[0].id());
        assert_eq!(Snapshot::list().await.unwrap().len(), 3);
        let retry = Snapshot::load_many(&[archives.join("b.msb"), archives.join("c.msb")], options()).await.unwrap();
        assert_eq!(retry.len(), 2);
        assert_eq!(Snapshot::list().await.unwrap().len(), 3);
        assert_eq!(Snapshot::group_head("qualified").await.unwrap().head, appended[0].id());
        assert_eq!(LIVE_PUBLICATIONS.load(Ordering::Relaxed), if prototype { 3 } else { 0 });
        eprintln!("LIVE_IMPORT_AND_RETRY_OK prototype={prototype} members=3 seconds={:.3}", started.elapsed().as_secs_f64());

        for state in ['a', 'b', 'c'] {
            let snapshot = Snapshot::open(format!("qualified:{state}")).await.unwrap();
            snapshot.verify().await.unwrap();
            let name = format!("pr01-restored-{state}");
            let boot = std::time::Instant::now();
            let sandbox = Sandbox::restore(format!("qualified:{state}"))
                .name(&name).cpus(2).memory(512u32).max_duration(120).restore().await.unwrap();
            let script = format!(
                "set -eu; test \"$(cat /work/state)\" = {}; test \"$(find /work/files -type f | wc -l | tr -d ' ')\" = 500; test \"$(cat /work/files/file-499)\" = record-499; sha256sum -c /work/payload.sha256; cat /work/state; if [ {} = a ]; then test ! -e /work/b; test ! -e /work/c; elif [ {} = b ]; then test -e /work/b; test ! -e /work/c; else test -e /work/b; test -e /work/c; fi",
                state.to_ascii_uppercase(), state, state,
            );
            let checked = sandbox.exec("sh", ["-c", &script]).await;
            // Clean up even when guest validation fails. The lifetime bound also covers
            // process interruption before cleanup; no source or user sandbox is targeted.
            let stopped = sandbox.stop().await;
            let removed = Sandbox::remove(&name).await;
            let output = checked.unwrap();
            assert!(output.status().success, "guest validation failed: {}", output.stderr().unwrap());
            stopped.unwrap();
            removed.unwrap();
            eprintln!("LIVE_RESTORE_OK state={state} seconds={:.3} output={:?}", boot.elapsed().as_secs_f64(), output.stdout().unwrap());
        }
        eprintln!("LIVE_END_TO_END_OK prototype={prototype} total_seconds={:.3}", started.elapsed().as_secs_f64());
    }).await;
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[tokio::test]
#[ignore = "live VM test: requires isolated home and full.msb containing the qualification background counter"]
async fn live_full_archive_import_resumes_captured_process() {
    use crate::{Sandbox, Snapshot, backend::LocalBackend, snapshot::LoadOpts};

    let home = std::path::PathBuf::from(std::env::var_os("MSB_TEST_LIVE_HOME").unwrap());
    let archives = std::path::PathBuf::from(std::env::var_os("MSB_TEST_LIVE_ARCHIVES").unwrap());
    let prototype = std::env::var_os("MSB_TEST_GENERATION_GROUP").is_some();
    let backend = LocalBackend::builder().home(&home).build().await.unwrap();
    crate::with_backend(backend, async {
        let started = std::time::Instant::now();
        let loaded = Snapshot::load_many(
            &[archives.join("full.msb")],
            LoadOpts { group: Some("qualified".into()), ..Default::default() },
        ).await.unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(Snapshot::list().await.unwrap().len(), 1);
        Snapshot::open("qualified:saved").await.unwrap().verify().await.unwrap();
        assert_eq!(LIVE_PUBLICATIONS.load(Ordering::Relaxed), if prototype { 1 } else { 0 });
        let sandbox = Sandbox::restore("qualified:saved").name("pr01-full-restored")
            .cpus(2).memory(512u32).max_duration(120).restore().await.unwrap();
        // A cold disk boot cannot advance this counter: only the shell captured in
        // guest RAM knows about it. Also verify that the recorded PID still exists.
        let script = "set -eu; test \"$(cat /work/marker)\" = full-state; pid=$(cat /work/pid); kill -0 \"$pid\"; before=$(cat /work/counter); sleep 2; after=$(cat /work/counter); test \"$after\" -gt \"$before\"; printf 'pid=%s counter=%s->%s\\n' \"$pid\" \"$before\" \"$after\"; tr '\\0' ' ' < /proc/$pid/cmdline";
        let checked = sandbox.exec("sh", ["-c", script]).await;
        let stopped = sandbox.stop().await;
        let removed = Sandbox::remove("pr01-full-restored").await;
        let output = checked.unwrap();
        assert!(output.status().success, "captured-process validation failed: {}", output.stderr().unwrap());
        stopped.unwrap();
        removed.unwrap();
        eprintln!("LIVE_FULL_RESUME_OK prototype={prototype} seconds={:.3} output={:?}", started.elapsed().as_secs_f64(), output.stdout().unwrap());
    }).await;
}

#[cfg(unix)]
#[tokio::test]
async fn staging_a_large_sparse_payload_preserves_inode_and_allocated_blocks() {
    let root = tempfile::tempdir().unwrap();
    let group = super::ensure(root.path(), Some("history")).await.unwrap();
    add(&group, 1, None).await;
    let input = stage(root.path(), &[descriptor(2, Some(1))]);
    let source = group
        .join(id(1).as_str())
        .join("qualification-sparse-payload");
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&source)
        .unwrap();
    file.set_len(64 * 1024 * 1024 * 1024).unwrap();
    file.sync_all().unwrap();
    let prepared = Generation::prepare(
        &group,
        input.path(),
        &BTreeMap::new(),
        Some(id(2).to_string()),
    )
    .unwrap();
    let target = prepared
        .path()
        .join(id(1).as_str())
        .join("qualification-sparse-payload");
    assert!(storage_lease::same_file(&source, &target).unwrap());
    assert_eq!(
        fs::metadata(&source).unwrap().len(),
        fs::metadata(&target).unwrap().len()
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        assert_eq!(
            fs::metadata(&source).unwrap().blocks(),
            fs::metadata(&target).unwrap().blocks()
        );
        assert!(fs::metadata(&source).unwrap().nlink() >= 2);
    }
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
fn new_group_publication_never_replaces_an_existing_destination() {
    let root = tempfile::tempdir().unwrap();
    let source = root.path().join("staged");
    let destination = root.path().join("history");
    fs::create_dir(&source).unwrap();
    fs::write(source.join("payload"), b"new").unwrap();
    fs::create_dir(&destination).unwrap();
    assert!(publish_new(&source, &destination).is_err());
    assert!(source.join("payload").exists());
    assert_eq!(fs::read_dir(&destination).unwrap().count(), 0);
}

#[tokio::test]
async fn staging_shares_payloads_but_isolates_mutable_metadata() {
    let root = tempfile::tempdir().unwrap();
    let group = super::ensure(root.path(), Some("history")).await.unwrap();
    add(&group, 1, None).await;
    let member = group.join(id(1).as_str());
    fs::write(member.join(METADATA_FILENAME), b"original labels").unwrap();
    write_member_name(&member, Some("baseline")).unwrap();
    let input = stage(root.path(), &[descriptor(2, Some(1))]);
    let _ownership = super::lock_group(&group).unwrap();
    let prepared = Generation::prepare(
        &group,
        input.path(),
        &BTreeMap::new(),
        Some(id(2).to_string()),
    )
    .unwrap();
    for (source, number) in [(&group, 1), (&input.path().to_path_buf(), 2)] {
        let original = source.join(id(number).as_str());
        let staged = prepared.path().join(id(number).as_str());
        assert!(
            storage_lease::same_file(
                &original.join(super::DESCRIPTOR_FILENAME),
                &staged.join(super::DESCRIPTOR_FILENAME)
            )
            .unwrap()
        );
        let manifest = descriptor(number, (number == 2).then_some(1));
        let microsandbox_image::snapshot::SnapshotState::File(state) = manifest.state else {
            unreachable!()
        };
        let payload = state.layer_path(&state.layers[0]);
        assert!(
            storage_lease::same_file(&original.join(&payload), &staged.join(&payload)).unwrap()
        );
    }
    for name in [MEMBER_FILENAME, METADATA_FILENAME] {
        let staged = prepared.path().join(id(1).as_str()).join(name);
        assert!(!storage_lease::same_file(&member.join(name), &staged).unwrap());
        let original = fs::read(member.join(name)).unwrap();
        fs::write(staged, b"changed staging").unwrap();
        assert_eq!(fs::read(member.join(name)).unwrap(), original);
    }
    assert!(
        !storage_lease::same_file(
            &group.join(GROUP_FILENAME),
            &prepared.path().join(GROUP_FILENAME)
        )
        .unwrap()
    );
    drop(prepared);
    assert!(member.join(super::DESCRIPTOR_FILENAME).exists());
    assert!(input.path().join(id(2).as_str()).exists());
}

#[cfg(unix)]
#[tokio::test]
async fn staging_rejects_symlinks_and_leaves_the_group_unchanged() {
    let root = tempfile::tempdir().unwrap();
    let group = super::ensure(root.path(), Some("history")).await.unwrap();
    add(&group, 1, None).await;
    let before = fs::read(group.join(GROUP_FILENAME)).unwrap();
    let input = stage(root.path(), &[descriptor(2, Some(1))]);
    std::os::unix::fs::symlink(
        root.path(),
        input.path().join(id(2).as_str()).join("escape"),
    )
    .unwrap();
    assert!(
        Generation::prepare(
            &group,
            input.path(),
            &BTreeMap::new(),
            Some(id(2).to_string())
        )
        .is_err()
    );
    assert_eq!(fs::read(group.join(GROUP_FILENAME)).unwrap(), before);
    assert!(!group.join(id(2).as_str()).exists());
    assert!(!fs::read_dir(root.path()).unwrap().any(|entry| {
        entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".group-generation-")
    }));
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[tokio::test]
async fn exchange_preserves_existing_group_lock_and_descriptor_reader() {
    let root = tempfile::tempdir().unwrap();
    let group = super::ensure(root.path(), Some("history")).await.unwrap();
    add(&group, 1, None).await;
    let member = group.join(id(1).as_str());
    let descriptor = member.join(super::DESCRIPTOR_FILENAME);
    let pin = StorageLease::descriptor(&descriptor, false)
        .unwrap()
        .unwrap();
    let ownership = super::lock_group(&group).unwrap();
    let input = stage(root.path(), &[self::descriptor(2, Some(1))]);
    let prepared = Generation::prepare(
        &group,
        input.path(),
        &BTreeMap::new(),
        Some(id(2).to_string()),
    )
    .unwrap();
    exchange(&group, prepared.path()).unwrap();
    let lock = process_lock::open_existing_lock_file(&group.join(".group.lock")).unwrap();
    assert!(!process_lock::try_lock_exclusive(&lock).unwrap());
    assert!(
        StorageLease::descriptor(&descriptor, true)
            .unwrap()
            .is_none()
    );
    assert_eq!(
        super::read_group(&group).unwrap().head,
        Some(id(2).to_string())
    );
    drop(ownership);
    assert_released(|| process_lock::try_lock_exclusive(&lock).unwrap());
    drop(pin);
    assert_released(|| {
        StorageLease::descriptor(&descriptor, true)
            .unwrap()
            .is_some()
    });
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[tokio::test]
async fn exchange_preserves_reader_namespace_acquired_after_preparation() {
    let root = tempfile::tempdir().unwrap();
    let group = super::ensure(root.path(), Some("history")).await.unwrap();
    add(&group, 1, None).await;
    let input = stage(root.path(), &[descriptor(2, Some(1))]);
    let _admission = super::super::writer::WriterLease::acquire(&group)
        .await
        .unwrap();
    let _ownership = super::lock_group(&group).unwrap();
    let prepared = Generation::prepare(
        &group,
        input.path(),
        &BTreeMap::new(),
        Some(id(2).to_string()),
    )
    .unwrap();
    // Model an unchanged old reader without acquiring the new writer gate. Both a
    // current member and an incoming ID have stable lease identity before commit.
    let readers =
        [1, 2].map(|number| StorageLease::shared(&group.join(id(number).as_str())).unwrap());
    exchange(&group, prepared.path()).unwrap();
    drop(prepared);
    for number in [1, 2] {
        assert!(
            StorageLease::try_exclusive(&group.join(id(number).as_str()))
                .unwrap()
                .is_none()
        );
    }
    drop(readers);
    for number in [1, 2] {
        assert_released(|| {
            StorageLease::try_exclusive(&group.join(id(number).as_str()))
                .unwrap()
                .is_some()
        });
    }
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[tokio::test]
async fn updated_publisher_waits_before_creating_namespace_leases() {
    let root = tempfile::tempdir().unwrap();
    let group = super::ensure(root.path(), Some("history")).await.unwrap();
    add(&group, 1, None).await;
    let input = stage(root.path(), &[descriptor(2, Some(1))]);
    let admission = super::super::writer::WriterLease::acquire(&group)
        .await
        .unwrap();
    let ownership = super::lock_group(&group).unwrap();
    let prepared = Generation::prepare(
        &group,
        input.path(),
        &BTreeMap::new(),
        Some(id(2).to_string()),
    )
    .unwrap();
    let later = stage(root.path(), &[descriptor(3, Some(2))]);
    let destination = group.clone();
    let mut publisher = tokio::spawn(async move {
        super::publish(&destination, later.path(), &BTreeMap::new(), &id(3), false).await
    });
    // Keep the actual publisher queued across preparation and exchange. This goes
    // through production writer admission rather than manufacturing an old lease.
    assert!(
        tokio::time::timeout(Duration::from_millis(50), &mut publisher)
            .await
            .is_err()
    );
    assert!(
        super::super::lease::deletion(&group.join(id(1).as_str()))
            .unwrap()
            .is_none()
    );
    exchange(&group, prepared.path()).unwrap();
    drop(ownership);
    drop(prepared);
    drop(admission);
    let result = tokio::time::timeout(Duration::from_secs(5), publisher)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(result.head, id(3).to_string());
    assert_eq!(read_members(&group, true).unwrap().len(), 3);
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[tokio::test]
async fn exchange_preserves_pending_deletion_recovery() {
    let root = tempfile::tempdir().unwrap();
    let group = super::ensure(root.path(), Some("history")).await.unwrap();
    add(&group, 1, None).await;
    let input = stage(root.path(), &[descriptor(2, Some(1))]);
    let _admission = super::super::writer::WriterLease::acquire(&group)
        .await
        .unwrap();
    let _ownership = super::lock_group(&group).unwrap();
    let journal = group.join(".snapshot-deletions/delete-interrupted");
    fs::create_dir_all(journal.join("payload")).unwrap();
    fs::write(journal.join("source.json"), b"\"retired\"").unwrap();
    fs::write(journal.join("payload/data"), b"retained payload").unwrap();
    let lock = process_lock::open_lock_file(&journal.join("active.lock")).unwrap();
    process_lock::lock_exclusive(&lock).unwrap();

    let prepared = Generation::prepare(
        &group,
        input.path(),
        &BTreeMap::new(),
        Some(id(2).to_string()),
    )
    .unwrap();
    exchange(&group, prepared.path()).unwrap();
    drop(prepared);
    assert_eq!(
        fs::read(journal.join("source.json")).unwrap(),
        b"\"retired\""
    );
    assert_eq!(
        fs::read(journal.join("payload/data")).unwrap(),
        b"retained payload"
    );
    let current = process_lock::open_existing_lock_file(&journal.join("active.lock")).unwrap();
    assert!(!process_lock::try_lock_exclusive(&current).unwrap());
    drop(lock);
    assert_released(|| process_lock::try_lock_exclusive(&current).unwrap());
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[tokio::test]
async fn sibling_capture_staging_survives_group_exchange() {
    let root = tempfile::tempdir().unwrap();
    let group = super::ensure(root.path(), Some("history")).await.unwrap();
    add(&group, 1, None).await;
    let input = stage(root.path(), &[descriptor(2, Some(1))]);
    let _admission = super::super::writer::WriterLease::acquire(&group)
        .await
        .unwrap();
    let _ownership = super::lock_group(&group).unwrap();
    let capture = tempfile::Builder::new()
        .prefix(".capture-")
        .tempdir_in(root.path())
        .unwrap();
    fs::write(capture.path().join("pending"), b"capture started").unwrap();
    let prepared = Generation::prepare(
        &group,
        input.path(),
        &BTreeMap::new(),
        Some(id(2).to_string()),
    )
    .unwrap();
    exchange(&group, prepared.path()).unwrap();
    drop(prepared);
    fs::write(capture.path().join("next-payload"), b"capture continues").unwrap();
    assert_eq!(
        fs::read(capture.path().join("pending")).unwrap(),
        b"capture started"
    );
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[tokio::test]
#[ignore = "qualification gate: current directory-swap prototype splits late-created namespace locks"]
async fn exchange_preserves_lease_created_after_staging() {
    let root = tempfile::tempdir().unwrap();
    let group = super::ensure(root.path(), Some("history")).await.unwrap();
    add(&group, 1, None).await;
    let input = stage(root.path(), &[descriptor(2, Some(1))]);
    let _ownership = super::lock_group(&group).unwrap();
    let prepared = Generation::prepare(
        &group,
        input.path(),
        &BTreeMap::new(),
        Some(id(2).to_string()),
    )
    .unwrap();
    // An older publisher pins its incoming ID BEFORE waiting for the group lock. The
    // group lock therefore cannot prevent this new lease from appearing after staging.
    let late_pin = StorageLease::shared(&group.join(id(3).as_str())).unwrap();
    exchange(&group, prepared.path()).unwrap();
    let deletion = StorageLease::try_exclusive(&group.join(id(3).as_str())).unwrap();
    assert!(
        deletion.is_none(),
        "directory exchange admitted deletion while an older publisher still held the same member's namespace lease"
    );
    drop((late_pin, deletion));
    // Production publication must pass this gate, not merely preserve the lock files
    // that happened to exist when preparation walked the original directory.
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[tokio::test]
#[ignore = "qualification gate: current directory-swap prototype relocates an in-flight capture's staging"]
async fn exchange_preserves_inflight_capture_path() {
    let root = tempfile::tempdir().unwrap();
    let group = super::ensure(root.path(), Some("history")).await.unwrap();
    add(&group, 1, None).await;
    let input = stage(root.path(), &[descriptor(2, Some(1))]);
    let _ownership = super::lock_group(&group).unwrap();
    let prepared = Generation::prepare(
        &group,
        input.path(),
        &BTreeMap::new(),
        Some(id(2).to_string()),
    )
    .unwrap();
    // create_snapshot prepares .capture-* inside the group before taking publication
    // ownership. Its subsequent writes reuse that path, even if the group is exchanged.
    let capture = tempfile::Builder::new()
        .prefix(".capture-")
        .tempdir_in(&group)
        .unwrap();
    fs::write(capture.path().join("pending"), b"capture started").unwrap();
    exchange(&group, prepared.path()).unwrap();
    let resumed = fs::write(capture.path().join("next-payload"), b"capture continues");
    assert!(
        resumed.is_ok(),
        "directory exchange stranded the ongoing capture: {resumed:?}"
    );
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[tokio::test]
async fn killed_generation_publisher_leaves_old_or_complete_directory() {
    crash_cases(None).await;
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[tokio::test]
#[ignore = "requires MSB_TEST_LEGACY_CLI pointing to an actual pre-change executable"]
async fn legacy_cli_observes_complete_generation_after_publisher_crash() {
    let executable = std::env::var_os("MSB_TEST_LEGACY_CLI").expect("MSB_TEST_LEGACY_CLI");
    crash_cases(Some(Path::new(&executable))).await;
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
async fn crash_cases(legacy_cli: Option<&Path>) {
    for fresh in [false, true] {
        for committed in [false, true] {
            let root = tempfile::tempdir().unwrap();
            let source = super::ensure(root.path(), Some(if fresh { "seed" } else { "history" }))
                .await
                .unwrap();
            if !fresh {
                add(&source, 1, None).await;
            }
            let destination = root.path().join("history");
            let input = stage(
                root.path(),
                &[descriptor(2, (!fresh).then_some(1)), descriptor(3, Some(2))],
            );
            let mut child = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "backend::local::snapshot::group::generation::generation_crash_worker",
                    "--ignored",
                    "--nocapture",
                ])
                .env("MSB_GENERATION_SOURCE", &source)
                .env("MSB_GENERATION_INPUT", input.path())
                .env("MSB_GENERATION_DESTINATION", &destination)
                .env(
                    "MSB_GENERATION_COMMITTED",
                    if committed { "1" } else { "0" },
                )
                .env("MSB_GENERATION_FRESH", if fresh { "1" } else { "0" })
                .stdout(Stdio::piped())
                .spawn()
                .unwrap();
            let output = child.stdout.take().unwrap();
            let (sender, receiver) = mpsc::channel();
            let reader = std::thread::spawn(move || {
                for line in BufReader::new(output).lines() {
                    if line.unwrap().contains("GENERATION_BOUNDARY_READY") {
                        let _ = sender.send(());
                        break;
                    }
                }
            });
            let reached = receiver.recv_timeout(Duration::from_secs(20));
            let _ = child.kill();
            child.wait().unwrap();
            reader.join().unwrap();
            reached.expect("generation publisher did not reach the requested boundary");
            if fresh && !committed {
                assert!(!destination.exists());
            } else {
                let members = read_members(&destination, true).unwrap();
                assert_eq!(
                    members.len(),
                    if committed {
                        if fresh { 2 } else { 3 }
                    } else {
                        1
                    }
                );
                assert_eq!(
                    super::read_group(&destination).unwrap().head,
                    Some(id(if committed { 3 } else { 1 }).to_string())
                );
            }
            if let Some(executable) = legacy_cli {
                for number in [2, 3] {
                    let output = Command::new(executable)
                        .env("MSB_HOME", root.path().join("isolated-legacy-home"))
                        .args(["snapshot", "inspect"])
                        .arg(destination.join(id(number).as_str()))
                        .output()
                        .unwrap();
                    assert_eq!(
                        output.status.success(),
                        committed,
                        "fresh={fresh}, committed={committed}, member={number}: {} {}",
                        String::from_utf8_lossy(&output.stdout),
                        String::from_utf8_lossy(&output.stderr)
                    );
                }
                if !fresh {
                    let output = Command::new(executable)
                        .env("MSB_HOME", root.path().join("isolated-legacy-home"))
                        .args(["snapshot", "inspect"])
                        .arg(destination.join(id(1).as_str()))
                        .output()
                        .unwrap();
                    assert!(
                        output.status.success(),
                        "old member must remain readable: {}",
                        String::from_utf8_lossy(&output.stderr)
                    );
                }
            }
        }
    }
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
#[ignore = "subprocess worker exercised by generation crash tests"]
fn generation_crash_worker() {
    let source = std::path::PathBuf::from(std::env::var_os("MSB_GENERATION_SOURCE").unwrap());
    let input = std::path::PathBuf::from(std::env::var_os("MSB_GENERATION_INPUT").unwrap());
    let destination =
        std::path::PathBuf::from(std::env::var_os("MSB_GENERATION_DESTINATION").unwrap());
    let _ownership = super::lock_group(&source).unwrap();
    let prepared =
        Generation::prepare(&source, &input, &BTreeMap::new(), Some(id(3).to_string())).unwrap();
    if std::env::var("MSB_GENERATION_COMMITTED").unwrap() == "1" {
        if std::env::var("MSB_GENERATION_FRESH").unwrap() == "1" {
            publish_new(prepared.path(), &destination).unwrap();
        } else {
            exchange(&source, prepared.path()).unwrap();
        }
    }
    println!("GENERATION_BOUNDARY_READY");
    std::io::stdout().flush().unwrap();
    loop {
        std::thread::park();
    }
}
