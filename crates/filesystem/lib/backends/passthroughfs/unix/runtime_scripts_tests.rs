//! Exact backing and adversarial namespace checks, independent of activation.

use std::{
    collections::BTreeSet,
    ffi::CString,
    fs::{self, File},
    os::unix::{ffi::OsStrExt, fs::symlink},
    path::Path,
    process::Command,
};

use cap_std::fs::Dir;
use tempfile::TempDir;

use super::PassthroughFs;
use super::runtime_scripts::{CapturedRuntimeScripts, RuntimeScriptLimits};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn source() -> (TempDir, File) {
    let root = tempfile::tempdir().unwrap();
    fs::create_dir(root.path().join("scripts")).unwrap();
    let dir = Dir::open_ambient_dir(root.path(), cap_std::ambient_authority()).unwrap();
    (root, dir.into_std_file())
}

fn capture_files(
    runtime: &File,
    names: &BTreeSet<String>,
) -> std::io::Result<CapturedRuntimeScripts> {
    CapturedRuntimeScripts::capture(
        runtime,
        names,
        RuntimeScriptLimits {
            max_entries: 256,
            max_script_bytes: 64 * 1024,
            max_total_bytes: 256 * 1024,
        },
    )
}

fn names(values: &[&str]) -> BTreeSet<String> {
    values.iter().map(|name| name.to_string()).collect()
}

fn permissions(path: &Path, uid: u32, gid: u32, mode: u16) {
    PassthroughFs::set_runtime_backing_permissions(&File::open(path).unwrap(), uid, gid, mode)
        .unwrap();
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[test]
fn exact_script_staging_preserves_guest_zero_mode_ownership_and_directory_metadata() {
    let (root, dir) = source();
    let content = "#!/bin/sh\r\nprintf 'LITERAL_SENTINEL λ'\r\n";
    fs::write(root.path().join("scripts/task"), content).unwrap();
    permissions(&root.path().join("scripts/task"), 123, 456, 0);
    permissions(root.path(), 7, 8, 0o751);
    permissions(&root.path().join("scripts"), 9, 10, 0o710);
    let capture = capture_files(&dir, &names(&["task"])).unwrap();
    let parent = tempfile::tempdir().unwrap();
    let staged = capture.stage_exact(parent.path()).unwrap();
    let staged_path = staged.path().to_owned();
    assert_eq!(
        fs::read(staged.path().join("scripts/task")).unwrap(),
        content.as_bytes()
    );
    for (relative, uid, gid, mode) in [
        ("", 7, 8, 0o751),
        ("scripts", 9, 10, 0o710),
        ("scripts/task", 123, 456, 0),
    ] {
        let stat =
            PassthroughFs::runtime_backing_stat(&File::open(staged.path().join(relative)).unwrap())
                .unwrap();
        assert_eq!((stat.st_uid, stat.st_gid), (uid, gid));
        assert_eq!(stat.st_mode & 0o7777, mode);
    }
    capture.revalidate().unwrap();
    assert!(!format!("{capture:?}").contains("SENTINEL"));
    assert_eq!(
        fs::read_to_string(root.path().join("scripts/task")).unwrap(),
        content
    );
    drop(staged);
    assert!(!staged_path.exists());
}

#[test]
fn source_inode_replacement_cannot_reuse_observed_bytes_or_publish_staging() {
    let (root, dir) = source();
    let file = root.path().join("scripts/task");
    fs::write(&file, "same bytes").unwrap();
    let capture = capture_files(&dir, &names(&["task"])).unwrap();
    let replacement = root.path().join("replacement");
    fs::write(&replacement, "same bytes").unwrap();
    fs::rename(replacement, &file).unwrap();
    assert!(capture.revalidate().is_err());
    let parent = tempfile::tempdir().unwrap();
    assert!(capture.stage_exact(parent.path()).is_err());
    assert_eq!(fs::read_dir(parent.path()).unwrap().count(), 0);
}

#[test]
fn content_and_virtual_permission_changes_invalidate_observations() {
    for mutate_content in [true, false] {
        let (root, dir) = source();
        let file = root.path().join("scripts/task");
        fs::write(&file, "old bytes").unwrap();
        let capture = capture_files(&dir, &names(&["task"])).unwrap();
        if mutate_content {
            fs::write(&file, "new bytes").unwrap();
        } else {
            permissions(&file, 0, 0, 0o640);
        }
        assert!(capture.revalidate().is_err());
    }
}

#[test]
fn linked_script_and_replaced_scripts_directory_never_read_outside_content() {
    let (root, dir) = source();
    let outside = tempfile::tempdir().unwrap();
    fs::write(outside.path().join("SECRET_PATH"), "SECRET_CONTENT").unwrap();
    symlink(
        outside.path().join("SECRET_PATH"),
        root.path().join("scripts/task"),
    )
    .unwrap();
    let error = capture_files(&dir, &names(&["task"]))
        .unwrap_err()
        .to_string();
    assert!(!error.contains("SECRET"));
    fs::remove_file(root.path().join("scripts/task")).unwrap();
    fs::write(root.path().join("scripts/task"), "original").unwrap();
    let capture = capture_files(&dir, &names(&["task"])).unwrap();
    fs::rename(root.path().join("scripts"), root.path().join("previous")).unwrap();
    symlink(outside.path(), root.path().join("scripts")).unwrap();
    assert!(capture.revalidate().is_err());
    assert!(capture_files(&dir, &names(&["SECRET_PATH"])).is_err());
    assert_eq!(
        fs::read_to_string(outside.path().join("SECRET_PATH")).unwrap(),
        "SECRET_CONTENT"
    );
}

#[test]
fn invalid_names_refuse_before_opening_any_candidate() {
    let (_root, dir) = source();
    for name in [
        "",
        ".",
        "..",
        "../SECRET",
        "/SECRET",
        "a/b",
        "a\\b",
        "NUL\0SECRET",
    ] {
        let error = capture_files(&dir, &names(&[name]))
            .unwrap_err()
            .to_string();
        assert!(error.contains("SCFG_BACKING"));
        assert!(!error.contains("SECRET"));
    }
}

#[test]
fn non_files_invalid_utf8_and_size_limits_refuse_without_executing_or_blocking() {
    let (root, dir) = source();
    fs::write(root.path().join("scripts/invalid"), [0xff]).unwrap();
    fs::write(root.path().join("scripts/large"), vec![b'x'; 64 * 1024 + 1]).unwrap();
    fs::create_dir(root.path().join("scripts/directory")).unwrap();
    let fifo = CString::new(root.path().join("scripts/fifo").as_os_str().as_bytes()).unwrap();
    // SAFETY: the CString is terminated and points into our owned temporary directory.
    assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
    for name in ["invalid", "large", "directory", "fifo"] {
        assert!(capture_files(&dir, &names(&[name])).is_err(), "{name}");
    }
    let too_many = (0..257).map(|i| format!("script-{i}")).collect();
    assert!(
        capture_files(&dir, &too_many)
            .unwrap_err()
            .to_string()
            .contains("SCFG_LIMIT")
    );
    for i in 0..5 {
        fs::write(
            root.path().join(format!("scripts/script-{i}")),
            vec![b'x'; 64 * 1024],
        )
        .unwrap();
    }
    assert!(
        capture_files(&dir, &(0..5).map(|i| format!("script-{i}")).collect())
            .unwrap_err()
            .to_string()
            .contains("SCFG_LIMIT")
    );
    assert!(
        CapturedRuntimeScripts::capture(
            &dir,
            &BTreeSet::new(),
            RuntimeScriptLimits {
                max_entries: 1,
                max_script_bytes: usize::MAX,
                max_total_bytes: usize::MAX,
            }
        )
        .is_err()
    );
}

#[test]
fn staging_failure_does_not_replace_existing_destination_and_empty_is_known_empty() {
    let (_root, dir) = source();
    let capture = capture_files(&dir, &BTreeSet::new()).unwrap();
    assert_eq!(capture.observations().count(), 0);
    let parent = tempfile::tempdir().unwrap();
    let sentinel = parent.path().join("keep");
    fs::write(&sentinel, "UNCHANGED").unwrap();
    assert!(capture.stage_exact(&sentinel).is_err());
    assert_eq!(fs::read_to_string(&sentinel).unwrap(), "UNCHANGED");
    let staged = capture.stage_exact(parent.path()).unwrap();
    assert_eq!(
        fs::read_dir(staged.path().join("scripts")).unwrap().count(),
        0
    );
}

#[test]
fn late_failure_or_source_change_discards_every_staged_file() {
    for source_change in [false, true] {
        let (root, dir) = source();
        for name in ["first", "second"] {
            fs::write(root.path().join("scripts").join(name), "captured").unwrap();
        }
        let capture = capture_files(&dir, &names(&["first", "second"])).unwrap();
        let parent = tempfile::tempdir().unwrap();
        let mut reached_completion = false;
        let result = capture.stage_with_check(parent.path(), || {
            reached_completion = true;
            let temporary = fs::read_dir(parent.path())
                .unwrap()
                .next()
                .unwrap()
                .unwrap()
                .path();
            assert!(temporary.join("scripts/first").is_file());
            assert!(temporary.join("scripts/second").is_file());
            if source_change {
                fs::write(root.path().join("scripts/second"), "changed").unwrap();
                Ok(())
            } else {
                Err(std::io::Error::other("injected late failure"))
            }
        });
        assert!(reached_completion, "must exercise failure after staging");
        assert!(result.is_err());
        assert_eq!(fs::read_dir(parent.path()).unwrap().count(), 0);
        assert_eq!(
            fs::read_to_string(root.path().join("scripts/first")).unwrap(),
            "captured"
        );
    }
}

#[test]
fn relative_staging_keeps_symlink_parent_semantics_and_survives_cwd_change() {
    let output = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "backends::passthroughfs::unix::runtime_scripts_tests::relative_staging_worker",
            "--ignored",
            "--nocapture",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed"));
}

#[test]
#[ignore = "isolated cwd worker invoked by relative_staging_keeps_symlink_parent_semantics_and_survives_cwd_change"]
fn relative_staging_worker() {
    let original_cwd = std::env::current_dir().unwrap();
    let root = tempfile::tempdir().unwrap();
    for directory in ["a/stage", "b/stage", "actual/nested", "actual/stage"] {
        fs::create_dir_all(root.path().join(directory)).unwrap();
    }
    symlink(
        root.path().join("actual/nested"),
        root.path().join("a/alias"),
    )
    .unwrap();
    let sentinel = root.path().join("b/stage/keep");
    fs::write(&sentinel, "untouched").unwrap();
    let (_source_root, source) = source();
    let captured = capture_files(&source, &BTreeSet::new()).unwrap();
    // Only this dedicated subprocess changes cwd; the parallel test harness is unaffected.
    std::env::set_current_dir(root.path().join("a")).unwrap();
    let staged = captured.stage_exact(Path::new("alias/../stage")).unwrap();
    assert!(staged.path().is_absolute());
    assert_eq!(
        fs::read_dir(root.path().join("actual/stage"))
            .unwrap()
            .count(),
        1
    );
    assert_eq!(
        fs::read_dir(root.path().join("a/stage")).unwrap().count(),
        0
    );
    std::env::set_current_dir(root.path().join("b")).unwrap();
    assert!(staged.path().join("scripts").is_dir());
    drop(staged);
    assert_eq!(
        fs::read_dir(root.path().join("actual/stage"))
            .unwrap()
            .count(),
        0
    );
    assert_eq!(fs::read_to_string(sentinel).unwrap(), "untouched");
    std::env::set_current_dir(original_cwd).unwrap();
}
