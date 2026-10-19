//! Durable reclamation of the old directory after a complete-group exchange.

use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::super::{
    MAX_METADATA_BYTES, integrity, read_regular, require_directory, sync_directory, write_json,
};
use crate::MicrosandboxResult;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

pub(super) const DIRECTORY: &str = ".group-retirements";
const SCHEMA: &str = "microsandbox.group-retirement/1";

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

#[derive(Serialize, Deserialize)]
struct Retirement {
    schema: String,
    name: PathBuf,
    device: u64,
    inode: u64,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Record the old directory's identity in the new view before either name changes.
/// The separate journal is intentional: old readers may recover/delete an old-format
/// `.snapshot-deletions` receipt, but must not erase this reclamation intent with it.
pub(super) fn stage(group: &Path, prepared: &Path) -> MicrosandboxResult<()> {
    let metadata = fs::symlink_metadata(group)?;
    require_directory(group)?;
    let name = prepared
        .file_name()
        .ok_or_else(|| integrity("generation has no name".into()))?;
    let root = prepared.join(DIRECTORY);
    fs::create_dir_all(&root)?;
    require_directory(&root)?;
    write_json(
        &root,
        &format!("{}.json", name.to_string_lossy()),
        &Retirement {
            schema: SCHEMA.into(),
            name: name.into(),
            device: metadata.dev(),
            inode: metadata.ino(),
        },
    )?;
    sync_directory(prepared)?;
    Ok(())
}

/// The caller holds writer admission throughout this operation, including on cancellation.
pub(super) fn recover(group: &Path) -> MicrosandboxResult<()> {
    let root = group.join(DIRECTORY);
    match fs::symlink_metadata(&root) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
        Ok(_) => require_directory(&root)?,
    }
    for entry in fs::read_dir(&root)? {
        let entry = entry?;
        if entry.path().extension().and_then(|value| value.to_str()) == Some("json") {
            finish_record(group, &entry.path())?;
        }
    }
    Ok(())
}

pub(super) fn finish(group: &Path, retired: &Path) -> MicrosandboxResult<()> {
    let name = retired
        .file_name()
        .ok_or_else(|| integrity("generation has no name".into()))?;
    finish_record(
        group,
        &group
            .join(DIRECTORY)
            .join(format!("{}.json", name.to_string_lossy())),
    )
}

fn finish_record(group: &Path, record: &Path) -> MicrosandboxResult<()> {
    let retirement: Retirement =
        serde_json::from_slice(&read_regular(record, MAX_METADATA_BYTES)?)?;
    if retirement.schema != SCHEMA
        || retirement.name.components().count() != 1
        || !matches!(
            retirement.name.components().next(),
            Some(Component::Normal(_))
        )
        || !retirement
            .name
            .to_string_lossy()
            .starts_with(".group-generation-")
    {
        return Err(integrity("invalid retired group generation record".into()));
    }
    let parent = group
        .parent()
        .ok_or_else(|| integrity("group has no parent".into()))?;
    let retired = parent.join(&retirement.name);
    // A crash can occur immediately after exchange, before either directory entry
    // is durable. Never reclaim the rollback view until the live view is flushed.
    sync_directory(group)?;
    sync_directory(parent)?;
    match fs::symlink_metadata(&retired) {
        Ok(metadata) => {
            if !metadata.file_type().is_dir()
                || (metadata.dev(), metadata.ino()) != (retirement.device, retirement.inode)
            {
                return Err(integrity(format!(
                    "retired group generation identity changed at {}; cleanup record retained",
                    retired.display()
                )));
            }
            fs::remove_dir_all(&retired)?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    // Payload removal is durable before the intent disappears. A missing retired
    // directory on retry means cleanup reached this boundary, not a failed import.
    sync_directory(parent)?;
    fs::remove_file(record)?;
    sync_directory(record.parent().unwrap())?;
    Ok(())
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::local::snapshot::writer::WriterLease;

    fn exchanged() -> (tempfile::TempDir, PathBuf, PathBuf, WriterLease) {
        let root = tempfile::tempdir().unwrap();
        let group = root.path().join("history");
        fs::create_dir(&group).unwrap();
        fs::write(group.join("payload"), b"retired bytes").unwrap();
        let retired = tempfile::Builder::new()
            .prefix(".group-generation-")
            .tempdir_in(root.path())
            .unwrap()
            .keep();
        let admission = WriterLease::try_acquire(&group).unwrap().unwrap();
        stage(&group, &retired).unwrap();
        super::super::exchange_names(&group, &retired).unwrap();
        (root, group, retired, admission)
    }

    #[test]
    fn cleanup_is_recoverable_after_payload_removal_before_receipt_removal() {
        let (_root, group, retired, _admission) = exchanged();
        fs::remove_dir_all(&retired).unwrap();
        recover(&group).unwrap();
        recover(&group).unwrap();
        assert_eq!(fs::read_dir(group.join(DIRECTORY)).unwrap().count(), 0);
    }

    #[test]
    fn replacement_at_retired_name_is_never_deleted() {
        let (root, group, retired, _admission) = exchanged();
        let original = root.path().join("original");
        fs::rename(&retired, &original).unwrap();
        fs::create_dir(&retired).unwrap();
        fs::write(retired.join("unrelated"), b"keep").unwrap();
        let error = recover(&group).unwrap_err();
        assert!(error.to_string().contains("identity changed"));
        assert_eq!(fs::read(retired.join("unrelated")).unwrap(), b"keep");
        assert!(original.join("payload").exists());
        assert_eq!(fs::read_dir(group.join(DIRECTORY)).unwrap().count(), 1);
        fs::remove_dir_all(&retired).unwrap();
        fs::rename(&original, &retired).unwrap();
        recover(&group).unwrap();
        assert!(!retired.exists());
    }

    #[test]
    fn traversal_and_symlink_records_cannot_select_external_payload() {
        let (root, group, retired, _admission) = exchanged();
        let record = fs::read_dir(group.join(DIRECTORY))
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        let bytes = fs::read(&record).unwrap();
        let mut invalid: Retirement = serde_json::from_slice(&bytes).unwrap();
        invalid.name = PathBuf::from("../outside");
        fs::write(&record, serde_json::to_vec(&invalid).unwrap()).unwrap();
        assert!(
            recover(&group)
                .unwrap_err()
                .to_string()
                .contains("invalid retired")
        );
        assert!(retired.join("payload").exists());
        fs::write(&record, bytes).unwrap();
        let original = root.path().join("original");
        fs::rename(&retired, &original).unwrap();
        std::os::unix::fs::symlink(&original, &retired).unwrap();
        assert!(
            recover(&group)
                .unwrap_err()
                .to_string()
                .contains("identity changed")
        );
        assert_eq!(
            fs::read(original.join("payload")).unwrap(),
            b"retired bytes"
        );
    }
}
