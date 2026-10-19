//! Whole-group verification with a pinned membership and shared physical payload checks.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use microsandbox_image::checkpoint::{
    CheckpointPayloadCheck, CheckpointVerificationPlan, ObjectId,
};
use microsandbox_image::snapshot::{
    FILE_MERKLE_BLAKE3_LEAF_SIZE, OwnedVolumeData, SnapshotState, UpperIntegrity,
    visit_owned_directory_payloads,
};

use crate::backend::LocalBackend;
use crate::snapshot::{
    CheckpointVerification, CheckpointVerifyStatus, SnapshotGroupVerifyReport, SnapshotId,
    SnapshotVerificationFinding, SnapshotVerificationFindingKind as FindingKind,
    SnapshotVerificationState as State, SnapshotVerifyReport, UpperVerifyStatus,
};
use crate::{MicrosandboxError, MicrosandboxResult};

use super::super::{Snapshot, create, group, store, writer::WriterLease};
use super::batch::{PayloadFailureKind, verify_payloads};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

struct MemberPlan {
    checks: Vec<CheckpointPayloadCheck>,
    head: Option<usize>,
    checkpoint: Option<CheckpointVerifyStatus>,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(in super::super) async fn verify_group(
    local: &LocalBackend,
    directory: &Path,
) -> MicrosandboxResult<SnapshotGroupVerifyReport> {
    verify_group_observed(local, directory, || {}).await
}

async fn verify_group_observed(
    local: &LocalBackend,
    directory: &Path,
    pinned: impl FnOnce() + Send + 'static,
) -> MicrosandboxResult<SnapshotGroupVerifyReport> {
    // Serialize selection with updated publishers, then hold every selected reader lease before
    // releasing admission. Never hold the group mutex while awaiting a descriptor reader lease.
    let writer = WriterLease::acquire(directory).await?;
    let paths = group::verification_paths(directory).await?;
    let mut members = Vec::with_capacity(paths.len());
    for path in paths {
        let result = match tokio::fs::symlink_metadata(&path).await {
            Ok(metadata) if metadata.file_type().is_dir() => {
                store::open_for_verification(local, &path)
                    .await
                    .and_then(|artifact| {
                        if path.file_name().and_then(|name| name.to_str())
                            != Some(artifact.id().as_str())
                        {
                            return Err(MicrosandboxError::SnapshotIntegrity(
                                "group member directory does not match its snapshot identity"
                                    .into(),
                            ));
                        }
                        Ok(artifact)
                    })
            }
            Ok(_) => Err(MicrosandboxError::SnapshotIntegrity(
                "group member is not a directory".into(),
            )),
            Err(error) => Err(error.into()),
        };
        members.push((path, result));
    }
    drop(writer);
    let group = directory
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .into_owned();
    let fs_state_limit = local.config().fs_state_limit();
    // The worker owns the leases, so cancelling the async caller cannot release protection while
    // blocking payload hashing is still running.
    tokio::task::spawn_blocking(move || {
        pinned();
        verify_members(group, members, fs_state_limit)
    })
    .await
    .map_err(|error| MicrosandboxError::Custom(format!("group verification task: {error}")))?
}

fn verify_members(
    group: String,
    members: Vec<(PathBuf, MicrosandboxResult<Snapshot>)>,
    fs_state_limit: usize,
) -> MicrosandboxResult<SnapshotGroupVerifyReport> {
    let mut checkpoints = Vec::with_capacity(members.len());
    let mut checks = Vec::new();
    let mut plans = Vec::with_capacity(members.len());
    // Keep `members` alive through hashing: each successful artifact owns its reader lease.
    for (path, artifact) in &members {
        let mut result = CheckpointVerification {
            id: path
                .file_name()
                .and_then(|name| name.to_str())
                .and_then(|name| SnapshotId::new(name).ok()),
            path: path.clone(),
            state: State::Complete,
            report: None,
            findings: Vec::new(),
        };
        let prepared = match artifact {
            Ok(artifact) => prepare(artifact, fs_state_limit),
            Err(error) => {
                result.findings.push(finding(path, error));
                checkpoints.push(result);
                plans.push(None);
                continue;
            }
        };
        match prepared {
            Ok(plan) => {
                let start = checks.len();
                checks.extend(plan.checks);
                plans.push(Some((
                    start..checks.len(),
                    plan.head.map(|index| start + index),
                    plan.checkpoint,
                )));
            }
            Err(error) => {
                result.findings.push(finding(path, &error));
                plans.push(None);
            }
        }
        checkpoints.push(result);
    }
    let batch = verify_payloads(&checks);
    for (index, plan) in plans.into_iter().enumerate() {
        let result = &mut checkpoints[index];
        if let Some((range, head, checkpoint)) = plan {
            let mut unrecorded = BTreeSet::new();
            for check_index in range {
                let check = &checks[check_index];
                match &batch.outcomes[check_index] {
                    Ok(UpperVerifyStatus::Verified { .. }) => {}
                    Ok(UpperVerifyStatus::NotRecorded) => {
                        unrecorded.insert(check.path.clone());
                        result.findings.push(SnapshotVerificationFinding {
                            path: check.path.clone(),
                            kind: FindingKind::NotRecorded,
                            detail: "payload has no recorded integrity".into(),
                        });
                    }
                    Err(error) => result.findings.push(SnapshotVerificationFinding {
                        path: check.path.clone(),
                        kind: match error.kind {
                            PayloadFailureKind::Missing => FindingKind::Missing,
                            PayloadFailureKind::Invalid => FindingKind::Invalid,
                            PayloadFailureKind::Unavailable => FindingKind::Unavailable,
                            PayloadFailureKind::Changed => FindingKind::Changed,
                        },
                        detail: error.detail.clone(),
                    }),
                }
            }
            if result
                .findings
                .iter()
                .all(|finding| finding.kind == FindingKind::NotRecorded)
            {
                let artifact = members[index]
                    .1
                    .as_ref()
                    .expect("planned member was opened");
                result.report = Some(SnapshotVerifyReport {
                    digest: artifact.digest().into(),
                    path: artifact.path().into(),
                    upper: head
                        .map(|index| {
                            batch.outcomes[index]
                                .as_ref()
                                .expect("all recorded checks passed")
                                .clone()
                        })
                        .unwrap_or(UpperVerifyStatus::NotRecorded),
                    checkpoint,
                    coverage: super::verification_coverage(unrecorded),
                });
            }
        }
        result.state = findings_state(&result.findings);
    }
    let state = if checkpoints.is_empty() {
        State::Empty
    } else if checkpoints
        .iter()
        .any(|member| member.state == State::Invalid)
    {
        State::Invalid
    } else if checkpoints
        .iter()
        .any(|member| member.state == State::Incomplete)
    {
        State::Incomplete
    } else {
        State::Complete
    };
    let failed = checkpoints
        .iter()
        .flat_map(|member| &member.findings)
        .any(|finding| finding.kind != FindingKind::NotRecorded);
    let report = SnapshotGroupVerifyReport {
        group,
        state,
        checkpoints,
        payload_hashes: batch.hashes,
    };
    if failed {
        Err(MicrosandboxError::SnapshotVerification(Box::new(report)))
    } else {
        Ok(report)
    }
}

fn prepare(artifact: &Snapshot, fs_state_limit: usize) -> MicrosandboxResult<MemberPlan> {
    let unsupported = artifact.manifest().unsupported_requires();
    if !unsupported.is_empty() {
        return Err(MicrosandboxError::Unsupported {
            op: crate::Operation::SnapshotOps,
            reason: crate::error::UnsupportedReason::NotAvailable(format!(
                "unknown required extensions: {}",
                unsupported.join(", ")
            )),
        });
    }
    match &artifact.manifest().state {
        SnapshotState::Checkpoint(state) => {
            let expected = ObjectId::new(&state.checkpoint_root)?;
            let plan = CheckpointVerificationPlan::prepare(
                artifact.path().join(create::CHECKPOINT_DIRECTORY),
                &expected,
                fs_state_limit,
            )?;
            create::validate_checkpoint_owned_inventory(artifact.manifest(), plan.checkpoint())?;
            Ok(MemberPlan {
                checks: plan.payloads().to_vec(),
                head: None,
                checkpoint: Some(CheckpointVerifyStatus {
                    root: plan.root_id().to_string(),
                }),
            })
        }
        SnapshotState::File(state) => {
            let mut plan = MemberPlan {
                checks: Vec::new(),
                head: None,
                checkpoint: None,
            };
            for layer in &state.layers {
                if layer.layer_id == state.head {
                    plan.head = Some(plan.checks.len());
                }
                let path = artifact.layer_path(layer);
                plan.checks.push(CheckpointPayloadCheck {
                    length: std::fs::symlink_metadata(&path)?.len(),
                    path,
                    integrity: layer.payload.integrity.clone(),
                    metadata_bytes: None,
                });
            }
            let owned = artifact.manifest().owned_volumes()?;
            visit_owned_directory_payloads(artifact.path(), &owned, |path, expected| {
                plan.checks.push(CheckpointPayloadCheck {
                    path: path.into(),
                    length: expected.bytes,
                    integrity: Some(UpperIntegrity::Sha256 {
                        digest: format!("sha256:{}", expected.digest),
                    }),
                    metadata_bytes: None,
                });
                Ok(())
            })?;
            for volume in owned {
                if let OwnedVolumeData::Disk { generation } = volume.data {
                    for layer in generation.layers {
                        plan.checks.push(CheckpointPayloadCheck {
                            path: artifact
                                .path()
                                .join("layers")
                                .join(format!("{}.{}", layer.layer_id, layer.format)),
                            length: layer.file_size,
                            integrity: layer.integrity_root.map(|root| {
                                UpperIntegrity::FileMerkleBlake3V1 {
                                    root,
                                    logical_size: layer.file_size,
                                    leaf_size: FILE_MERKLE_BLAKE3_LEAF_SIZE,
                                }
                            }),
                            metadata_bytes: None,
                        });
                    }
                }
            }
            Ok(plan)
        }
    }
}

fn finding(path: &Path, error: &MicrosandboxError) -> SnapshotVerificationFinding {
    let kind = match error {
        MicrosandboxError::Unsupported { .. } => FindingKind::Unsupported,
        MicrosandboxError::SnapshotNotFound(_) => FindingKind::Missing,
        MicrosandboxError::Io(error)
        | MicrosandboxError::Image(microsandbox_image::ImageError::Io(error)) => {
            if error.kind() == std::io::ErrorKind::NotFound {
                FindingKind::Missing
            } else {
                FindingKind::Unavailable
            }
        }
        _ => FindingKind::Invalid,
    };
    SnapshotVerificationFinding {
        path: path.into(),
        kind,
        detail: error.to_string(),
    }
}

fn findings_state(findings: &[SnapshotVerificationFinding]) -> State {
    if findings.iter().any(|finding| {
        matches!(
            finding.kind,
            FindingKind::Invalid | FindingKind::Changed | FindingKind::Missing
        )
    }) {
        State::Invalid
    } else if !findings.is_empty() {
        State::Incomplete
    } else {
        State::Complete
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use microsandbox_image::snapshot::*;
    use std::collections::BTreeMap;
    use std::sync::Arc;
    use std::time::Duration;

    fn install(directory: &Path, ordinal: u128) -> PathBuf {
        let id = SnapshotId::new(format!("snap_{ordinal:032x}")).unwrap();
        let layer = DiskLayerId::new(format!("layer_{ordinal:032x}")).unwrap();
        let path = directory.join(id.as_str());
        std::fs::create_dir(&path).unwrap();
        let manifest = Manifest {
            schema: SCHEMA.into(),
            snapshot_id: id,
            scope: SnapshotScope::Disk,
            state: SnapshotState::File(FileSnapshotState {
                disk_format: SnapshotFormat::Raw,
                filesystem: "ext4".into(),
                virtual_size: 5,
                head: layer.clone(),
                layers: vec![DiskLayer {
                    layer_id: layer,
                    format: SnapshotFormat::Raw,
                    virtual_size: 5,
                    backing: None,
                    payload: LayerPayload {
                        file_kind: LayerFileKind::Regular,
                        integrity: Some(UpperIntegrity::Sha256 {
                            digest: ObjectId::from_bytes(b"valid").unwrap().to_string(),
                        }),
                    },
                }],
            }),
            capture: SnapshotCapture {
                created_at: "2026-10-19T00:00:00Z".into(),
                source_lineage: None,
                source_checkpoint: None,
                consistency: SnapshotConsistency::CrashConsistent,
            },
            image: ImageRef {
                reference: "docker.io/library/alpine:3.20".into(),
                manifest_digest: format!("sha256:{}", "a".repeat(64)),
            },
            root_disk: SnapshotRootDisk::Managed,
            parent: None,
            extensions: BTreeMap::new(),
            requires: Vec::new(),
        };
        std::fs::write(
            path.join(DESCRIPTOR_FILENAME),
            manifest.to_canonical_bytes().unwrap(),
        )
        .unwrap();
        std::fs::write(path.join(DEFAULT_UPPER_FILE), b"valid").unwrap();
        path
    }

    #[tokio::test]
    async fn selection_stays_pinned_and_cancellation_keeps_worker_reader_leases() {
        for cancel in [false, true] {
            let home = tempfile::tempdir().unwrap();
            let local = Arc::new(
                LocalBackend::builder()
                    .home(home.path())
                    .build()
                    .await
                    .unwrap(),
            );
            let directory = group::ensure(&local.snapshots_dir(), Some("verification"))
                .await
                .unwrap();
            let first = install(&directory, 1);
            let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
            let (release_tx, release_rx) = std::sync::mpsc::channel();
            let verifier = tokio::spawn({
                let local = local.clone();
                let directory = directory.clone();
                async move {
                    verify_group_observed(&local, &directory, move || {
                        entered_tx.send(()).unwrap();
                        release_rx.recv_timeout(Duration::from_secs(10)).unwrap();
                    })
                    .await
                }
            });
            tokio::time::timeout(Duration::from_secs(10), entered_rx)
                .await
                .unwrap()
                .unwrap();
            // Normal updated writers may proceed once the selection is pinned. A newly
            // published member must not enter this verification's already-selected report.
            let admission = WriterLease::try_acquire(&directory).unwrap().unwrap();
            install(&directory, 2);
            drop(admission);
            assert!(
                super::super::super::lease::deletion(&first)
                    .unwrap()
                    .is_none()
            );
            if cancel {
                verifier.abort();
                assert!(verifier.await.unwrap_err().is_cancelled());
                assert!(
                    super::super::super::lease::deletion(&first)
                        .unwrap()
                        .is_none()
                );
                release_tx.send(()).unwrap();
            } else {
                release_tx.send(()).unwrap();
                let report = verifier.await.unwrap().unwrap();
                assert_eq!(report.state, State::Complete);
                assert_eq!(report.checkpoints.len(), 1);
                assert_eq!(report.checkpoints[0].path, first);
            }
            // Cancellation only detaches the worker; its completion must release all pins.
            tokio::time::timeout(Duration::from_secs(10), async {
                loop {
                    if super::super::super::lease::deletion(&first)
                        .unwrap()
                        .is_some()
                    {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .unwrap();
        }
    }
}
