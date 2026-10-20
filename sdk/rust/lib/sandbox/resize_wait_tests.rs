//! Deadline regression using a real SDK control connection and a delayed peer.

use std::sync::Arc;
use std::time::Duration;

use microsandbox_control_client::ControlWelcome;
use microsandbox_db::entity::{run, sandbox};
use microsandbox_protocol::{codec, wire::Envelope};
use microsandbox_runtime::ipc::RuntimeSocketPaths;
use sea_orm::{ActiveModelTrait, Set};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

use super::*;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn recorded(resource: ResourceKind) -> ResizeOperation {
    let target = match resource {
        ResourceKind::Cpus => ResizeTarget::Cpus { online: 4 },
        ResourceKind::Memory => ResizeTarget::Memory { total_mib: 512 },
    };
    ResizeOperation {
        id: if resource == ResourceKind::Cpus {
            "cpu"
        } else {
            "memory"
        }
        .into(),
        runtime_boot_id: "boot".into(),
        generation: 1,
        requested_target: target.clone(),
        accepted_target: target,
        status: ResourceResizeStatus {
            resource,
            requested: if resource == ResourceKind::Cpus {
                "4"
            } else {
                "512 MiB"
            }
            .into(),
            actual: "1".into(),
            enforced: "4".into(),
            state: ResourceConvergenceState::Converging,
        },
        outcome: ResizeOutcome::Pending,
        observation: ResizeObservation::Available,
    }
}

async fn delayed_memory_peer(listener: tokio::net::UnixListener, delay_pass: usize) {
    let mut peers = tokio::task::JoinSet::new();
    loop {
        let (socket, _) = tokio::select! {
            accepted = listener.accept() => accepted.unwrap(),
            Some(done) = peers.join_next(), if !peers.is_empty() => {
                done.unwrap();
                continue;
            }
        };
        peers.spawn(async move {
            let mut socket = BufReader::new(socket);
            match socket.fill_buf().await.unwrap().first().copied() {
                None => return,
                Some(0) => {},
                _ => {
                    let mut line = String::new();
                    socket.read_line(&mut line).await.unwrap();
                    assert_eq!(line, "{\"op\":\"capabilities\"}\n");
                    socket.write_all(b"{\"ok\":true,\"capabilities\":{\"cpu_resize\":true,\"memory_resize\":true,\"secrets_update\":false,\"resize_operations\":true},\"control_protocols\":[\"json\",\"cbor\"]}\n").await.unwrap();
                    return;
                }
            }
            let frame = codec::read_raw_frame(&mut socket).await.unwrap();
            let hello = Envelope::decode(&frame.body).unwrap().payload().unwrap();
            let welcome = ControlWelcome::negotiate(&hello, 64).unwrap();
            codec::write_raw_frame(&mut socket, &Envelope::new(1, "control.welcome", &welcome).unwrap().frame(0, 1).unwrap()).await.unwrap();
            let mut cpu_reads = 0;
            let mut memory_reads = 0;
            while let Ok(frame) = codec::read_raw_frame(&mut socket).await {
                let envelope = Envelope::decode(&frame.body).unwrap();
                if envelope.t == "control.pause.state" {
                    let state = microsandbox_protocol::control::PauseState {
                        paused: false,
                        recovery_required: false,
                        capture_unavailable: None,
                    };
                    codec::write_raw_frame(&mut socket, &Envelope::new(2, "control.pause.state", &state).unwrap().frame(frame.id, 1).unwrap()).await.unwrap();
                    continue;
                }
                assert_eq!(envelope.t, microsandbox_protocol::resize::RESIZE_REQUEST);
                let ResizeRequest::Read { id, .. } = envelope.payload().unwrap() else {
                    panic!("unexpected request {}", envelope.t);
                };
                let mut operation = if id == "cpu" {
                    cpu_reads += 1;
                    let mut operation = recorded(ResourceKind::Cpus);
                    operation.status.actual = cpu_reads.to_string();
                    operation
                } else {
                    memory_reads += 1;
                    if memory_reads == delay_pass {
                        // The caller's deadline must retain the completed CPU reply, including
                        // when a later polling pass has already improved its actual quantity.
                        std::future::pending::<()>().await;
                    }
                    recorded(ResourceKind::Memory)
                };
                operation.id = id;
                let reply = ResizeResponse {
                    tracking: ResizeTracking { runtime_boot_id: "boot".into(), max_retained: 256 },
                    operations: vec![operation],
                };
                codec::write_raw_frame(&mut socket, &Envelope::new(2, microsandbox_protocol::resize::RESIZE_RESPONSE, &reply).unwrap().frame(frame.id, 1).unwrap()).await.unwrap();
            }
        });
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[tokio::test]
async fn timeout_keeps_each_completed_resource_reply() {
    for delay_pass in [1, 2] {
        let home = tempfile::Builder::new()
            .prefix("msb-rsz-")
            .tempdir_in("/tmp")
            .unwrap();
        let local = Arc::new(
            crate::test_support::local_backend_builder(home.path())
                .build()
                .await
                .unwrap(),
        );
        let pools = local.db().await.unwrap();
        let mut config = crate::SandboxConfig::default();
        config.spec.name = "resize-wait".into();
        let config = serde_json::to_string(&config).unwrap();
        let sandbox = sandbox::ActiveModel {
            name: Set("resize-wait".into()),
            config: Set(config.clone()),
            active_config: Set(Some(config)),
            status: Set(sandbox::SandboxStatus::Running),
            ephemeral: Set(false),
            ..Default::default()
        }
        .insert(pools.write())
        .await
        .unwrap();
        run::ActiveModel {
            sandbox_id: Set(sandbox.id),
            pid: Set(Some(std::process::id() as i32)),
            status: Set(run::RunStatus::Running),
            ..Default::default()
        }
        .insert(pools.write())
        .await
        .unwrap();
        let paths = RuntimeSocketPaths::new(&local.config().run_dir(), "resize-wait");
        std::fs::create_dir_all(paths.control.parent().unwrap()).unwrap();
        let listener = tokio::net::UnixListener::bind(paths.control).unwrap();
        let peer = tokio::spawn(delayed_memory_peer(listener, delay_pass));
        let backend: Arc<dyn Backend> = local;
        let identity = SandboxIdentity::Local(sandbox.id);
        // Warm identity discovery before the deliberate response-delay deadline.
        open_session(&backend, "resize-wait", &identity)
            .await
            .unwrap();
        let selected = [recorded(ResourceKind::Cpus), recorded(ResourceKind::Memory)];
        let result = wait_for_operations(
            &backend,
            "resize-wait",
            &identity,
            Some(&selected),
            Some(Duration::from_secs(2)),
        )
        .await;
        peer.abort();
        if let Err(error) = peer.await {
            assert!(error.is_cancelled(), "peer failed: {error}");
        }
        let Err(MicrosandboxError::ResizeTimeout { status, .. }) = result else {
            panic!("expected response timeout, got {result:?}");
        };
        assert_eq!(
            status.len(),
            delay_pass,
            "retain only replies actually received"
        );
        assert_eq!(status[0].resource, ResourceKind::Cpus);
        assert_eq!(status[0].actual, delay_pass.to_string());
        if delay_pass == 2 {
            assert_eq!(status[1].resource, ResourceKind::Memory);
            assert_eq!(status[1].actual, "1");
        }
    }
}
