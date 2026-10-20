//! Coalesced guest confirmation without retaining runtime mutation authority during I/O.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use microsandbox_agent_client::{AgentClient, ClientResult, ErrorKind};
use microsandbox_protocol::resize::{
    ResizeObservation, ResizeOperation, ResizeOutcome, ResizeTarget,
};
use microsandbox_protocol::resources::{
    ObservationUnavailable, ObservedResources, ResourceObservation,
};
use microsandbox_types::modify::{ResourceConvergenceState, ResourceResizeStatus};
use tokio::sync::{Mutex, Notify};

use super::executor::RuntimeControlExecutor;
use super::resize_memory::{MemoryDeviceEvidence, observe_memory};
use crate::control::RuntimeLifecycle;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const RETRY_INTERVAL: Duration = Duration::from_secs(1);
const QUERY_DEADLINE: Duration = Duration::from_secs(2);

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

#[derive(Default)]
pub(super) struct ResizeObserver {
    pub wake: Arc<Notify>,
    query: Mutex<()>,
    started: AtomicBool,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl RuntimeControlExecutor {
    /// Start one observer per runtime. No work is sent for idle or unsupported resources.
    pub(crate) fn start_resize_observer(self: &Arc<Self>) {
        if self.resize_observer.started.swap(true, Ordering::AcqRel) {
            return;
        }
        let weak = Arc::downgrade(self);
        let wake = Arc::clone(&self.resize_observer.wake);
        self.signal_runtime.spawn(async move {
            loop {
                let Some(executor) = weak.upgrade() else {
                    break;
                };
                executor.refresh_resize(true).await;
                let retry = executor.retry_resize_observation();
                drop(executor);
                // Notify retains a permit if a setter races this transition to sleep. A
                // pending query is bounded; a sleeping worker never keeps the executor alive.
                if retry {
                    tokio::select! {
                        _ = wake.notified() => {},
                        _ = tokio::time::sleep(RETRY_INTERVAL) => {},
                    }
                } else {
                    wake.notified().await;
                }
            }
        });
    }

    /// Background and explicit reads share one query gate and one CPU/memory response.
    pub(super) async fn refresh_resize(&self, background: bool) {
        // An in-flight query will publish its own result. Return the retained state rather
        // than adding its deadline to this reader's deadline or queueing duplicate queries.
        let Ok(_query) = self.resize_observer.query.try_lock() else {
            return;
        };
        let (fence, records) = {
            // Capture can retain mutation authority while awaiting guest work. A background
            // task must never block a Tokio worker on that mutex and starve the guest relay.
            let Ok(mut state) = self.state.try_lock() else {
                return;
            };
            let records: Vec<_> = state
                .resize
                .current()
                .into_iter()
                .filter(|record| {
                    record.outcome == ResizeOutcome::Pending
                        && (!background || automatic_observation(record))
                })
                .collect();
            if records.is_empty() {
                return;
            }
            if state.lifecycle != RuntimeLifecycle::Running || state.user_pause.is_some() {
                for record in records {
                    state.resize.observed(
                        &record.id,
                        record.generation,
                        record.status,
                        ResizeObservation::Paused,
                    );
                }
                return;
            }
            (state.resize.observation_fence(), records)
        };

        let started = Instant::now();
        let query = tokio::time::timeout(QUERY_DEADLINE, async {
            let client = AgentClient::connect_with(&self.agent_sock, |options| {
                options.setup_timeout(Duration::from_secs(1))
            })
            .await?;
            // The typed client checks both relay and guest support before sending. Legacy
            // peers never receive a new message just because a background observer exists.
            let report = microsandbox_agent_client::resources::observe_resources(
                &client,
                rand::random(),
                Duration::from_secs(1),
            )
            .await;
            client.close().await;
            report
        })
        .await;

        let Ok(mut state) = self.state.try_lock() else {
            return;
        };
        if !state.resize.matches_observation(&fence)
            || state.lifecycle != RuntimeLifecycle::Running
            || state.user_pause.is_some()
        {
            // A pause/resume, capture attempt, or later target invalidates this response
            // even if the resulting numeric quantities happen to match again.
            return;
        }
        for record in records {
            let mut status = record.status;
            let observation = match &query {
                Ok(result) if started.elapsed() <= QUERY_DEADLINE => {
                    self.apply_resize_evidence(&record.accepted_target, &mut status, result)
                }
                _ => ResizeObservation::Unavailable,
            };
            state
                .resize
                .observed(&record.id, record.generation, status, observation);
        }
    }

    fn retry_resize_observation(&self) -> bool {
        let Ok(state) = self.state.try_lock() else {
            return true;
        };
        state.lifecycle == RuntimeLifecycle::Running
            && state.user_pause.is_none()
            && state.resize.current().iter().any(automatic_observation)
    }

    fn apply_resize_evidence(
        &self,
        target: &ResizeTarget,
        status: &mut ResourceResizeStatus,
        result: &ClientResult<ObservedResources>,
    ) -> ResizeObservation {
        let report = match result {
            Ok(report) => report,
            Err(error) if error.kind == ErrorKind::UnsupportedOperation => {
                return ResizeObservation::Unsupported;
            }
            Err(_) => return ResizeObservation::Unavailable,
        };
        match target {
            ResizeTarget::Cpus { online } => match (&report.cpu, self.vm.cpu_state()) {
                (ResourceObservation::Available { value }, Some(host))
                    if value.possible == host.possible && host.requested_online == *online =>
                {
                    status.actual = value.actual_online.to_string();
                    status.enforced = host.enforced.to_string();
                    status.state = if value.requested_online == *online
                        && value.actual_online == *online
                        && value.exact
                        && host.actual_online == *online
                        && host.enforced == *online
                    {
                        ResourceConvergenceState::Applied
                    } else {
                        ResourceConvergenceState::Converging
                    };
                    ResizeObservation::Available
                }
                (
                    ResourceObservation::Unavailable {
                        reason: ObservationUnavailable::Unsupported,
                    },
                    _,
                ) => ResizeObservation::Unsupported,
                _ => ResizeObservation::Unavailable,
            },
            ResizeTarget::Memory { total_mib } => observe_memory(
                status,
                *total_mib,
                self.vm
                    .memory_device_state()
                    .map(|host| MemoryDeviceEvidence {
                        boot_size: host.boot_size,
                        address: host.address,
                        region_size: host.region_size,
                        requested_size: host.requested_size,
                        plugged_size: host.plugged_size,
                    }),
                report.memory.clone(),
            ),
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Drop for ResizeObserver {
    fn drop(&mut self) {
        // Wake a parked worker so its weak-reference check can terminate it.
        self.wake.notify_one();
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn automatic_observation(record: &ResizeOperation) -> bool {
    record.outcome == ResizeOutcome::Pending && record.observation != ResizeObservation::Unsupported
}
