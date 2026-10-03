//! Rust node and fleet controllers. REST owns snapshots; WS only requests resync.
use node_core::{AppliedSnapshot, UserSpec};
use node_kernel::{KernelAdapter, KernelError, KernelStatus, SingBoxProcessKernel};
use node_panel::{Fetch, Panel, PanelError, ReportOutcome, WsClient, WsEvent};
pub mod administration;
pub mod embedded;
pub mod fleet;
pub mod health_fleet;
pub mod logging;
pub mod observations;
mod owned_task;
pub use owned_task::Task as OwnedTask;
pub mod traffic;
use serde::{Deserialize, Serialize};
use std::{
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use thiserror::Error;
use tokio::sync::{mpsc, watch};
use traffic::{Outbox, TrafficError};

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeConfig {
    #[serde(default)]
    pub embedded: bool,
    #[serde(default)]
    pub dns: Option<node_core::routing::DnsConfig>,
    pub panel_url: String,
    /// Explicit local fixture support; remote panels continue to require HTTPS.
    #[serde(default)]
    pub allow_loopback_http: bool,
    pub token_env: String,
    pub node_id: u32,
    #[serde(default)]
    pub machine_id: Option<u32>,
    #[serde(default)]
    pub node_type: Option<String>,
    #[serde(default)]
    pub singbox_executable: Option<PathBuf>,
    pub state_dir: PathBuf,
    #[serde(default = "default_poll")]
    pub poll_seconds: u64,
    #[serde(default)]
    pub websocket: bool,
    #[serde(default)]
    pub native_user_updates: bool,
    #[serde(default)]
    pub traffic_reporting: Option<bool>,
    #[serde(default = "default_report")]
    pub report_seconds: u64,
    #[serde(default = "default_checkpoint")]
    pub traffic_checkpoint_ms: u64,
}
fn default_checkpoint() -> u64 {
    1000
}
fn default_report() -> u64 {
    60
}
fn default_poll() -> u64 {
    30
}
impl RuntimeConfig {
    pub fn validate(&self) -> Result<(), RuntimeError> {
        if let Some(dns) = &self.dns {
            if self.singbox_executable.is_some() {
                return Err(RuntimeError::Config);
            }
            dns.validate().map_err(|_| RuntimeError::Config)?;
        }
        if self.node_id == 0
            || self.embedded && (!cfg!(unix) || self.singbox_executable.is_some())
            || ((self.native_user_updates || self.singbox_executable.is_none()) && !cfg!(unix))
            || self.machine_id == Some(0)
            || !(1..=3600).contains(&self.poll_seconds)
            || !(1..=3600).contains(&self.report_seconds)
            || !(50..=60000).contains(&self.traffic_checkpoint_ms)
            || (self.traffic_reporting == Some(true) && self.singbox_executable.is_some())
            || self.token_env.is_empty()
            || self.token_env.len() > 128
            || !self
                .token_env
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_')
            || self
                .singbox_executable
                .as_ref()
                .is_some_and(|path| !path.is_absolute())
            || !self.state_dir.is_absolute()
            || (self.machine_id.is_none() && self.node_type.as_deref().is_none_or(str::is_empty))
        {
            return Err(RuntimeError::Config);
        }
        Ok(())
    }
}

#[derive(Debug, Error)]
pub enum RuntimeError {
    #[error("invalid runtime configuration")]
    Config,
    #[error("panel synchronization failed: {0}")]
    Panel(#[from] PanelError),
    #[error("kernel application failed: {0}")]
    Kernel(#[from] KernelError),
    #[error("missing initial configuration or users")]
    MissingSnapshot,
    #[error("invalid user or configuration snapshot")]
    InvalidSnapshot,
    #[error("kernel worker failed")]
    Worker,
    #[error("runtime is shutting down")]
    Closing,
    #[error("cached response no longer matches active snapshot; resync required")]
    CacheChanged,
    #[error("traffic accounting failed: {0}")]
    Traffic(#[from] TrafficError),
    #[error("runtime administration failed: {0}")]
    Administration(&'static str),
}

pub trait ManagedKernel: KernelAdapter + Send + Sync + 'static {
    fn stop(&self) -> Result<(), KernelError>;
    fn activity(&self) -> Result<node_core::ActivitySnapshot, KernelError> {
        Err(KernelError::Invalid(
            "activity accounting unavailable".into(),
        ))
    }
    fn traffic_quiesce(&self) -> Result<bool, KernelError> {
        Ok(false)
    }
    fn traffic_snapshot(&self) -> Result<Option<node_core::TrafficSnapshot>, KernelError> {
        Err(KernelError::Invalid(
            "traffic accounting unavailable".into(),
        ))
    }
    fn traffic_ack(&self, _: &node_core::TrafficSnapshot) -> Result<(), KernelError> {
        Err(KernelError::Invalid(
            "traffic accounting unavailable".into(),
        ))
    }
}
impl ManagedKernel for SingBoxProcessKernel {
    fn stop(&self) -> Result<(), KernelError> {
        SingBoxProcessKernel::stop(self)
    }
    fn activity(&self) -> Result<node_core::ActivitySnapshot, KernelError> {
        SingBoxProcessKernel::activity(self)
    }
    fn traffic_quiesce(&self) -> Result<bool, KernelError> {
        SingBoxProcessKernel::traffic_quiesce(self)
    }
    fn traffic_snapshot(&self) -> Result<Option<node_core::TrafficSnapshot>, KernelError> {
        SingBoxProcessKernel::traffic_snapshot(self)
    }
    fn traffic_ack(&self, snapshot: &node_core::TrafficSnapshot) -> Result<(), KernelError> {
        SingBoxProcessKernel::traffic_ack(self, snapshot)
    }
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct RuntimeMetrics {
    pub sync_attempts: u64,
    pub applied: u64,
    pub unchanged: u64,
    pub failed: u64,
    pub push_resyncs: u64,
    pub recovered: u64,
    pub traffic_collected: u64,
    pub traffic_reports: u64,
    pub traffic_uncertain: u64,
}
#[derive(Debug, PartialEq, Eq)]
pub enum SyncResult {
    Applied,
    Unchanged,
}

#[derive(Default)]
struct CommittedState {
    snapshot: Option<AppliedSnapshot>,
    source_config: Option<node_core::NodeSpec>,
    generation: u64,
}

pub struct NodeRuntime<K: ManagedKernel> {
    panel: Panel,
    kernel: Arc<K>,
    node_id: u32,
    applied: Arc<Mutex<CommittedState>>,
    cache_generation: u64,
    transaction: Arc<Mutex<()>>,
    closing: Arc<AtomicBool>,
    metrics: RuntimeMetrics,
    outbox: Option<Arc<Mutex<Outbox>>>,
    report_period: Duration,
    transform: Option<Arc<dyn administration::SnapshotTransform>>,
    local: Option<Arc<dyn administration::LocalSnapshotSource>>,
    observation_period: Option<Duration>,
    status_period: Option<Duration>,
    last_active: std::collections::BTreeSet<i64>,
    track_period: Duration,
    health: Option<Arc<observations::Health>>,
    state_dir: PathBuf,
    collector: observations::Collector,
    log: Option<Arc<logging::Log>>,
}
impl<K: ManagedKernel> NodeRuntime<K> {
    pub fn new(panel: Panel, kernel: K, node_id: u32) -> Self {
        Self {
            panel,
            kernel: Arc::new(kernel),
            node_id,
            applied: Arc::new(Mutex::new(CommittedState::default())),
            cache_generation: 0,
            transaction: Arc::new(Mutex::new(())),
            closing: Arc::new(AtomicBool::new(false)),
            metrics: RuntimeMetrics::default(),
            outbox: None,
            report_period: Duration::from_secs(60),
            transform: None,
            local: None,
            observation_period: None,
            status_period: None,
            last_active: Default::default(),
            track_period: Duration::from_secs(60),
            health: None,
            state_dir: PathBuf::from("/"),
            collector: observations::Collector::default(),
            log: None,
        }
    }
    pub fn snapshot(&self) -> Option<AppliedSnapshot> {
        self.applied
            .lock()
            .ok()
            .and_then(|state| state.snapshot.clone())
    }
    pub fn with_administration(
        mut self,
        transform: Arc<dyn administration::SnapshotTransform>,
        local: Option<Arc<dyn administration::LocalSnapshotSource>>,
        health: Arc<observations::Health>,
        state_dir: PathBuf,
        track: Duration,
        observations: Option<Duration>,
    ) -> Self {
        self.transform = Some(transform);
        self.local = local;
        self.health = Some(health);
        self.state_dir = state_dir;
        self.track_period = track;
        self.observation_period = observations;
        self
    }
    pub fn with_log(mut self, log: Arc<logging::Log>) -> Self {
        self.log = Some(log);
        self
    }
    pub fn with_status_period(mut self, period: Option<Duration>) -> Self {
        self.status_period = period;
        self
    }
    fn log(&self, level: &str, message: &str) {
        logging::emit(self.log.as_deref(), level, message);
    }
    pub fn metrics(&self) -> &RuntimeMetrics {
        &self.metrics
    }
    pub fn status(&self) -> KernelStatus {
        self.kernel.status()
    }
    pub fn panel(&self) -> &Panel {
        &self.panel
    }
    pub fn with_traffic(
        mut self,
        directory: &std::path::Path,
        period: Duration,
    ) -> Result<Self, RuntimeError> {
        if period.is_zero() {
            return Err(RuntimeError::Config);
        }
        self.outbox = Some(Arc::new(Mutex::new(Outbox::open(
            directory,
            self.panel.traffic_identity(),
        )?)));
        self.report_period = period;
        Ok(self)
    }

    pub async fn collect_traffic(&mut self) -> Result<(), RuntimeError> {
        let Some(outbox) = self.outbox.clone() else {
            return Ok(());
        };
        let kernel = Arc::clone(&self.kernel);
        let transaction = Arc::clone(&self.transaction);
        let closing = Arc::clone(&self.closing);
        let collected = tokio::task::spawn_blocking(move || {
            let _guard = transaction.lock().map_err(|_| RuntimeError::Worker)?;
            if closing.load(Ordering::Acquire) {
                return Err(RuntimeError::Closing);
            }
            if kernel.status() != KernelStatus::Ready {
                return Ok(false);
            }
            let Some(snapshot) = kernel.traffic_snapshot()? else {
                return Ok(false);
            };
            let collected = outbox
                .lock()
                .map_err(|_| RuntimeError::Worker)?
                .collect(&snapshot)?;
            kernel.traffic_ack(&snapshot)?;
            Ok::<_, RuntimeError>(collected)
        })
        .await
        .map_err(|_| RuntimeError::Worker)??;
        if collected {
            self.metrics.traffic_collected = self.metrics.traffic_collected.saturating_add(1);
        }
        Ok(())
    }

    pub async fn report_once(&mut self) -> Result<(), RuntimeError> {
        if self.closing.load(Ordering::Acquire) {
            return Err(RuntimeError::Closing);
        }
        let Some(outbox) = self.outbox.clone() else {
            return Ok(());
        };
        if let Err(error) = self.collect_traffic().await {
            self.log("error", &error.to_string());
        }
        let prepared = Arc::clone(&outbox);
        let transaction = Arc::clone(&self.transaction);
        let closing = Arc::clone(&self.closing);
        let batch = tokio::task::spawn_blocking(move || {
            let _guard = transaction.lock().map_err(|_| RuntimeError::Worker)?;
            if closing.load(Ordering::Acquire) {
                return Err(RuntimeError::Closing);
            }
            let mut outbox = prepared.lock().map_err(|_| RuntimeError::Worker)?;
            let Some(batch) = outbox.prepare()? else {
                return Ok(None);
            };
            outbox.sending(batch.id)?;
            Ok::<_, RuntimeError>(Some(batch))
        })
        .await
        .map_err(|_| RuntimeError::Worker)??;
        let Some(batch) = batch else {
            return Ok(());
        };
        let outcome = self.panel.report_traffic(&batch.traffic).await;
        tokio::task::spawn_blocking(move || {
            outbox
                .lock()
                .map_err(|_| RuntimeError::Worker)?
                .finish(batch.id, outcome)?;
            Ok::<_, RuntimeError>(())
        })
        .await
        .map_err(|_| RuntimeError::Worker)??;
        match outcome {
            ReportOutcome::Acknowledged => {
                self.metrics.traffic_reports = self.metrics.traffic_reports.saturating_add(1)
            }
            ReportOutcome::Uncertain => {
                self.metrics.traffic_uncertain = self.metrics.traffic_uncertain.saturating_add(1)
            }
            ReportOutcome::NotSent => {}
        }
        Ok(())
    }

    pub async fn sync_once(&mut self) -> Result<SyncResult, RuntimeError> {
        if self.closing.load(Ordering::Acquire) {
            return Err(RuntimeError::Closing);
        }
        self.metrics.sync_attempts = self.metrics.sync_attempts.saturating_add(1);
        if let Err(error) = self.collect_traffic().await {
            self.log("error", &error.to_string());
        }
        if let Err(error) = self.recover_if_stopped().await {
            self.log(
                "error",
                &format!("last-known-good recovery failed: {error}"),
            );
        }
        let generation = self
            .applied
            .lock()
            .map_err(|_| RuntimeError::Worker)?
            .generation;
        if generation != self.cache_generation {
            self.panel.invalidate_cache();
            self.cache_generation = generation;
        }
        let result = self.fetch_and_apply().await;
        if result.is_err() {
            self.panel.reject_config();
            self.panel.reject_users();
            if matches!(&result, Err(RuntimeError::CacheChanged)) {
                self.panel.invalidate_cache();
            }
            self.metrics.failed = self.metrics.failed.saturating_add(1);
        }
        result
    }

    async fn fetch_and_apply(&mut self) -> Result<SyncResult, RuntimeError> {
        let (config, users) = if let Some(source) = &self.local {
            let (config, users) = source.snapshot()?;
            (
                Fetch::Modified(config),
                Fetch::Modified(
                    users
                        .into_iter()
                        .map(|user| node_panel::User {
                            id: user.id,
                            uuid: user.uuid,
                            speed_limit: user.speed_limit,
                            device_limit: user.device_limit,
                        })
                        .collect(),
                ),
            )
        } else {
            (self.panel.config().await?, self.panel.users().await?)
        };
        let mut source_config = None;
        let candidate = if matches!((&config, &users), (Fetch::NotModified, Fetch::NotModified))
            && self.transform.is_none()
        {
            None
        } else {
            let (config, mut users, users_modified) = {
                let state = self.applied.lock().map_err(|_| RuntimeError::Worker)?;
                if (matches!(config, Fetch::NotModified) || matches!(users, Fetch::NotModified))
                    && state.generation != self.cache_generation
                {
                    return Err(RuntimeError::CacheChanged);
                }
                let config = match config {
                    Fetch::Modified(config) => config,
                    Fetch::NotModified => state
                        .source_config
                        .clone()
                        .or_else(|| {
                            state
                                .snapshot
                                .as_ref()
                                .map(|snapshot| snapshot.config.clone())
                        })
                        .ok_or(RuntimeError::MissingSnapshot)?,
                };
                let modified = matches!(users, Fetch::Modified(_));
                let users = match users {
                    Fetch::Modified(users) => users
                        .into_iter()
                        .map(|user| UserSpec {
                            id: user.id,
                            uuid: user.uuid,
                            speed_limit: user.speed_limit,
                            device_limit: user.device_limit,
                        })
                        .collect(),
                    Fetch::NotModified => state
                        .snapshot
                        .as_ref()
                        .ok_or(RuntimeError::MissingSnapshot)?
                        .users
                        .clone(),
                };
                (config, users, modified)
            };
            if users_modified {
                users.sort_unstable_by_key(|user| user.id);
            }
            if self.outbox.is_some() && users.iter().any(|user| user.id <= 0) {
                return Err(RuntimeError::InvalidSnapshot);
            }
            source_config = Some(config.clone());
            let config = match &self.transform {
                Some(transform) => transform.transform(config).await?,
                None => config,
            };
            Some(AppliedSnapshot::new(config, users).map_err(|_| RuntimeError::InvalidSnapshot)?)
        };
        let cache_generation = self.cache_generation;
        let kernel = Arc::clone(&self.kernel);
        let applied = Arc::clone(&self.applied);
        let transaction = Arc::clone(&self.transaction);
        let closing = Arc::clone(&self.closing);
        // The worker owns the snapshot commit, even if its awaiting future is cancelled.
        let (result, generation) = tokio::task::spawn_blocking(move || {
            let _guard = transaction.lock().map_err(|_| RuntimeError::Worker)?;
            if closing.load(Ordering::Acquire) {
                return Err(RuntimeError::Closing);
            }
            let candidate = match candidate {
                Some(candidate) => candidate,
                None => {
                    let state = applied.lock().map_err(|_| RuntimeError::Worker)?;
                    if state.generation != cache_generation {
                        return Err(RuntimeError::CacheChanged);
                    }
                    let snapshot = state
                        .snapshot
                        .as_ref()
                        .ok_or(RuntimeError::MissingSnapshot)?;
                    if kernel.status() == KernelStatus::Ready {
                        return Ok((SyncResult::Unchanged, state.generation));
                    }
                    // A child can fail while REST is in flight; preserve the restart path.
                    snapshot.clone()
                }
            };
            {
                let mut state = applied.lock().map_err(|_| RuntimeError::Worker)?;
                if state.snapshot.as_ref() == Some(&candidate)
                    && kernel.status() == KernelStatus::Ready
                {
                    if source_config.is_some() && state.source_config != source_config {
                        state.source_config = source_config;
                        state.generation = state.generation.saturating_add(1);
                    }
                    return Ok((SyncResult::Unchanged, state.generation));
                }
            }
            let prepared = kernel.prepare(&candidate.config, &candidate.users)?;
            if closing.load(Ordering::Acquire) {
                return Err(RuntimeError::Closing);
            }
            if let Err(error) = kernel.activate(prepared) {
                kernel.rollback()?;
                return Err(RuntimeError::Kernel(error));
            }
            let mut state = applied.lock().map_err(|_| RuntimeError::Worker)?;
            state.snapshot = Some(candidate);
            if source_config.is_some() {
                state.source_config = source_config;
            }
            state.generation = state.generation.saturating_add(1);
            Ok::<_, RuntimeError>((SyncResult::Applied, state.generation))
        })
        .await
        .map_err(|_| RuntimeError::Worker)??;
        self.panel.accept_config();
        self.panel.accept_users();
        self.cache_generation = generation;
        match result {
            SyncResult::Applied => self.metrics.applied = self.metrics.applied.saturating_add(1),
            SyncResult::Unchanged => {
                self.metrics.unchanged = self.metrics.unchanged.saturating_add(1)
            }
        }
        Ok(result)
    }

    async fn recover_if_stopped(&mut self) -> Result<(), RuntimeError> {
        let kernel = Arc::clone(&self.kernel);
        let applied = Arc::clone(&self.applied);
        let transaction = Arc::clone(&self.transaction);
        let closing = Arc::clone(&self.closing);
        let recovered = tokio::task::spawn_blocking(move || {
            let _guard = transaction.lock().map_err(|_| RuntimeError::Worker)?;
            if closing.load(Ordering::Acquire) {
                return Err(RuntimeError::Closing);
            }
            if kernel.status() == KernelStatus::Ready {
                return Ok(false);
            }
            let Some(snapshot) = applied
                .lock()
                .map_err(|_| RuntimeError::Worker)?
                .snapshot
                .clone()
            else {
                return Ok(false);
            };
            let prepared = kernel.prepare(&snapshot.config, &snapshot.users)?;
            if closing.load(Ordering::Acquire) {
                return Err(RuntimeError::Closing);
            }
            if let Err(error) = kernel.activate(prepared) {
                kernel.rollback()?;
                return Err(RuntimeError::Kernel(error));
            }
            Ok::<_, RuntimeError>(true)
        })
        .await
        .map_err(|_| RuntimeError::Worker)??;
        if recovered {
            self.metrics.recovered = self.metrics.recovered.saturating_add(1);
        }
        Ok(())
    }

    /// Ignore stale push payloads: the panel provides no cross-channel revision.
    pub fn push_hint(&mut self, event: &WsEvent) -> bool {
        let node_id = match event {
            WsEvent::Config { node_id, .. }
            | WsEvent::Users { node_id, .. }
            | WsEvent::UserDelta { node_id, .. }
            | WsEvent::Devices { node_id, .. } => *node_id,
        };
        self.push_node_hint(node_id)
    }

    fn push_node_hint(&mut self, node_id: Option<u32>) -> bool {
        if node_id != Some(self.node_id) {
            return false;
        }
        self.panel.invalidate_cache();
        self.metrics.push_resyncs = self.metrics.push_resyncs.saturating_add(1);
        true
    }

    pub async fn shutdown(&self) -> Result<(), RuntimeError> {
        self.closing.store(true, Ordering::Release);
        let kernel = Arc::clone(&self.kernel);
        let transaction = Arc::clone(&self.transaction);
        let outbox = self.outbox.clone();
        let log = self.log.clone();
        tokio::task::spawn_blocking(move || {
            let _guard = transaction.lock().map_err(|_| RuntimeError::Worker)?;
            // A supported native barrier ends all writers before final sampling.
            // Its durable store retains any bytes left by this bounded drain.
            let mut failure = None;
            if let Some(outbox) = outbox {
                let mut outbox = outbox.lock().map_err(|_| RuntimeError::Worker)?;
                if kernel.status() == KernelStatus::Ready {
                    if let Err(error)=kernel.traffic_quiesce() { failure=Some(RuntimeError::Kernel(error)); }
                    let started = std::time::Instant::now();
                    for batch_index in 0..128 {
                        if failure.is_some() { break; }
                        if started.elapsed() >= Duration::from_secs(1) {
                            logging::emit(log.as_deref(),"warn","final traffic drain budget reached; unsampled bytes may remain");
                            break;
                        }
                        match kernel.traffic_snapshot() {
                        Ok(Some(snapshot)) => match outbox.collect(&snapshot) {
                            Ok(_) => {
                                if let Err(error) = kernel.traffic_ack(&snapshot) {
                                    failure = Some(RuntimeError::Kernel(error));
                                }
                            }
                            Err(error) => failure = Some(RuntimeError::Traffic(error)),
                        },
                        Ok(None) => break,
                        Err(error) => failure = Some(RuntimeError::Kernel(error)),
                    }
                        if failure.is_some() { break; }
                        if batch_index == 127 { logging::emit(log.as_deref(),"warn","final traffic drain batch limit reached; unsampled bytes may remain"); }
                    }
                }
                if let Err(error) = outbox.abandon_sending() {
                    failure = Some(RuntimeError::Traffic(error));
                }
            }
            kernel.stop()?;
            if let Some(error) = failure {
                return Err(error);
            }
            Ok::<_, RuntimeError>(())
        })
        .await
        .map_err(|_| RuntimeError::Worker)??;
        Ok(())
    }

    pub async fn run(
        &mut self,
        poll: Duration,
        ws: Option<WsClient>,
        mut stop: watch::Receiver<bool>,
    ) -> Result<(), RuntimeError> {
        if poll.is_zero() {
            return Err(RuntimeError::Config);
        }
        let (tx, mut rx) = mpsc::channel(1);
        let (ws_stop_tx, ws_stop_rx) = watch::channel(*stop.borrow());
        let mut ws_task = ws.map(|client| {
            owned_task::Task::new(tokio::spawn(async move {
                client.run_hints(ws_stop_rx, tx).await
            }))
        });
        let mut queue_open = ws_task.is_some();
        let mut interval = tokio::time::interval(poll);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut report_interval = tokio::time::interval(self.report_period);
        report_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut track = tokio::time::interval(self.track_period);
        track.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut observations =
            tokio::time::interval(self.observation_period.unwrap_or(Duration::from_secs(60)));
        observations.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut status_interval =
            tokio::time::interval(self.status_period.unwrap_or(Duration::from_secs(60)));
        status_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let _ = self.collector.sample(&self.state_dir);
        while !*stop.borrow() {
            let should_sync = tokio::select! {
                changed = stop.changed() => {
                    if changed.is_err() || *stop.borrow() { break; }
                    false
                }
                _ = interval.tick() => true,
                _ = track.tick(), if self.outbox.is_some() => {
                    let result=tokio::select! {_=stop.changed()=>{break;}, result=self.collect_traffic()=>result};
                    if let Err(error)=result {self.log("error",&error.to_string());} false
                },
                _=observations.tick(),if self.observation_period.is_some()=>{
                    let result=tokio::select! {_=stop.changed()=>{break;},result=self.report_observations()=>result};
                    if let Err(error)=result {self.log("error",&error.to_string());} false
                },
                _=status_interval.tick(),if self.status_period.is_some() && self.local.is_none()=>{
                    let result=tokio::select! {_=stop.changed()=>{break;},result=self.report_status()=>result};
                    if let Err(error)=result {self.log("error",&error.to_string());}false
                },
                _ = report_interval.tick(), if self.outbox.is_some() => {
                    let result = tokio::select! {
                        biased;
                        _ = stop.changed() => { break; },
                        result = self.report_once() => result,
                    };
                    if let Err(error) = result { self.log("error",&error.to_string()); }
                    false
                },
                event = rx.recv(), if queue_open => {
                    match event {
                        None => { queue_open = false; self.log("warn","websocket stopped; REST polling remains active"); false }
                        Some(event) => {
                            let mut dirty = self.push_node_hint(event.node_id);
                            // Coalesce a burst before refetching; preserve a bounded queue.
                            tokio::select! {
                                _ = tokio::time::sleep(Duration::from_millis(250)) => {}
                                _ = stop.changed() => {}
                            }
                            while let Ok(event) = rx.try_recv() { dirty |= self.push_node_hint(event.node_id); }
                            dirty && !*stop.borrow()
                        }
                    }
                }
            };
            if let Some(health) = &self.health {
                health.update(
                    self.status() == KernelStatus::Ready && self.snapshot().is_some(),
                    &self.metrics,
                    None,
                );
            }
            if should_sync {
                let result = tokio::select! {
                    biased;
                    changed = stop.changed() => {
                        if changed.is_err() || *stop.borrow() { break; }
                        continue;
                    }
                    result = self.sync_once() => result,
                };
                if let Err(error) = result {
                    self.log("error", &error.to_string());
                }
                if let Some(health) = &self.health {
                    health.update(
                        self.status() == KernelStatus::Ready && self.snapshot().is_some(),
                        &self.metrics,
                        None,
                    );
                }
            }
        }
        // Signal closing before awaiting the WS task, including a cancelled kernel worker.
        self.closing.store(true, Ordering::Release);
        let _ = ws_stop_tx.send(true);
        if let Some(mut task) = ws_task.take()
            && tokio::time::timeout(Duration::from_secs(2), &mut task)
                .await
                .is_err()
        {
            task.abort();
            let _ = task.await;
        }
        let result = self.shutdown().await;
        if !self.last_active.is_empty() {
            let mut empty = node_core::ActivitySnapshot::default();
            for id in &self.last_active {
                empty.alive.insert(*id, Vec::new());
                empty.online.insert(*id, 0);
            }
            if !matches!(
                tokio::time::timeout(Duration::from_secs(3), self.panel.report_activity(&empty))
                    .await,
                Ok(Ok(()))
            ) {
                self.log("warn", "final online-IP clearing was not acknowledged");
            }
        }
        if let Some(health) = &self.health {
            health.update(false, &self.metrics, Some(0));
        }
        result
    }
    async fn report_observations(&mut self) -> Result<(), RuntimeError> {
        if self.status() != KernelStatus::Ready {
            return Ok(());
        }
        let kernel = Arc::clone(&self.kernel);
        let mut activity = tokio::task::spawn_blocking(move || kernel.activity())
            .await
            .map_err(|_| RuntimeError::Worker)??;
        if let Some(health) = &self.health {
            health.update(true, &self.metrics, Some(activity.sessions));
        }
        if self.local.is_some() {
            return Ok(());
        }
        let current = activity.alive.keys().copied().collect();
        for id in self.last_active.difference(&current) {
            activity.alive.insert(*id, Vec::new());
            activity.online.insert(*id, 0);
        }
        self.panel.report_activity(&activity).await?;
        self.last_active = current;
        Ok(())
    }
    async fn report_status(&mut self) -> Result<(), RuntimeError> {
        if self.status() != KernelStatus::Ready {
            return Ok(());
        }
        let status = self.collector.sample(&self.state_dir);
        // CPU requires two actual samples. Never send an invented zero.
        if status.get("cpu").is_none() || status.get("mem").is_none() {
            return Ok(());
        }
        let kernel = Arc::clone(&self.kernel);
        let activity = tokio::task::spawn_blocking(move || kernel.activity())
            .await
            .map_err(|_| RuntimeError::Worker)??;
        self.panel.report_status(status,serde_json::json!({"rust_runtime":self.metrics,"active_connections":activity.sessions,"active_users":activity.alive.len(),"kernel_status":true})).await?;
        Ok(())
    }
}

impl<K: ManagedKernel> Drop for NodeRuntime<K> {
    fn drop(&mut self) {
        self.closing.store(true, Ordering::Release);
    }
}
