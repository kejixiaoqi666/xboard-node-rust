//! One local health listener for the nodes belonging to a Go instance.
//!
//! Validate before preparing nodes. Preparation transfers ownership of health
//! ports to the groups, while each runtime keeps updating its own Health.
use crate::{RuntimeError, RuntimeMetrics, administration::PreparedNode, observations::Health};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::sync::watch;

/// A port can belong to only one instance. Node IDs must be unique within that
/// port because the public per-node metrics are indexed by the panel node ID.
pub fn validate(nodes: &[PreparedNode]) -> Result<(), RuntimeError> {
    let mut ports: BTreeMap<u16, (&str, BTreeSet<u32>)> = BTreeMap::new();
    for node in nodes {
        let Some(settings) = &node.settings else {
            continue;
        };
        if settings.health_port == 0 {
            continue;
        }
        if settings.instance_id.trim().is_empty() {
            return Err(RuntimeError::Administration(
                "health instance identity missing",
            ));
        }
        let (instance, ids) = ports
            .entry(settings.health_port)
            .or_insert_with(|| (settings.instance_id.as_str(), BTreeSet::new()));
        if *instance != settings.instance_id {
            return Err(RuntimeError::Administration(
                "health port belongs to different instances",
            ));
        }
        if !ids.insert(node.runtime.node_id) {
            return Err(RuntimeError::Administration(
                "duplicate node ID in health group",
            ));
        }
    }
    Ok(())
}

struct Child {
    instance_id: String,
    node_id: u32,
    health: Arc<Health>,
}

/// The sole owner of a shared health port. The runtime owner must retain and
/// join the spawned run task, passing the same shutdown signal as its nodes.
pub struct Group {
    pub port: u16,
    children: Vec<Child>,
}

/// Transfer positive health ports to groups in stable port order. Call validate
/// first; run also checks its invariants if preparation was called directly.
pub fn prepare(nodes: &mut [PreparedNode]) -> Vec<Group> {
    let mut groups: BTreeMap<u16, Group> = BTreeMap::new();
    for node in nodes {
        let Some(settings) = &mut node.settings else {
            continue;
        };
        let port = settings.health_port;
        if port == 0 {
            continue;
        }
        groups
            .entry(port)
            .or_insert_with(|| Group {
                port,
                children: Vec::new(),
            })
            .children
            .push(Child {
                instance_id: settings.instance_id.clone(),
                node_id: node.runtime.node_id,
                health: Arc::clone(&node.health),
            });
        settings.health_port = 0;
    }
    groups.into_values().collect()
}

impl Group {
    fn validate(&self) -> Result<(), RuntimeError> {
        let Some(first) = self.children.first() else {
            return Err(RuntimeError::Administration("empty health group"));
        };
        if self.port == 0 || first.instance_id.trim().is_empty() {
            return Err(RuntimeError::Administration(
                "invalid health group identity or port",
            ));
        }
        let mut ids = BTreeSet::new();
        for child in &self.children {
            if child.instance_id != first.instance_id {
                return Err(RuntimeError::Administration(
                    "health port belongs to different instances",
                ));
            }
            if !ids.insert(child.node_id) {
                return Err(RuntimeError::Administration(
                    "duplicate node ID in health group",
                ));
            }
        }
        Ok(())
    }

    fn sample(&self, aggregate: &Health) {
        let mut metrics = BTreeMap::new();
        let mut total = RuntimeMetrics::default();
        let mut ready = 0;
        let mut sessions = 0u64;
        let mut activity = BTreeMap::new();
        let mut activity_sample_unix = BTreeMap::new();
        for child in &self.children {
            if let Ok(state) = child.health.0.lock() {
                ready += usize::from(state.ready);
                sessions = sessions.saturating_add(state.sessions);
                add_metrics(&mut total, &state.metrics);
                metrics.insert(child.node_id, state.metrics.clone());
                if let Some(audit) = &state.activity_audit {
                    activity.insert(child.node_id, audit.clone());
                }
                if let Some(sample_unix) = state.activity_sample_unix {
                    activity_sample_unix.insert(child.node_id, sample_unix);
                }
            }
        }
        // Commit all fields under one lock: HTTP readers see the totals and
        // individual metrics from the same sample, even during a refresh.
        if let Ok(mut state) = aggregate.0.lock() {
            let count = self.children.len();
            state.ready = count > 0 && ready == count;
            state.nodes = Some(count);
            state.ready_nodes = Some(ready);
            state.desired_nodes = Some(count);
            state.rejected_nodes = Some(0);
            state.sessions = sessions;
            state.node_metrics = metrics;
            state.activity_valid = None;
            state.activity_sample_unix = None;
            state.activity_audit = None;
            state.node_activity = activity;
            state.node_activity_sample_unix = activity_sample_unix;
            state.metrics = total;
            state.updated_unix = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
        }
    }

    /// Serve the current leaf observations on localhost. A closed shutdown
    /// channel also stops the listener; aborting this future drops its Server,
    /// whose RAII guard closes the listener rather than detaching it.
    pub async fn run(self, mut stop: watch::Receiver<bool>) -> Result<(), RuntimeError> {
        self.validate()?;
        if *stop.borrow() || stop.has_changed().is_err() {
            return Ok(());
        }
        let health = Arc::new(Health::default());
        self.sample(&health);
        let server = Arc::clone(&health)
            .listen(self.port)
            .await
            .map_err(|_| RuntimeError::Administration("health port unavailable"))?;
        let mut interval = tokio::time::interval(Duration::from_secs(1));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                changed = stop.changed() => {
                    if changed.is_err() || *stop.borrow() {
                        break;
                    }
                }
                _ = interval.tick() => self.sample(&health),
            }
        }
        // Stop accepting health requests, abort any bounded request workers,
        // and await the listener before returning to the fleet owner.
        server.shutdown().await;
        Ok(())
    }
}

fn add_metrics(total: &mut RuntimeMetrics, node: &RuntimeMetrics) {
    total.sync_attempts = total.sync_attempts.saturating_add(node.sync_attempts);
    total.applied = total.applied.saturating_add(node.applied);
    total.unchanged = total.unchanged.saturating_add(node.unchanged);
    total.failed = total.failed.saturating_add(node.failed);
    total.push_resyncs = total.push_resyncs.saturating_add(node.push_resyncs);
    total.recovered = total.recovered.saturating_add(node.recovered);
    total.cache_recoveries = total.cache_recoveries.saturating_add(node.cache_recoveries);
    total.cache_write_failures = total
        .cache_write_failures
        .saturating_add(node.cache_write_failures);
    total.traffic_collected = total
        .traffic_collected
        .saturating_add(node.traffic_collected);
    total.traffic_reports = total.traffic_reports.saturating_add(node.traffic_reports);
    total.traffic_uncertain = total
        .traffic_uncertain
        .saturating_add(node.traffic_uncertain);
    total.traffic_not_sent = total.traffic_not_sent.saturating_add(node.traffic_not_sent);
    for (total_bytes, node_bytes) in total
        .traffic_bytes_collected
        .iter_mut()
        .zip(node.traffic_bytes_collected)
    {
        *total_bytes = total_bytes.saturating_add(node_bytes);
    }
    for (total_bytes, node_bytes) in total
        .traffic_bytes_acknowledged
        .iter_mut()
        .zip(node.traffic_bytes_acknowledged)
    {
        *total_bytes = total_bytes.saturating_add(node_bytes);
    }
    for (total_bytes, node_bytes) in total
        .traffic_bytes_uncertain
        .iter_mut()
        .zip(node.traffic_bytes_uncertain)
    {
        *total_bytes = total_bytes.saturating_add(node_bytes);
    }
    for (total_bytes, node_bytes) in total
        .traffic_bytes_not_sent
        .iter_mut()
        .zip(node.traffic_bytes_not_sent)
    {
        *total_bytes = total_bytes.saturating_add(node_bytes);
    }
    total.activity_samples = total.activity_samples.saturating_add(node.activity_samples);
    total.activity_rejected = total
        .activity_rejected
        .saturating_add(node.activity_rejected);
}
