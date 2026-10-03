//! Runtime hooks for imported configuration, private secrets and certificates.
use crate::{RuntimeConfig, RuntimeError};
use async_trait::async_trait;
use node_admin::{CertConfig, CertificateManager, ChallengeStore, NodeConfig, SecretResolver};
use node_core::{NodeSpec, UserSpec};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio::{
    net::TcpListener,
    sync::{Mutex, watch},
};

#[async_trait]
pub trait SnapshotTransform: Send + Sync {
    async fn transform(&self, node: NodeSpec) -> Result<NodeSpec, RuntimeError>;
}
pub trait LocalSnapshotSource: Send + Sync {
    fn snapshot(&self) -> Result<(NodeSpec, Vec<UserSpec>), RuntimeError>;
}

pub const RUNTIME_FEATURES: &[&str] = &[
    "node_intervals",
    "websocket_tuning",
    "kernel_settings",
    "logging",
    "health_endpoint",
    "standalone",
    "machine_discovery",
    "xray_kernel",
    "custom_outbound",
    "custom_route",
    "custom_config",
    "certificate_lifecycle",
];

pub struct Services {
    pub secrets: Arc<dyn SecretResolver>,
    challenges: ChallengeStore,
    servers: Mutex<
        BTreeMap<u16, crate::OwnedTask<Result<(), node_admin::certificate::CertificateError>>>,
    >,
    stop: watch::Receiver<bool>,
}
impl Services {
    pub fn new(secrets: Arc<dyn SecretResolver>, stop: watch::Receiver<bool>) -> Arc<Self> {
        Arc::new(Self {
            secrets,
            challenges: ChallengeStore::default(),
            servers: Mutex::new(BTreeMap::new()),
            stop,
        })
    }
    async fn http(&self, port: u16) -> Result<(), RuntimeError> {
        let mut servers = self.servers.lock().await;
        if let Some(task) = servers.get(&port) {
            return if task.is_finished() {
                Err(RuntimeError::Administration(
                    "HTTP challenge listener stopped",
                ))
            } else {
                Ok(())
            };
        }
        let listener = TcpListener::bind((std::net::Ipv4Addr::UNSPECIFIED, port))
            .await
            .map_err(|_| RuntimeError::Administration("HTTP challenge port unavailable"))?;
        let store = self.challenges.clone();
        let mut stop = self.stop.clone();
        servers.insert(
            port,
            crate::OwnedTask::new(tokio::spawn(async move {
                store.serve_listener(listener, &mut stop).await
            })),
        );
        Ok(())
    }
    pub async fn join(&self) {
        let tasks = std::mem::take(&mut *self.servers.lock().await);
        for (_, mut task) in tasks {
            if tokio::time::timeout(std::time::Duration::from_secs(3), &mut task)
                .await
                .is_err()
            {
                task.abort();
                let _ = task.await;
            }
        }
    }
}

pub struct Hook {
    settings: Option<NodeConfig>,
    state_dir: PathBuf,
    services: Arc<Services>,
    manager: CertificateManager,
}
impl Hook {
    pub fn new(
        settings: Option<NodeConfig>,
        state_dir: PathBuf,
        services: Arc<Services>,
    ) -> Arc<Self> {
        let manager = CertificateManager::new(services.challenges.clone())
            .with_secrets(services.secrets.clone());
        Arc::new(Self {
            settings,
            state_dir,
            services,
            manager,
        })
    }
}
#[async_trait]
impl SnapshotTransform for Hook {
    async fn transform(&self, mut node: NodeSpec) -> Result<NodeSpec, RuntimeError> {
        if node.protocol == "hysteria" && node.version == 2 {
            node.protocol = "hysteria2".into();
        }
        let mut cert = if let Some(settings) =
            self.settings.as_ref().filter(|s| s.cert.mode() != "none")
        {
            settings.cert.clone()
        } else if let Some(value) = &node.cert_config {
            serde_json::from_value(value.clone())
                .map_err(|_| RuntimeError::Administration("invalid panel certificate settings"))?
        } else {
            CertConfig::default()
        };
        if cert.domain.is_empty() {
            cert.domain = node
                .domain
                .clone()
                .or_else(|| node.server_name.clone())
                .unwrap_or_default();
        }
        if node.auto_tls && cert.mode() == "none" {
            cert.auto_tls = true;
        }
        if cert.cert_dir.is_none() {
            cert.cert_dir = Some(self.state_dir.join("certs"));
        }
        cert.validate()
            .map_err(|_| RuntimeError::Administration("invalid certificate settings"))?;
        if cert.mode() == "http" {
            self.services.http(cert.http_port()).await?;
        }
        if let Some(files) = self
            .manager
            .ensure(&cert, &self.state_dir.join("certs"))
            .await
            .map_err(|_| {
                RuntimeError::Administration("certificate issue, validation or renewal failed")
            })?
        {
            node.cert_config =
                Some(json!({"cert_mode":"file","cert_file":files.cert,"key_file":files.key}));
            node.tls = 1;
            if node.server_name.is_none() && !cert.domain.is_empty() {
                node.server_name = Some(cert.domain.clone());
            }
        }
        node.auto_tls = false;
        node.domain = None;
        if let Some(settings) = &self.settings {
            node.kernel_type = Some("singbox".into());
            node.kernel_log_level = Some(settings.kernel.log_level.clone());
            let mut outbounds = settings
                .kernel
                .resolve_custom_outbound(self.services.secrets.as_ref())
                .map_err(|_| {
                    RuntimeError::Administration("custom outbound secrets missing or invalid")
                })?;
            let mut routes = settings
                .kernel
                .resolve_custom_route(self.services.secrets.as_ref())
                .map_err(|_| {
                    RuntimeError::Administration("custom routing secrets missing or invalid")
                })?;
            if let Some(path) = &settings.kernel.custom_config {
                let template = read_json(path)?;
                let object = template.as_object().ok_or(RuntimeError::Administration(
                    "custom template requires an object",
                ))?;
                if object.keys().any(|k| {
                    !matches!(
                        k.as_str(),
                        "outbounds" | "route" | "routing" | "dns" | "log"
                    )
                }) {
                    return Err(RuntimeError::Administration(
                        "custom template contains unsupported root settings",
                    ));
                }
                if let Some(value) = object.get("log") {
                    let log = value
                        .as_object()
                        .ok_or(RuntimeError::Administration("invalid template log"))?;
                    if log
                        .keys()
                        .any(|key| key != "level" && key != "loglevel" && key != "timestamp")
                        || log
                            .get("timestamp")
                            .is_some_and(|value| value != &json!(true))
                    {
                        return Err(RuntimeError::Administration(
                            "unsupported template log settings",
                        ));
                    }
                    if let Some(level) = log.get("level").or_else(|| log.get("loglevel")) {
                        node.kernel_log_level = Some(
                            level
                                .as_str()
                                .ok_or(RuntimeError::Administration("invalid template log level"))?
                                .to_owned(),
                        );
                    }
                }
                if let Some(value) = object.get("outbounds") {
                    outbounds.extend(
                        value
                            .as_array()
                            .ok_or(RuntimeError::Administration("invalid template outbounds"))?
                            .clone(),
                    );
                }
                for key in ["route", "routing"] {
                    if let Some(value) = object.get(key) {
                        let section = value
                            .as_object()
                            .ok_or(RuntimeError::Administration("invalid template routing"))?;
                        if section.keys().any(|key| key != "rules") {
                            return Err(RuntimeError::Administration(
                                "template routing options must use explicit native rules",
                            ));
                        }
                        routes.extend(
                            section
                                .get("rules")
                                .and_then(Value::as_array)
                                .ok_or(RuntimeError::Administration("invalid template rules"))?
                                .clone(),
                        );
                    }
                }
            }
            for value in outbounds {
                node.custom_outbounds.push(outbound(value)?);
            }
            node.custom_routes.extend(routes);
        }
        Ok(node)
    }
}
fn outbound(mut value: Value) -> Result<node_core::OutboundConfig, RuntimeError> {
    let object = value
        .as_object_mut()
        .ok_or(RuntimeError::Administration("invalid custom outbound"))?;
    if object.contains_key("protocol") {
        return serde_json::from_value(value)
            .map_err(|_| RuntimeError::Administration("invalid custom outbound"));
    }
    let protocol = object
        .remove("type")
        .and_then(|v| v.as_str().map(str::to_owned))
        .ok_or(RuntimeError::Administration("custom outbound type missing"))?;
    let tag = object
        .remove("tag")
        .and_then(|v| v.as_str().map(str::to_owned))
        .ok_or(RuntimeError::Administration("custom outbound tag missing"))?;
    let proxy_tag = object
        .remove("detour")
        .and_then(|v| v.as_str().map(str::to_owned));
    Ok(node_core::OutboundConfig {
        tag,
        protocol,
        settings: value,
        proxy_tag,
    })
}
fn read_json(path: &Path) -> Result<Value, RuntimeError> {
    use std::io::Read;
    let meta = std::fs::symlink_metadata(path)
        .map_err(|_| RuntimeError::Administration("custom template unavailable"))?;
    if !path.is_absolute() || !meta.is_file() || meta.len() > 4 * 1024 * 1024 {
        return Err(RuntimeError::Administration(
            "invalid custom template path or size",
        ));
    }
    let mut data = Vec::new();
    std::fs::File::open(path)
        .map_err(|_| RuntimeError::Administration("custom template unavailable"))?
        .take(4 * 1024 * 1024 + 1)
        .read_to_end(&mut data)
        .map_err(|_| RuntimeError::Administration("custom template read failed"))?;
    if data.len() > 4 * 1024 * 1024 {
        return Err(RuntimeError::Administration("custom template too large"));
    }
    serde_json::from_slice(&data)
        .map_err(|_| RuntimeError::Administration("custom template JSON invalid"))
}

pub struct LocalSource {
    pub reference: node_admin::import::StandaloneRef,
    pub secrets: Arc<dyn SecretResolver>,
}
impl LocalSnapshotSource for LocalSource {
    fn snapshot(&self) -> Result<(NodeSpec, Vec<UserSpec>), RuntimeError> {
        let snapshot = self
            .reference
            .resolve(self.secrets.as_ref())
            .map_err(|_| RuntimeError::Administration("standalone snapshot missing or invalid"))?;
        Ok((snapshot.node, snapshot.users))
    }
}

#[derive(Clone)]
pub struct PreparedNode {
    pub runtime: RuntimeConfig,
    pub settings: Option<NodeConfig>,
    pub health: Arc<crate::observations::Health>,
}
impl PreparedNode {
    pub fn simple(runtime: RuntimeConfig) -> Self {
        Self {
            runtime,
            settings: None,
            health: Arc::new(crate::observations::Health::default()),
        }
    }
    pub fn imported(settings: NodeConfig) -> Result<Self, RuntimeError> {
        let mut runtime: RuntimeConfig = serde_json::from_value(settings.runtime.clone())
            .map_err(|_| RuntimeError::Administration("invalid imported runtime settings"))?;
        runtime.embedded = true;
        if settings.intervals.pull_interval > 0 {
            runtime.poll_seconds = settings.intervals.pull_interval;
        }
        if settings.intervals.push_interval > 0 {
            runtime.report_seconds = settings.intervals.push_interval;
        }
        if settings.standalone.is_some() {
            runtime.panel_url = "https://standalone.invalid".into();
            runtime.node_type = Some("standalone".into());
            runtime.websocket = false;
            runtime.traffic_reporting = Some(false);
        }
        if let Some(path) = &settings.kernel.custom_config {
            let template = read_json(path)?;
            if let Some(dns) = template.get("dns") {
                runtime.dns =
                    Some(serde_json::from_value(dns.clone()).map_err(|_| {
                        RuntimeError::Administration("invalid template DNS settings")
                    })?);
            }
        }
        runtime.validate()?;
        for period in [
            settings.intervals.push_interval,
            settings.intervals.pull_interval,
            settings.intervals.track_interval,
            settings.intervals.device_report_interval,
            settings.websocket.status_interval,
            settings.websocket.handshake_timeout,
            settings.websocket.backoff_initial,
            settings.websocket.backoff_max,
            settings.websocket.discovery_interval,
        ] {
            if period > 3600 {
                return Err(RuntimeError::Administration(
                    "interval exceeds 3600 seconds",
                ));
            }
        }
        if !matches!(
            settings.kernel.kind.as_str(),
            "singbox" | "sing-box" | "xray"
        ) {
            return Err(RuntimeError::Administration("unknown imported kernel mode"));
        }
        Ok(Self {
            runtime,
            settings: Some(settings),
            health: Arc::new(crate::observations::Health::default()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{net::Ipv4Addr, time::Duration};

    struct NoSecrets;
    impl SecretResolver for NoSecrets {
        fn get(&self, _: &str) -> Option<node_admin::Secret> {
            None
        }
    }

    struct AbortOnDrop(tokio::task::AbortHandle);
    impl Drop for AbortOnDrop {
        fn drop(&mut self) {
            self.0.abort();
        }
    }

    async fn challenge_fixture() -> (Arc<Services>, watch::Sender<bool>, AbortOnDrop, u16) {
        let (stop, stop_rx) = watch::channel(false);
        let service = Services::new(Arc::new(NoSecrets), stop_rx);
        // Exercise the actual Services task ownership with a loopback-only
        // listener; no CA request or externally accessible challenge port.
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let store = service.challenges.clone();
        let mut stop_rx = service.stop.clone();
        let task = tokio::spawn(async move { store.serve_listener(listener, &mut stop_rx).await });
        let abort = AbortOnDrop(task.abort_handle());
        service
            .servers
            .lock()
            .await
            .insert(port, crate::OwnedTask::new(task));
        (service, stop, abort, port)
    }

    async fn port_released(port: u16, budget: Duration) -> bool {
        tokio::time::timeout(budget, async {
            loop {
                if let Ok(listener) = TcpListener::bind((Ipv4Addr::LOCALHOST, port)).await {
                    drop(listener);
                    return;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .is_ok()
    }

    async fn cleanup_challenge(stop: watch::Sender<bool>, abort: AbortOnDrop, port: u16) {
        let _ = stop.send(true);
        if !port_released(port, Duration::from_secs(2)).await {
            abort.0.abort();
        }
        assert!(
            port_released(port, Duration::from_secs(2)).await,
            "fixture cleanup must release its loopback port"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn service_owner_drop_releases_its_challenge_listener() {
        let (service, stop, abort, port) = challenge_fixture().await;
        drop(service);
        // Keep the stop sender alive: task ownership must release the listener
        // even when main's signal task or another service holds a sender.
        let closed = port_released(port, Duration::from_millis(200)).await;
        cleanup_challenge(stop, abort, port).await;
        assert!(closed, "dropping Services detached its challenge listener");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancelled_service_join_releases_drained_challenge_tasks() {
        let (service, stop, abort, port) = challenge_fixture().await;
        {
            let joining = service.join();
            tokio::pin!(joining);
            tokio::select! {
                _ = &mut joining => panic!("listener should still be waiting for stop"),
                _ = tokio::time::sleep(Duration::from_millis(20)) => {}
            }
        }
        let drained = service.servers.lock().await.is_empty();
        drop(service);
        let closed = port_released(port, Duration::from_millis(200)).await;
        cleanup_challenge(stop, abort, port).await;
        assert!(drained, "join must have taken ownership of the task map");
        assert!(closed, "cancelling Services::join detached its listener");
    }
}
