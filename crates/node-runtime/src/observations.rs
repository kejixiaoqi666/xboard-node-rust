//! Measured Linux host status and local health. No synthetic load measurements.
use crate::RuntimeMetrics;
use serde::Serialize;
use serde_json::{Value, json};
use std::{
    path::Path,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::watch,
    task::JoinSet,
};

#[derive(Default, Serialize)]
pub struct HealthState {
    pub ready: bool,
    pub updated_unix: u64,
    pub metrics: RuntimeMetrics,
    pub sessions: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nodes: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ready_nodes: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub desired_nodes: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rejected_nodes: Option<usize>,
    #[serde(skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub node_metrics: std::collections::BTreeMap<u32, RuntimeMetrics>,
}
#[derive(Default)]
pub struct Health(pub Mutex<HealthState>);
impl Health {
    pub fn update(&self, ready: bool, metrics: &RuntimeMetrics, sessions: Option<u64>) {
        if let Ok(mut state) = self.0.lock() {
            state.ready = ready;
            state.updated_unix = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            state.metrics = metrics.clone();
            if let Some(sessions) = sessions {
                state.sessions = sessions;
            }
        }
    }
    pub fn update_fleet(
        &self,
        children: impl IntoIterator<Item = (u32, Arc<Health>)>,
        discovery_ready: bool,
    ) {
        let mut count = 0;
        let mut ready = 0;
        let mut sessions = 0u64;
        let mut metrics = std::collections::BTreeMap::new();
        for (id, child) in children {
            count += 1;
            if let Ok(state) = child.0.lock() {
                ready += usize::from(state.ready);
                sessions = sessions.saturating_add(state.sessions);
                metrics.insert(id, state.metrics.clone());
            }
        }
        if let Ok(mut state) = self.0.lock() {
            let desired = state.desired_nodes.unwrap_or(count);
            state.ready = discovery_ready && count > 0 && count == ready && count == desired;
            state.nodes = Some(count);
            state.ready_nodes = Some(ready);
            state.rejected_nodes = Some(desired.saturating_sub(count));
            state.sessions = sessions;
            let mut total = RuntimeMetrics::default();
            for node in metrics.values() {
                total.sync_attempts = total.sync_attempts.saturating_add(node.sync_attempts);
                total.applied = total.applied.saturating_add(node.applied);
                total.unchanged = total.unchanged.saturating_add(node.unchanged);
                total.failed = total.failed.saturating_add(node.failed);
                total.push_resyncs = total.push_resyncs.saturating_add(node.push_resyncs);
                total.recovered = total.recovered.saturating_add(node.recovered);
                total.traffic_collected = total
                    .traffic_collected
                    .saturating_add(node.traffic_collected);
                total.traffic_reports = total.traffic_reports.saturating_add(node.traffic_reports);
                total.traffic_uncertain = total
                    .traffic_uncertain
                    .saturating_add(node.traffic_uncertain);
            }
            state.metrics = total;
            state.node_metrics = metrics;
            state.updated_unix = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
        }
    }
    pub fn expect_nodes(&self, desired: usize) {
        if let Ok(mut state) = self.0.lock() {
            state.desired_nodes = Some(desired);
        }
    }
    pub async fn listen(self: Arc<Self>, port: u16) -> std::io::Result<Server> {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port)).await?;
        let (stop, rx) = watch::channel(false);
        let task = tokio::spawn(self.serve(listener, rx));
        Ok(Server {
            stop,
            task: Some(task),
        })
    }
    pub async fn serve(
        self: Arc<Self>,
        listener: TcpListener,
        mut stop: watch::Receiver<bool>,
    ) -> std::io::Result<()> {
        let mut tasks = JoinSet::new();
        while !*stop.borrow() {
            tokio::select! {
                changed=stop.changed()=>{if changed.is_err(){break;}},
                _=tasks.join_next(),if !tasks.is_empty()=>{},
                accepted=listener.accept(),if tasks.len()<32=>{
                    let (mut stream,_)=accepted?;let health=self.clone();
                    tasks.spawn(async move {
                        let _=tokio::time::timeout(std::time::Duration::from_secs(2),async {
                            let mut bytes=[0;2048];let size=stream.read(&mut bytes).await?;
                            let line=std::str::from_utf8(&bytes[..size]).ok().and_then(|s|s.split("\r\n").next());
                            let (status,body)={
                            let state=health.0.lock().map_err(|_|std::io::Error::other("health state unavailable"))?;
                            match line {
                                Some("GET /healthz HTTP/1.1"|"GET /healthz HTTP/1.0")=>(if state.ready {"200 OK"} else {"503 Service Unavailable"},json!({"ready":state.ready,"updated_unix":state.updated_unix})),
                                Some("GET /metrics HTTP/1.1"|"GET /metrics HTTP/1.0")=>("200 OK",serde_json::to_value(&*state).map_err(std::io::Error::other)?),
                                _=>("404 Not Found",json!({"error":"not found"})),
                            }
                            };
                            let body=body.to_string();let response=format!("HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len());
                            stream.write_all(response.as_bytes()).await?;stream.shutdown().await
                        }).await;
                    });
                },
            }
        }
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
        Ok(())
    }
}

/// A failed or cancelled owner cannot leave its health listener behind.
pub struct Server {
    stop: watch::Sender<bool>,
    task: Option<tokio::task::JoinHandle<std::io::Result<()>>>,
}
impl Server {
    pub async fn shutdown(mut self) {
        let _ = self.stop.send(true);
        if let Some(mut task) = self.task.take()
            && tokio::time::timeout(std::time::Duration::from_secs(3), &mut task)
                .await
                .is_err()
        {
            task.abort();
            let _ = task.await;
        }
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.stop.send(true);
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}

#[derive(Default)]
pub struct Collector {
    previous_cpu: Option<(u64, u64)>,
}
impl Collector {
    pub fn sample(&mut self, path: &Path) -> Value {
        let mut status = serde_json::Map::new();
        #[cfg(target_os = "linux")]
        {
            if let Ok(data) = std::fs::read_to_string("/proc/stat")
                && let Some(values) = data
                    .lines()
                    .next()
                    .and_then(|line| line.strip_prefix("cpu "))
            {
                let v: Vec<u64> = values
                    .split_whitespace()
                    .filter_map(|n| n.parse().ok())
                    .take(8)
                    .collect();
                if v.len() >= 5 {
                    let total: u64 = v.iter().sum();
                    let idle = v[3] + v[4];
                    if let Some((old_total, old_idle)) = self.previous_cpu {
                        let delta = total.saturating_sub(old_total);
                        if delta > 0 {
                            status.insert(
                                "cpu".into(),
                                json!(
                                    100.0
                                        * (delta.saturating_sub(idle.saturating_sub(old_idle)))
                                            as f64
                                        / delta as f64
                                ),
                            );
                        }
                    }
                    self.previous_cpu = Some((total, idle));
                }
            }
            if let Ok(data) = std::fs::read_to_string("/proc/meminfo") {
                let memory: std::collections::HashMap<_, _> = data
                    .lines()
                    .filter_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        Some((
                            name,
                            value
                                .split_whitespace()
                                .next()?
                                .parse::<u64>()
                                .ok()?
                                .saturating_mul(1024),
                        ))
                    })
                    .collect();
                for (name, total, free) in [
                    ("mem", "MemTotal", "MemAvailable"),
                    ("swap", "SwapTotal", "SwapFree"),
                ] {
                    if let (Some(total), Some(free)) = (memory.get(total), memory.get(free)) {
                        status.insert(
                            name.into(),
                            json!({"total":total,"used":total.saturating_sub(*free)}),
                        );
                    }
                }
            }
            use std::os::unix::ffi::OsStrExt;
            if let Ok(path) = std::ffi::CString::new(path.as_os_str().as_bytes()) {
                let mut statistics = std::mem::MaybeUninit::<libc::statvfs>::uninit();
                // statvfs initializes the entire structure on success.
                if unsafe { libc::statvfs(path.as_ptr(), statistics.as_mut_ptr()) } == 0 {
                    let s = unsafe { statistics.assume_init() };
                    let total = s.f_blocks.saturating_mul(s.f_frsize);
                    let used = s
                        .f_blocks
                        .saturating_sub(s.f_bavail)
                        .saturating_mul(s.f_frsize);
                    status.insert("disk".into(), json!({"total":total,"used":used}));
                }
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = path;
            let _ = &self.previous_cpu;
            let _ = &mut status;
        }
        Value::Object(status)
    }
}
