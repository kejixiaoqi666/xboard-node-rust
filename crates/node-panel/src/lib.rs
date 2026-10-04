//! Bounded XBoard REST/WebSocket transport with explicit application acknowledgements.
use node_core::NodeSpec;
use reqwest::{Client, Method, Response, StatusCode, Url, header};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use std::{collections::BTreeMap, time::Duration};
use thiserror::Error;

mod ws;
pub use ws::{WsEvent, parse_ws_message};
mod ws_client;
pub use ws_client::{WsBackoff, WsClient, WsClientError};
mod ws_hint;
pub use ws_hint::{WsHint, parse_ws_hint};
mod reducer;
pub use reducer::{ControlPlaneReducer, ReduceError, ReduceResult};
mod wire;
pub use wire::{BaseConfig, PanelNodeConfig, decode_node_config};

const MAX_RESPONSE: usize = 4 * 1024 * 1024;

#[derive(Debug, Error)]
pub enum PanelError {
    #[error("invalid or insecure panel URL")]
    Url,
    #[error("invalid panel authentication")]
    Auth,
    #[error("panel transport failed")]
    Transport,
    #[error("panel HTTP status {0}")]
    Status(u16),
    #[error("panel response too large")]
    TooLarge,
    #[error("invalid panel response")]
    Decode,
}

impl PanelError {
    /// A cache may bridge a temporary outage, but never an authentication or
    /// malformed-response failure. HTTP 5xx is treated as unavailable because
    /// the panel endpoint is reachable but cannot serve authoritative state.
    pub fn is_unavailable(&self) -> bool {
        matches!(self, Self::Transport) || matches!(self, Self::Status(status) if *status >= 500)
    }
}

#[derive(Debug)]
pub enum Fetch<T> {
    Modified(T),
    NotModified,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReportOutcome {
    Acknowledged,
    NotSent,
    /// The server may have applied the report. Never blindly retry billing.
    Uncertain,
}

#[derive(Clone)]
pub struct Auth {
    token: String,
    node_id: u32,
    node_type: Option<String>,
    machine_id: Option<u32>,
}
impl Auth {
    pub fn machine(token: impl Into<String>, machine_id: u32, node_id: u32) -> Self {
        Self {
            token: token.into(),
            node_id,
            node_type: None,
            machine_id: Some(machine_id),
        }
    }
    pub fn legacy(token: impl Into<String>, node_id: u32, node_type: impl Into<String>) -> Self {
        Self {
            token: token.into(),
            node_id,
            node_type: Some(node_type.into()),
            machine_id: None,
        }
    }
    fn validate(&self) -> Result<(), PanelError> {
        if self.token.is_empty()
            || self.token.chars().any(char::is_control)
            || self.machine_id == Some(0)
        {
            return Err(PanelError::Auth);
        }
        Ok(())
    }
    fn payload(&self) -> Map<String, Value> {
        let mut m = Map::new();
        m.insert("token".into(), json!(self.token));
        m.insert("node_id".into(), json!(self.node_id));
        if let Some(id) = self.machine_id {
            m.insert("machine_id".into(), json!(id));
        } else if let Some(t) = &self.node_type {
            m.insert("node_type".into(), json!(t));
        }
        m
    }
    fn query(&self, url: &mut Url) {
        let mut q = url.query_pairs_mut();
        q.append_pair("token", &self.token)
            .append_pair("node_id", &self.node_id.to_string());
        if let Some(id) = self.machine_id {
            q.append_pair("machine_id", &id.to_string());
        } else if let Some(t) = &self.node_type {
            q.append_pair("node_type", t);
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct User {
    pub id: i64,
    pub uuid: String,
    #[serde(default)]
    pub speed_limit: i64,
    #[serde(default)]
    pub device_limit: i64,
}
#[derive(Debug, Deserialize)]
struct Users {
    users: Vec<User>,
}
#[derive(Debug, Deserialize)]
pub struct Handshake {
    pub websocket: WebSocketConfig,
    #[serde(default)]
    pub settings: Value,
}
#[derive(Debug, Deserialize)]
pub struct WebSocketConfig {
    pub enabled: bool,
    #[serde(default)]
    pub ws_url: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct MachineNode {
    pub id: u32,
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default)]
    pub name: String,
}
#[derive(Deserialize)]
struct MachineNodes {
    nodes: Vec<MachineNode>,
}
fn telemetry_ack(data: &[u8]) -> Result<(), PanelError> {
    let value: Value = serde_json::from_slice(data).map_err(|_| PanelError::Decode)?;
    let object = value.as_object().ok_or(PanelError::Decode)?;
    if object.get("data") != Some(&Value::Bool(true))
        || object
            .get("code")
            .is_some_and(|code| code.as_i64() != Some(0))
        || object
            .get("message")
            .is_some_and(|message| !message.is_string())
        || object
            .keys()
            .any(|key| !matches!(key.as_str(), "data" | "code" | "message"))
    {
        return Err(PanelError::Decode);
    }
    Ok(())
}

#[derive(Debug, Serialize)]
pub struct ResourceUse {
    pub total: u64,
    pub used: u64,
}
#[derive(Debug, Serialize)]
pub struct Report {
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub traffic: BTreeMap<i64, [i64; 2]>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub alive: BTreeMap<i64, Vec<String>>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub online: BTreeMap<i64, u32>,
    #[serde(skip)]
    pub cpu: f64,
    #[serde(skip)]
    pub mem: ResourceUse,
    #[serde(skip)]
    pub swap: ResourceUse,
    #[serde(skip)]
    pub disk: ResourceUse,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub metrics: BTreeMap<String, Value>,
}
impl Report {
    fn json(&self) -> Result<Map<String, Value>, PanelError> {
        if !self.cpu.is_finite() {
            return Err(PanelError::Decode);
        }
        let Value::Object(mut m) = serde_json::to_value(self).map_err(|_| PanelError::Decode)?
        else {
            return Err(PanelError::Decode);
        };
        m.insert(
            "status".into(),
            json!({"cpu":self.cpu,"mem":self.mem,"swap":self.swap,"disk":self.disk}),
        );
        Ok(m)
    }
}

pub struct Panel {
    base: Url,
    auth: Auth,
    http: Client,
    user_etag: Option<String>,
    pending_user_etag: Option<Option<String>>,
    config_etag: Option<String>,
    pending_config_etag: Option<Option<String>>,
    base_config: Option<BaseConfig>,
    pending_base_config: Option<BaseConfig>,
}
impl Panel {
    pub fn new(base: &str, auth: Auth) -> Result<Self, PanelError> {
        Self::build(base, auth, false)
    }
    /// Local-only test mode; never use against a non-loopback address.
    pub fn new_for_test(base: &str, auth: Auth) -> Result<Self, PanelError> {
        Self::build(base, auth, true)
    }
    fn build(base: &str, auth: Auth, local_test: bool) -> Result<Self, PanelError> {
        auth.validate()?;
        let url = Url::parse(base).map_err(|_| PanelError::Url)?;
        let loopback = matches!(url.host_str(), Some("127.0.0.1" | "localhost" | "[::1]"));
        if url.scheme() != "https" && !(local_test && url.scheme() == "http" && loopback) {
            return Err(PanelError::Url);
        }
        if !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || url.path() != "/"
        {
            return Err(PanelError::Url);
        }
        let http = Client::builder()
            .retry(reqwest::retry::never())
            .timeout(Duration::from_secs(30))
            .redirect(reqwest::redirect::Policy::none())
            .pool_max_idle_per_host(10)
            .build()
            .map_err(|_| PanelError::Transport)?;
        Ok(Self {
            base: url,
            auth,
            http,
            user_etag: None,
            pending_user_etag: None,
            config_etag: None,
            pending_config_etag: None,
            base_config: None,
            pending_base_config: None,
        })
    }
    pub fn config_etag(&self) -> Option<&str> {
        self.config_etag.as_deref()
    }
    pub fn pending_config_etag(&self) -> Option<&str> {
        self.pending_config_etag.as_ref().and_then(Option::as_deref)
    }
    /// Call only after the candidate has been successfully applied by a safe kernel adapter.
    pub fn accept_config(&mut self) {
        if let Some(tag) = self.pending_config_etag.take() {
            self.config_etag = tag;
            self.base_config = self.pending_base_config.take();
        }
    }
    pub fn reject_config(&mut self) {
        self.pending_config_etag = None;
        self.pending_base_config = None;
    }
    pub fn base_config(&self) -> Option<&BaseConfig> {
        self.base_config.as_ref()
    }
    pub fn user_etag(&self) -> Option<&str> {
        self.user_etag.as_deref()
    }
    /// Commit the user ETag only after the corresponding users are active in the kernel.
    pub fn accept_users(&mut self) {
        if let Some(tag) = self.pending_user_etag.take() {
            self.user_etag = tag;
        }
    }
    pub fn reject_users(&mut self) {
        self.pending_user_etag = None;
    }
    /// A push is a resync hint, not a global revision. Refetch authoritative REST state.
    pub fn invalidate_cache(&mut self) {
        self.user_etag = None;
        self.config_etag = None;
        self.reject_users();
        self.reject_config();
    }
    pub fn set_test_base(&mut self, base: &str) {
        let url = Url::parse(base).expect("test base URL");
        assert_eq!(url.host_str(), Some("127.0.0.1"));
        self.base = url;
    }
    fn path(&self, suffix: &str) -> Result<Url, PanelError> {
        self.base.join(suffix).map_err(|_| PanelError::Url)
    }
    async fn response(&self, response: Response) -> Result<Vec<u8>, PanelError> {
        if response.status() != StatusCode::OK {
            return Err(PanelError::Status(response.status().as_u16()));
        }
        if response
            .content_length()
            .is_some_and(|n| n > MAX_RESPONSE as u64)
        {
            return Err(PanelError::TooLarge);
        }
        let mut response = response;
        let mut result = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|_| PanelError::Transport)? {
            if chunk.len() > MAX_RESPONSE - result.len() {
                return Err(PanelError::TooLarge);
            }
            result.extend_from_slice(&chunk);
        }
        Ok(result)
    }
    async fn post(&self, path: &str, mut body: Map<String, Value>) -> Result<Vec<u8>, PanelError> {
        body.extend(self.auth.payload());
        let response = self
            .http
            .request(Method::POST, self.path(path)?)
            .json(&body)
            .send()
            .await
            .map_err(|_| PanelError::Transport)?;
        self.response(response).await
    }
    pub async fn handshake(&self) -> Result<Handshake, PanelError> {
        let data = self.post("api/v2/server/handshake", Map::new()).await?;
        let mut value: Value = serde_json::from_slice(&data).map_err(|_| PanelError::Decode)?;
        if value.get("settings") == Some(&json!([])) {
            value["settings"] = json!({});
        }
        serde_json::from_value(value).map_err(|_| PanelError::Decode)
    }
    pub async fn machine_nodes(&self) -> Result<Vec<MachineNode>, PanelError> {
        if self.auth.machine_id.is_none() {
            return Err(PanelError::Auth);
        }
        let data = self.post("api/v2/server/machine/nodes", Map::new()).await?;
        let response: MachineNodes =
            serde_json::from_slice(&data).map_err(|_| PanelError::Decode)?;
        let mut ids = std::collections::HashSet::new();
        if response.nodes.len() > 64
            || response.nodes.iter().any(|node| {
                node.id == 0 || node.kind.is_empty() || node.kind.len() > 32 || !ids.insert(node.id)
            })
        {
            return Err(PanelError::Decode);
        }
        Ok(response.nodes)
    }
    /// Observations contain no traffic deltas, so reconnecting cannot rebill.
    pub async fn report_observations(
        &self,
        activity: &node_core::ActivitySnapshot,
        status: Value,
        metrics: Value,
    ) -> Result<(), PanelError> {
        if !activity.validate() {
            return Err(PanelError::Decode);
        }
        let mut body = Map::new();
        body.insert("alive".into(), json!(activity.alive));
        body.insert("online".into(), json!(activity.online));
        body.insert("status".into(), status);
        body.insert("metrics".into(), metrics);
        let data = self.post("api/v2/server/report", body).await?;
        if serde_json::from_slice::<Value>(&data).ok() != Some(json!({"data":true})) {
            return Err(PanelError::Decode);
        }
        Ok(())
    }
    async fn legacy_post(&self, path: &str, body: Value) -> Result<Vec<u8>, PanelError> {
        let mut url = self.path(path)?;
        self.auth.query(&mut url);
        let response = self
            .http
            .post(url)
            .json(&body)
            .send()
            .await
            .map_err(|_| PanelError::Transport)?;
        self.response(response).await
    }
    pub async fn report_activity(
        &self,
        activity: &node_core::ActivitySnapshot,
    ) -> Result<(), PanelError> {
        if !activity.validate() {
            return Err(PanelError::Decode);
        }
        let data = if self.auth.machine_id.is_some() {
            let mut body = Map::new();
            body.insert("alive".into(), json!(activity.alive));
            body.insert("online".into(), json!(activity.online));
            self.post("api/v2/server/report", body).await?
        } else {
            self.legacy_post("api/v1/server/UniProxy/alive", json!(activity.alive))
                .await?
        };
        telemetry_ack(&data)
    }
    pub async fn report_status(&self, status: Value, metrics: Value) -> Result<(), PanelError> {
        let data = if self.auth.machine_id.is_some() {
            let mut body = Map::new();
            body.insert("status".into(), status);
            body.insert("metrics".into(), metrics);
            self.post("api/v2/server/report", body).await?
        } else {
            self.legacy_post("api/v1/server/UniProxy/status", status)
                .await?
        };
        telemetry_ack(&data)
    }
    pub async fn machine_status(&self, status: Value) -> Result<(), PanelError> {
        if self.auth.machine_id.is_none() || !status.is_object() {
            return Err(PanelError::Auth);
        }
        telemetry_ack(
            &self
                .post(
                    "api/v2/server/machine/status",
                    status.as_object().cloned().ok_or(PanelError::Decode)?,
                )
                .await?,
        )
    }
    pub async fn report(&self, report: Report) -> Result<(), PanelError> {
        let data = self.post("api/v2/server/report", report.json()?).await?;
        telemetry_ack(&data)
    }

    /// Stable, credential-free destination binding for a persisted traffic outbox.
    pub fn traffic_identity(&self) -> String {
        json!([
            self.base.as_str(),
            self.auth.node_id,
            self.auth.machine_id,
            self.auth.node_type
        ])
        .to_string()
    }

    /// Report payload bytes without fabricating CPU/memory/online measurements.
    /// The v2 endpoint has no confirmed batch-id deduplication contract.
    pub async fn report_traffic(&self, traffic: &BTreeMap<i64, [i64; 2]>) -> ReportOutcome {
        if traffic.is_empty()
            || traffic.len() > node_core::MAX_TRAFFIC_ROWS
            || traffic
                .iter()
                .any(|(id, bytes)| *id <= 0 || bytes.iter().any(|n| *n < 0) || *bytes == [0, 0])
        {
            return ReportOutcome::NotSent;
        }
        let Ok(mut url) = self.path(if self.auth.machine_id.is_some() {
            "api/v2/server/report"
        } else {
            "api/v1/server/UniProxy/push"
        }) else {
            return ReportOutcome::NotSent;
        };
        let body = if self.auth.machine_id.is_some() {
            let mut body = self.auth.payload();
            body.insert("traffic".into(), json!(traffic));
            Value::Object(body)
        } else {
            self.auth.query(&mut url);
            json!(traffic)
        };
        match self.http.post(url).json(&body).send().await {
            Ok(response) => match self.response(response).await {
                Ok(body) => {
                    // XBoard v2 ServerController::report returns {"data":true}.
                    // A login page or a business error with HTTP 200 is not an ACK.
                    match serde_json::from_slice::<Value>(&body) {
                        Ok(Value::Object(object))
                            if object.len() == 1
                                && object.get("data") == Some(&Value::Bool(true)) =>
                        {
                            ReportOutcome::Acknowledged
                        }
                        Ok(value)
                            if self.auth.machine_id.is_none()
                                && telemetry_ack(
                                    &serde_json::to_vec(&value).unwrap_or_default(),
                                )
                                .is_ok() =>
                        {
                            ReportOutcome::Acknowledged
                        }
                        _ => ReportOutcome::Uncertain,
                    }
                }
                Err(_) => ReportOutcome::Uncertain,
            },
            Err(error) if error.is_connect() || error.is_builder() => ReportOutcome::NotSent,
            Err(_) => ReportOutcome::Uncertain,
        }
    }
    /// Fetch a decoded configuration candidate; this is not kernel activation.
    pub async fn config(&mut self) -> Result<Fetch<NodeSpec>, PanelError> {
        self.reject_config();
        let path = if self.auth.machine_id.is_some() {
            "api/v2/server/config"
        } else {
            "api/v1/server/UniProxy/config"
        };
        let mut url = self.path(path)?;
        self.auth.query(&mut url);
        let mut request = self
            .http
            .get(url)
            .header(header::ACCEPT, "application/json");
        if let Some(tag) = &self.config_etag {
            request = request.header(header::IF_NONE_MATCH, tag);
        }
        let response = request.send().await.map_err(|_| PanelError::Transport)?;
        if response.status() == StatusCode::NOT_MODIFIED {
            return Ok(Fetch::NotModified);
        }
        let etag = response
            .headers()
            .get(header::ETAG)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let bytes = self.response(response).await?;
        let wire =
            decode_node_config(serde_json::from_slice(&bytes).map_err(|_| PanelError::Decode)?)?;
        if wire.node_id.is_some_and(|id| id != self.auth.node_id) {
            return Err(PanelError::Decode);
        }
        let config = wire.spec;
        self.pending_config_etag = Some(etag);
        self.pending_base_config = wire.base_config;
        Ok(Fetch::Modified(config))
    }
    /// Legacy XBoard uses token query auth on GET. HTTPS is mandatory to limit exposure.
    pub async fn users(&mut self) -> Result<Fetch<Vec<User>>, PanelError> {
        self.reject_users();
        let path = if self.auth.machine_id.is_some() {
            "api/v2/server/user"
        } else {
            "api/v1/server/UniProxy/user"
        };
        let mut url = self.path(path)?;
        self.auth.query(&mut url);
        let mut request = self
            .http
            .get(url)
            .header(header::ACCEPT, "application/json");
        if let Some(tag) = &self.user_etag {
            request = request.header(header::IF_NONE_MATCH, tag);
        }
        let response = request.send().await.map_err(|_| PanelError::Transport)?;
        if response.status() == StatusCode::NOT_MODIFIED {
            return Ok(Fetch::NotModified);
        }
        let etag = response
            .headers()
            .get(header::ETAG)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        let data = self.response(response).await?;
        let users: Users = serde_json::from_slice(&data).map_err(|_| PanelError::Decode)?;
        let mut ids = std::collections::HashSet::with_capacity(users.users.len());
        for user in &users.users {
            if user.uuid.trim().is_empty() || !ids.insert(user.id) {
                return Err(PanelError::Decode);
            }
        }
        self.pending_user_etag = Some(etag);
        Ok(Fetch::Modified(users.users))
    }
}
