//! Strict migration of the Go config.go/standalone.go schema. This is an import,
//! not an environment-dependent Go loader: environment references stay references.
use crate::{
    certificate::CertConfig,
    secrets::{Secret, SecretPlan, SecretResolver, valid_env_name},
};
use node_core::{NodeSpec, UserSpec};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use sha1::{Digest, Sha1};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
};
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ImportError {
    #[error("invalid YAML at line {line}, column {column}")]
    Yaml { line: usize, column: usize },
    #[error("invalid configuration field: {0}")]
    Field(String),
    #[error("unmapped configuration field: {0}")]
    Unmapped(String),
    #[error("configuration conflict: {0}")]
    Conflict(String),
    #[error("configuration exceeds import size limit")]
    Size,
}
#[derive(Debug, Serialize)]
pub struct ImportResult {
    pub fleet: FleetConfig,
    pub secrets: SecretPlan,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FleetConfig {
    pub version: u32,
    pub nodes: Vec<NodeConfig>,
    pub machines: Vec<MachineConfig>,
    /// The runtime must reject the fleet unless it implements every listed
    /// feature. Merely retaining a legacy field is not runtime support.
    pub required_runtime_features: BTreeSet<String>,
}
impl FleetConfig {
    pub fn validate_runtime_features(&self, supported: &[&str]) -> Result<(), ImportError> {
        for required in &self.required_runtime_features {
            if !supported.contains(&required.as_str()) {
                return Err(ImportError::Unmapped(format!("runtime feature {required}")));
            }
        }
        validate_layout(&self.nodes, &self.machines)
    }
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NodeConfig {
    pub instance_id: String,
    pub id: String,
    /// Baseline fields match node-runtime's RuntimeConfig. The root owns mapping
    /// the additional typed settings after checking required_runtime_features.
    pub runtime: Value,
    pub intervals: NodeIntervals,
    pub websocket: WsSettings,
    pub kernel: KernelSettings,
    pub log: LogSettings,
    pub cert: CertConfig,
    pub standalone: Option<StandaloneRef>,
    pub health_port: u16,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MachineConfig {
    pub instance_id: String,
    pub panel_url: String,
    pub machine_id: u32,
    pub token_env: String,
    pub state_dir: PathBuf,
    pub template: NodeConfig,
}
impl MachineConfig {
    /// Discovery belongs to node-runtime. The same validated template is used
    /// for every newly discovered node and gets a distinct state/cert directory.
    pub fn expand(&self, node_id: u32, node_type: &str) -> Result<NodeConfig, ImportError> {
        if node_id == 0 || node_type.trim().is_empty() {
            return Err(ImportError::Field("machine discovery node identity".into()));
        }
        let mut node = self.template.clone();
        node.id = format!("{}-node-{node_id}", self.instance_id);
        let state = self.state_dir.join(format!("node-{node_id}"));
        node.runtime["node_id"] = json!(node_id);
        node.runtime["node_type"] = json!(node_type);
        node.runtime["state_dir"] = json!(state);
        node.kernel.config_dir = state.clone();
        node.cert.cert_dir = Some(state.join("certs"));
        Ok(node)
    }
}
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct NodeIntervals {
    pub push_interval: u64,
    pub pull_interval: u64,
    pub track_interval: u64,
    pub device_report_interval: u64,
}
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct WsSettings {
    pub status_interval: u64,
    pub handshake_timeout: u64,
    pub backoff_initial: u64,
    pub backoff_max: u64,
    pub discovery_interval: u64,
}
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct KernelSettings {
    #[serde(rename = "type")]
    pub kind: String,
    pub config_dir: PathBuf,
    pub geo_data_dir: PathBuf,
    pub log_level: String,
    pub custom_outbound: Vec<Value>,
    pub custom_route: Vec<Value>,
    pub custom_config: Option<PathBuf>,
    pub custom_outbound_env: Option<String>,
    pub custom_route_env: Option<String>,
}
impl KernelSettings {
    pub fn resolve_custom_outbound(
        &self,
        secrets: &dyn SecretResolver,
    ) -> Result<Vec<Value>, ImportError> {
        resolve_array(
            &self.custom_outbound_env,
            &self.custom_outbound,
            secrets,
            "kernel.custom_outbound",
        )
    }
    pub fn resolve_custom_route(
        &self,
        secrets: &dyn SecretResolver,
    ) -> Result<Vec<Value>, ImportError> {
        resolve_array(
            &self.custom_route_env,
            &self.custom_route,
            secrets,
            "kernel.custom_route",
        )
    }
}
fn resolve_array(
    reference: &Option<String>,
    inline: &[Value],
    secrets: &dyn SecretResolver,
    field: &str,
) -> Result<Vec<Value>, ImportError> {
    match reference {
        None => Ok(inline.to_vec()),
        Some(name) => {
            let value = secrets
                .get(name)
                .ok_or_else(|| ImportError::Field(format!("{field} environment reference")))?;
            serde_json::from_str(value.expose())
                .map_err(|_| ImportError::Field(format!("{field} JSON")))
        }
    }
}
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct LogSettings {
    pub level: String,
    pub output: String,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StandaloneRef {
    pub snapshot_env: String,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StandaloneSnapshot {
    pub node: NodeSpec,
    pub users: Vec<UserSpec>,
}
impl StandaloneRef {
    pub fn resolve(&self, secrets: &dyn SecretResolver) -> Result<StandaloneSnapshot, ImportError> {
        let secret = secrets.get(&self.snapshot_env).ok_or_else(|| {
            ImportError::Field("standalone snapshot environment reference".into())
        })?;
        let snapshot: StandaloneSnapshot = serde_json::from_str(secret.expose())
            .map_err(|_| ImportError::Field("standalone snapshot JSON".into()))?;
        validate_standalone(&snapshot)?;
        Ok(snapshot)
    }
}

#[derive(Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct GoConfig {
    panel: GoPanel,
    node: NodeIntervals,
    kernel: GoKernel,
    cert: CertConfig,
    log: LogSettings,
    runtime: GoRuntime,
    ws: WsSettings,
    standalone: Option<GoStandalone>,
    health_port: u16,
    nodes: Vec<GoNodeEntry>,
    machine: Option<GoMachine>,
}
#[derive(Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct GoPanel {
    url: String,
    token: Secret,
    token_env: String,
    node_id: u32,
    node_type: String,
}
#[derive(Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct GoMachine {
    machine_id: u32,
    token: Secret,
    token_env: String,
}
#[derive(Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct GoKernel {
    #[serde(rename = "type")]
    kind: String,
    config_dir: String,
    geo_data_dir: String,
    log_level: String,
    custom_outbound: Vec<Value>,
    custom_route: Vec<Value>,
    custom_config: String,
}
#[derive(Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct GoRuntime {
    gomemlimit: String,
    gogc: i64,
}
#[derive(Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct GoNodeEntry {
    node_id: u32,
    node_type: String,
    kernel: Option<GoKernelOverride>,
    cert: Option<CertConfig>,
}
#[derive(Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct GoKernelOverride {
    config_dir: String,
    geo_data_dir: String,
    log_level: String,
    custom_config: String,
}
#[derive(Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct GoStandalone {
    enabled: bool,
    node: Value,
    users: Vec<GoUser>,
}
#[derive(Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct GoUser {
    id: i64,
    uuid: Secret,
    speed_limit: i64,
    device_limit: i64,
}

fn parse<T: DeserializeOwned>(value: Value, path: &str) -> Result<T, ImportError> {
    let bytes = serde_json::to_vec(&value).map_err(|_| ImportError::Field(path.into()))?;
    let mut deserializer = serde_json::Deserializer::from_slice(&bytes);
    serde_path_to_error::deserialize(&mut deserializer).map_err(|error| {
        let message = error.inner().to_string();
        let field_path = if error.path().to_string() == "." {
            path.into()
        } else {
            format!("{path}.{}", error.path())
        };
        if let Some(start) = message.strip_prefix("unknown field `") {
            let name = start.split('`').next().unwrap_or("unknown");
            ImportError::Unmapped(format!("{field_path}.{name}"))
        } else {
            ImportError::Field(field_path)
        }
    })
}

pub fn import_go_yaml(input: &str, source_path: &Path) -> Result<ImportResult, ImportError> {
    let working_directory = std::env::current_dir()
        .map_err(|_| ImportError::Field("original working directory".into()))?;
    import_go_yaml_with_working_directory(input, source_path, &working_directory)
}
/// Relative Go paths are interpreted relative to the original process working
/// directory. Only the default config_dir is based on the YAML file's directory.
/// Supply this explicitly when migrating a configuration from another machine.
pub fn import_go_yaml_with_working_directory(
    input: &str,
    source_path: &Path,
    working_directory: &Path,
) -> Result<ImportResult, ImportError> {
    if input.len() > 4 * 1024 * 1024 {
        return Err(ImportError::Size);
    }
    let yaml: serde_yaml::Value = serde_yaml::from_str(input).map_err(|error| {
        let location = error.location();
        ImportError::Yaml {
            line: location.as_ref().map_or(0, |x| x.line()),
            column: location.map_or(0, |x| x.column()),
        }
    })?;
    let json = serde_json::to_value(yaml)
        .map_err(|_| ImportError::Field("root: expected string mapping keys".into()))?;
    let mut root = json
        .as_object()
        .cloned()
        .ok_or_else(|| ImportError::Field("root".into()))?;
    let entries = root.remove("instances").unwrap_or(json!([]));
    let parent: GoConfig = parse(Value::Object(root), "root")?;
    // Even ignored parent settings are checked, so non-Rust runtime knobs never disappear.
    validate_go_runtime(&parent.runtime, "root")?;
    let instances: Vec<Value> = parse(entries, "instances")?;
    let many = instances.len() > 1;
    let configs = if instances.is_empty() {
        vec![parent.clone()]
    } else {
        instances
            .into_iter()
            .enumerate()
            .map(|(i, value)| {
                let mut cfg: GoConfig = parse(value, &format!("instances[{i}]"))?;
                inherit(&mut cfg, &parent);
                Ok(cfg)
            })
            .collect::<Result<Vec<_>, ImportError>>()?
    };
    let source = absolute_path(source_path.to_string_lossy().as_ref(), working_directory)?;
    let base = source
        .parent()
        .ok_or_else(|| ImportError::Field("source path".into()))?
        .to_path_buf();
    let mut result = ImportResult {
        fleet: FleetConfig {
            version: 1,
            nodes: vec![],
            machines: vec![],
            required_runtime_features: BTreeSet::new(),
        },
        secrets: SecretPlan::default(),
    };
    let mut instance_ids = BTreeSet::new();
    for (index, mut cfg) in configs.into_iter().enumerate() {
        let scope = format!("instances[{index}]");
        validate_go_runtime(&cfg.runtime, &scope)?;
        let standalone = cfg.standalone.as_ref().is_some_and(|s| s.enabled);
        let machine = cfg.machine.as_ref().is_some_and(|m| m.machine_id > 0);
        if cfg.machine.is_some() && !machine {
            return Err(ImportError::Field(format!("{scope}.machine.machine_id")));
        }
        if (standalone && (machine || !cfg.nodes.is_empty())) || (machine && !cfg.nodes.is_empty())
        {
            return Err(ImportError::Conflict(format!(
                "{scope}: standalone, machine and nodes are mutually exclusive"
            )));
        }
        if cfg.standalone.is_some() && !standalone {
            return Err(ImportError::Unmapped(format!(
                "{scope}.standalone.enabled=false (inactive settings)"
            )));
        }
        let (normalized, slug) = if standalone {
            ("standalone".to_owned(), "standalone".to_owned())
        } else {
            normalize_panel(&cfg.panel.url, &scope)?
        };
        cfg.panel.url = normalized;
        let (mode, target) = if standalone {
            ("standalone", "local".to_owned())
        } else if machine {
            (
                "machine",
                cfg.machine.as_ref().unwrap().machine_id.to_string(),
            )
        } else if !cfg.nodes.is_empty() {
            let mut ids: Vec<_> = cfg.nodes.iter().map(|n| n.node_id.to_string()).collect();
            ids.sort();
            ("node", ids.join(","))
        } else {
            ("node", cfg.panel.node_id.to_string())
        };
        let hash = format!(
            "{:x}",
            Sha1::digest(format!("{}|{mode}|{target}", cfg.panel.url).as_bytes())
        );
        let instance_id = format!("{slug}-{mode}-{target}-{}", &hash[..6]);
        if !instance_ids.insert(instance_id.clone()) {
            return Err(ImportError::Conflict("duplicate instance identity".into()));
        }
        let inst_base = if many && cfg.kernel.config_dir.is_empty() {
            base.join(&instance_id)
        } else {
            base.clone()
        };
        defaults(&mut cfg, &inst_base, working_directory)?;
        collect_features(&cfg, &mut result.fleet.required_runtime_features);
        if standalone {
            let local = standalone_snapshot(cfg.standalone.as_ref().unwrap(), &scope)?;
            let name = secret_name(&instance_id, "STANDALONE");
            let content = serde_json::to_string(&local)
                .map_err(|_| ImportError::Field(format!("{scope}.standalone")))?;
            result
                .secrets
                .insert(name.clone(), Secret::new(content))
                .map_err(|_| ImportError::Conflict("secret reference".into()))?;
            let reference = StandaloneRef { snapshot_env: name };
            let node = make_node(
                &cfg,
                &instance_id,
                (1, "standalone"),
                Some(reference),
                working_directory,
                &mut result.secrets,
                &scope,
            )?;
            result.fleet.nodes.push(node);
        } else if machine {
            let machine = cfg.machine.as_ref().unwrap();
            let token = token_reference(
                &machine.token,
                &machine.token_env,
                &instance_id,
                "MACHINE_TOKEN",
                &mut result.secrets,
                &format!("{scope}.machine"),
            )?;
            if !cfg.panel.token.is_empty()
                || !cfg.panel.token_env.is_empty()
                || cfg.panel.node_id != 0
                || !cfg.panel.node_type.is_empty()
            {
                return Err(ImportError::Unmapped(format!(
                    "{scope}.panel node credentials/identity ignored by machine mode"
                )));
            }
            let mut template = make_node(
                &cfg,
                &instance_id,
                (0, ""),
                None,
                working_directory,
                &mut result.secrets,
                &scope,
            )?;
            template.runtime["token_env"] = json!(token);
            result.fleet.machines.push(MachineConfig {
                instance_id: instance_id.clone(),
                panel_url: cfg.panel.url.clone(),
                machine_id: machine.machine_id,
                token_env: token,
                state_dir: PathBuf::from(&cfg.kernel.config_dir),
                template,
            });
        } else {
            token_reference(
                &cfg.panel.token,
                &cfg.panel.token_env,
                &instance_id,
                "PANEL_TOKEN",
                &mut result.secrets,
                &format!("{scope}.panel"),
            )?;
            if cfg.nodes.is_empty() {
                if cfg.panel.node_id == 0 {
                    return Err(ImportError::Field(format!("{scope}.panel.node_id")));
                }
                result.fleet.nodes.push(make_node(
                    &cfg,
                    &instance_id,
                    (cfg.panel.node_id, &cfg.panel.node_type),
                    None,
                    working_directory,
                    &mut result.secrets,
                    &scope,
                )?);
            } else {
                let mut ids = BTreeSet::new();
                for (n, entry) in cfg.nodes.iter().enumerate() {
                    if entry.node_id == 0 || !ids.insert(entry.node_id) {
                        return Err(ImportError::Conflict(format!("{scope}.nodes[{n}].node_id")));
                    }
                    let mut expanded = cfg.clone();
                    expanded.nodes.clear();
                    expanded.panel.node_id = entry.node_id;
                    expanded.panel.node_type = entry.node_type.clone();
                    if let Some(overrides) = &entry.kernel {
                        if !overrides.config_dir.is_empty() {
                            let was_default = expanded.kernel.geo_data_dir == cfg.kernel.config_dir;
                            expanded.kernel.config_dir =
                                absolute_path(&overrides.config_dir, working_directory)?
                                    .to_string_lossy()
                                    .into_owned();
                            if was_default {
                                expanded.kernel.geo_data_dir = expanded.kernel.config_dir.clone();
                            }
                        }
                        if !overrides.geo_data_dir.is_empty() {
                            expanded.kernel.geo_data_dir =
                                absolute_path(&overrides.geo_data_dir, working_directory)?
                                    .to_string_lossy()
                                    .into_owned();
                        }
                        if !overrides.log_level.is_empty() {
                            expanded.kernel.log_level = overrides.log_level.clone();
                        }
                        if !overrides.custom_config.is_empty() {
                            expanded.kernel.custom_config = overrides.custom_config.clone();
                        }
                    } else {
                        expanded.kernel.config_dir = Path::new(&cfg.kernel.config_dir)
                            .join(format!("node-{}", entry.node_id))
                            .to_string_lossy()
                            .into_owned();
                    }
                    if let Some(cert) = &entry.cert {
                        expanded.cert = cert.clone();
                    }
                    if expanded
                        .cert
                        .cert_dir
                        .as_ref()
                        .is_none_or(|p| p.as_os_str().is_empty())
                    {
                        expanded.cert.cert_dir =
                            Some(Path::new(&expanded.kernel.config_dir).join("certs"));
                    }
                    collect_features(&expanded, &mut result.fleet.required_runtime_features);
                    result.fleet.nodes.push(make_node(
                        &expanded,
                        &instance_id,
                        (entry.node_id, &entry.node_type),
                        None,
                        working_directory,
                        &mut result.secrets,
                        &format!("{scope}.nodes[{n}]"),
                    )?);
                }
            }
        }
    }
    validate_layout(&result.fleet.nodes, &result.fleet.machines)?;
    Ok(result)
}
fn token_reference(
    token: &Secret,
    reference: &str,
    owner: &str,
    role: &str,
    plan: &mut SecretPlan,
    scope: &str,
) -> Result<String, ImportError> {
    if !reference.is_empty() && !valid_env_name(reference) {
        return Err(ImportError::Field(format!("{scope}.token_env")));
    }
    if !token.is_empty() {
        let name = if reference.is_empty() {
            secret_name(owner, role)
        } else {
            reference.to_owned()
        };
        plan.insert(name.clone(), token.clone()).map_err(|_| {
            ImportError::Conflict(format!("{scope}.token_env has conflicting values"))
        })?;
        Ok(name)
    } else if !reference.is_empty() {
        Ok(reference.to_owned())
    } else {
        Err(ImportError::Field(format!("{scope}.token/token_env")))
    }
}
fn secret_name(owner: &str, role: &str) -> String {
    let hash = format!("{:x}", Sha1::digest(owner.as_bytes()));
    format!(
        "XBOARD_IMPORTED_{}_{}",
        hash[..12].to_ascii_uppercase(),
        role
    )
}
fn validate_go_runtime(runtime: &GoRuntime, scope: &str) -> Result<(), ImportError> {
    if !runtime.gomemlimit.is_empty() {
        return Err(ImportError::Unmapped(format!(
            "{scope}.runtime.gomemlimit (Go GC setting)"
        )));
    }
    if runtime.gogc != 0 {
        return Err(ImportError::Unmapped(format!(
            "{scope}.runtime.gogc (Go GC setting)"
        )));
    }
    Ok(())
}
fn make_node(
    cfg: &GoConfig,
    instance: &str,
    identity: (u32, &str),
    standalone: Option<StandaloneRef>,
    base: &Path,
    plan: &mut SecretPlan,
    scope: &str,
) -> Result<NodeConfig, ImportError> {
    let (node_id, node_type) = identity;
    let machine_id = cfg.machine.as_ref().map(|machine| machine.machine_id);
    let state = PathBuf::from(&cfg.kernel.config_dir);
    let id = format!("{instance}-node-{node_id}");
    let token = if standalone.is_some() {
        "XBOARD_STANDALONE_UNUSED".to_owned()
    } else if machine_id.is_some() {
        "XBOARD_MACHINE_PENDING".to_owned()
    } else {
        token_reference(
            &cfg.panel.token,
            &cfg.panel.token_env,
            instance,
            "PANEL_TOKEN",
            plan,
            &format!("{scope}.panel"),
        )?
    };
    if standalone.is_none() && machine_id.is_none() && node_type.trim().is_empty() {
        return Err(ImportError::Field(format!(
            "{scope}.panel.node_type (runtime requires explicit type)"
        )));
    }
    let runtime = json!({"panel_url":cfg.panel.url,"token_env":token,"node_id":node_id,"machine_id":machine_id,"node_type":if node_type.is_empty(){None}else{Some(node_type)},
        "state_dir":state,"poll_seconds":if cfg.node.pull_interval==0{30}else{cfg.node.pull_interval},"report_seconds":if cfg.node.push_interval==0{60}else{cfg.node.push_interval},"websocket":standalone.is_none()});
    let mut cert = cfg.cert.clone();
    normalize_cert_paths(&mut cert, base)?;
    // Convert every secret before public serialization. A per-node certificate
    // override replaces the whole block, matching Go ExpandNodes.
    let owner = format!("{instance}:{node_id}:{}", state.display());
    let direct = std::mem::take(&mut cert.dns_env);
    for (key, value) in direct {
        if !valid_env_name(&key) {
            return Err(ImportError::Field(format!("{scope}.cert.dns_env key")));
        }
        let name = secret_name(&owner, &format!("DNS_{key}"));
        plan.insert(name.clone(), value)
            .map_err(|_| ImportError::Conflict("DNS secret reference".into()))?;
        cert.dns_env_refs.insert(key, name);
    }
    if !cert.cert_content.is_empty() {
        let name = secret_name(&owner, "CERT_PEM");
        plan.insert(name.clone(), std::mem::take(&mut cert.cert_content))
            .map_err(|_| ImportError::Conflict("certificate secret reference".into()))?;
        cert.cert_content_env = Some(name);
    }
    if !cert.key_content.is_empty() {
        let name = secret_name(&owner, "KEY_PEM");
        plan.insert(name.clone(), std::mem::take(&mut cert.key_content))
            .map_err(|_| ImportError::Conflict("key secret reference".into()))?;
        cert.key_content_env = Some(name);
    }
    if !cert.cert_mode.is_empty() || !cert.mode_fallback.is_empty() {
        cert.cert_mode = cert.mode().to_ascii_lowercase();
        cert.mode_fallback.clear();
    }
    cert.validate()
        .map_err(|_| ImportError::Field(format!("{scope}.cert")))?;
    if cert.mode() == "dns"
        && !matches!(
            cert.dns_provider.to_ascii_lowercase().as_str(),
            "cf" | "cloudflare"
        )
        && cert.dns_hook.is_none()
    {
        return Err(ImportError::Unmapped(format!(
            "{scope}.cert.dns_provider requires an external hook"
        )));
    }
    let mut kernel = KernelSettings {
        kind: cfg.kernel.kind.clone(),
        config_dir: state,
        geo_data_dir: PathBuf::from(&cfg.kernel.geo_data_dir),
        log_level: cfg.kernel.log_level.clone(),
        custom_outbound: vec![],
        custom_route: vec![],
        custom_outbound_env: None,
        custom_route_env: None,
        custom_config: if cfg.kernel.custom_config.is_empty() {
            None
        } else {
            Some(absolute_path(&cfg.kernel.custom_config, base)?)
        },
    };
    for (role, values, reference) in [
        (
            "CUSTOM_OUTBOUND",
            &cfg.kernel.custom_outbound,
            &mut kernel.custom_outbound_env,
        ),
        (
            "CUSTOM_ROUTE",
            &cfg.kernel.custom_route,
            &mut kernel.custom_route_env,
        ),
    ] {
        if !values.is_empty() {
            let name = secret_name(&owner, role);
            let content = serde_json::to_string(values)
                .map_err(|_| ImportError::Field(format!("{scope}.kernel custom JSON")))?;
            plan.insert(name.clone(), Secret::new(content))
                .map_err(|_| ImportError::Conflict("kernel custom secret reference".into()))?;
            *reference = Some(name);
        }
    }
    Ok(NodeConfig {
        instance_id: instance.to_owned(),
        id,
        runtime,
        intervals: cfg.node.clone(),
        websocket: cfg.ws.clone(),
        kernel,
        log: cfg.log.clone(),
        cert,
        standalone,
        health_port: cfg.health_port,
    })
}
fn normalize_cert_paths(cert: &mut CertConfig, base: &Path) -> Result<(), ImportError> {
    for path in [
        &mut cert.cert_file,
        &mut cert.key_file,
        &mut cert.cert_dir,
        &mut cert.dns_hook,
        &mut cert.acme_ca_file,
    ] {
        if let Some(value) = path {
            if value.as_os_str().is_empty() {
                *path = None;
            } else {
                *value = absolute_path(value.to_string_lossy().as_ref(), base)?;
            }
        }
    }
    Ok(())
}
fn collect_features(cfg: &GoConfig, features: &mut BTreeSet<String>) {
    for feature in [
        "node_intervals",
        "websocket_tuning",
        "kernel_settings",
        "logging",
    ] {
        features.insert(feature.into());
    }
    if cfg.health_port > 0 {
        features.insert("health_endpoint".into());
    }
    if cfg.standalone.as_ref().is_some_and(|s| s.enabled) {
        features.insert("standalone".into());
    }
    if cfg.machine.is_some() {
        features.insert("machine_discovery".into());
    }
    if cfg.kernel.kind == "xray" {
        features.insert("xray_kernel".into());
    }
    if !cfg.kernel.custom_outbound.is_empty() {
        features.insert("custom_outbound".into());
    }
    if !cfg.kernel.custom_route.is_empty() {
        features.insert("custom_route".into());
    }
    if !cfg.kernel.custom_config.is_empty() {
        features.insert("custom_config".into());
    }
    if cfg.cert.mode() != "none" {
        features.insert("certificate_lifecycle".into());
    }
}
fn defaults(cfg: &mut GoConfig, base: &Path, working_directory: &Path) -> Result<(), ImportError> {
    if cfg.kernel.kind.is_empty() {
        cfg.kernel.kind = "singbox".into();
    }
    if !matches!(cfg.kernel.kind.as_str(), "singbox" | "xray") {
        return Err(ImportError::Field("kernel.type".into()));
    }
    if cfg.kernel.config_dir.is_empty() {
        cfg.kernel.config_dir = base.to_string_lossy().into_owned();
    } else {
        cfg.kernel.config_dir = absolute_path(&cfg.kernel.config_dir, working_directory)?
            .to_string_lossy()
            .into_owned();
    }
    if cfg.kernel.geo_data_dir.is_empty() {
        cfg.kernel.geo_data_dir = cfg.kernel.config_dir.clone();
    } else {
        cfg.kernel.geo_data_dir = absolute_path(&cfg.kernel.geo_data_dir, working_directory)?
            .to_string_lossy()
            .into_owned();
    }
    if cfg.kernel.log_level.is_empty() {
        cfg.kernel.log_level = "warn".into();
    }
    if cfg.log.level.is_empty() {
        cfg.log.level = "info".into();
    }
    if cfg.log.output.is_empty() {
        cfg.log.output = "stdout".into();
    }
    if !matches!(cfg.log.output.as_str(), "stdout" | "stderr") {
        cfg.log.output = absolute_path(&cfg.log.output, working_directory)?
            .to_string_lossy()
            .into_owned();
    }
    if !matches!(cfg.log.level.as_str(), "debug" | "info" | "warn" | "error") {
        return Err(ImportError::Field("log.level".into()));
    }
    if !matches!(
        cfg.kernel.log_level.as_str(),
        "trace" | "debug" | "info" | "warn" | "error" | "fatal" | "panic" | "off"
    ) {
        return Err(ImportError::Field("kernel.log_level".into()));
    }
    if cfg
        .cert
        .cert_dir
        .as_ref()
        .is_none_or(|p| p.as_os_str().is_empty())
    {
        cfg.cert.cert_dir = Some(Path::new(&cfg.kernel.config_dir).join("certs"));
    }
    if cfg.cert.http_port == 0 {
        cfg.cert.http_port = 80;
    }
    if cfg.ws.status_interval == 0 {
        cfg.ws.status_interval = 10;
    }
    if cfg.ws.handshake_timeout == 0 {
        cfg.ws.handshake_timeout = 15;
    }
    if cfg.ws.backoff_initial == 0 {
        cfg.ws.backoff_initial = 1;
    }
    if cfg.ws.backoff_max == 0 {
        cfg.ws.backoff_max = 60;
    }
    if cfg.ws.discovery_interval == 0 {
        cfg.ws.discovery_interval = 300;
    }
    if cfg.node.track_interval == 0 {
        cfg.node.track_interval = 10;
    }
    if cfg.node.device_report_interval == 0 {
        cfg.node.device_report_interval = 30;
    }
    if cfg.ws.backoff_max < cfg.ws.backoff_initial {
        return Err(ImportError::Field("ws.backoff_max".into()));
    }
    for interval in [
        cfg.node.push_interval,
        cfg.node.pull_interval,
        cfg.node.track_interval,
        cfg.node.device_report_interval,
        cfg.ws.status_interval,
        cfg.ws.handshake_timeout,
        cfg.ws.backoff_initial,
        cfg.ws.backoff_max,
        cfg.ws.discovery_interval,
    ] {
        if interval > 86400 {
            return Err(ImportError::Field("interval exceeds one day".into()));
        }
    }
    if cfg.node.push_interval > 3600 || cfg.node.pull_interval > 3600 {
        return Err(ImportError::Field(
            "runtime poll/report interval exceeds one hour".into(),
        ));
    }
    Ok(())
}
fn inherit(child: &mut GoConfig, parent: &GoConfig) {
    macro_rules! strings {($($field:expr => $source:expr),* $(,)?)=>{$(if $field.is_empty(){$field=$source.clone();})*};}
    macro_rules! numbers {($($field:expr => $source:expr),* $(,)?)=>{$(if $field==0{$field=$source;})*};}
    strings!(child.log.level=>parent.log.level,child.log.output=>parent.log.output,child.runtime.gomemlimit=>parent.runtime.gomemlimit,
        child.kernel.kind=>parent.kernel.kind,child.kernel.log_level=>parent.kernel.log_level,child.kernel.geo_data_dir=>parent.kernel.geo_data_dir,
        child.kernel.custom_config=>parent.kernel.custom_config);
    numbers!(child.node.push_interval=>parent.node.push_interval,child.node.pull_interval=>parent.node.pull_interval,child.node.track_interval=>parent.node.track_interval,child.node.device_report_interval=>parent.node.device_report_interval,
        child.ws.status_interval=>parent.ws.status_interval,child.ws.handshake_timeout=>parent.ws.handshake_timeout,child.ws.backoff_initial=>parent.ws.backoff_initial,child.ws.backoff_max=>parent.ws.backoff_max,child.ws.discovery_interval=>parent.ws.discovery_interval,child.runtime.gogc=>parent.runtime.gogc);
    if child.kernel.custom_outbound.is_empty() {
        child.kernel.custom_outbound = parent.kernel.custom_outbound.clone();
    }
    if child.kernel.custom_route.is_empty() {
        child.kernel.custom_route = parent.kernel.custom_route.clone();
    }
    strings!(child.cert.cert_mode=>parent.cert.cert_mode,child.cert.domain=>parent.cert.domain,child.cert.email=>parent.cert.email,child.cert.dns_provider=>parent.cert.dns_provider);
    if child.cert.cert_file.is_none() {
        child.cert.cert_file = parent.cert.cert_file.clone();
    }
    if child.cert.key_file.is_none() {
        child.cert.key_file = parent.cert.key_file.clone();
    }
    if child.cert.dns_env.is_empty() {
        child.cert.dns_env = parent.cert.dns_env.clone();
    }
    if child.cert.dns_env_refs.is_empty() {
        child.cert.dns_env_refs = parent.cert.dns_env_refs.clone();
    }
    if child.cert.cert_content.is_empty() {
        child.cert.cert_content = parent.cert.cert_content.clone();
    }
    if child.cert.key_content.is_empty() {
        child.cert.key_content = parent.cert.key_content.clone();
    }
    numbers!(child.cert.http_port=>parent.cert.http_port);
    // This order deliberately mirrors the Go implementation after cert inheritance.
    let child_has_cert = !child.cert.cert_mode.is_empty()
        || child.cert.cert_file.is_some()
        || !child.cert.cert_content.is_empty();
    if !child_has_cert && !child.cert.auto_tls && parent.cert.auto_tls {
        child.cert.auto_tls = true;
    }
    if child.cert.acme_directory.is_none() {
        child.cert.acme_directory = parent.cert.acme_directory.clone();
    }
    if child.cert.acme_ca_file.is_none() {
        child.cert.acme_ca_file = parent.cert.acme_ca_file.clone();
    }
    if child.cert.dns_hook.is_none() {
        child.cert.dns_hook = parent.cert.dns_hook.clone();
    }
}
fn standalone_snapshot(raw: &GoStandalone, scope: &str) -> Result<StandaloneSnapshot, ImportError> {
    let mut node = raw
        .node
        .as_object()
        .cloned()
        .ok_or_else(|| ImportError::Field(format!("{scope}.standalone.node")))?;
    if let Some(value) = node.remove("network_settings")
        && node.insert("networkSettings".into(), value).is_some()
    {
        return Err(ImportError::Conflict(
            "standalone network settings aliases".into(),
        ));
    }
    if let Some(value) = node.remove("obfs_password") {
        node.insert("obfs-password".into(), value);
    }
    let spec: NodeSpec = parse(Value::Object(node), &format!("{scope}.standalone.node"))?;
    let users = raw
        .users
        .iter()
        .map(|user| {
            UserSpec::new(user.id, user.uuid.expose())
                .with_limits(user.speed_limit, user.device_limit)
        })
        .collect();
    let snapshot = StandaloneSnapshot { node: spec, users };
    validate_standalone(&snapshot)?;
    Ok(snapshot)
}
fn validate_standalone(snapshot: &StandaloneSnapshot) -> Result<(), ImportError> {
    snapshot
        .node
        .validate()
        .map_err(|_| ImportError::Field("standalone.node".into()))?;
    if !(0..=2).contains(&snapshot.node.tls) {
        return Err(ImportError::Field("standalone.node.tls".into()));
    }
    if snapshot.users.is_empty() {
        return Err(ImportError::Field("standalone.users".into()));
    }
    let mut ids = BTreeSet::new();
    let mut uuids = BTreeSet::new();
    for user in &snapshot.users {
        if user.id <= 0
            || user.uuid.is_empty()
            || user.speed_limit < 0
            || user.device_limit < 0
            || !ids.insert(user.id)
            || !uuids.insert(&user.uuid)
        {
            return Err(ImportError::Field(
                "standalone.users identity or limits".into(),
            ));
        }
    }
    Ok(())
}
fn normalize_panel(raw: &str, scope: &str) -> Result<(String, String), ImportError> {
    let mut url = url::Url::parse(raw.trim())
        .map_err(|_| ImportError::Field(format!("{scope}.panel.url")))?;
    if !matches!(url.scheme(), "https" | "http")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(ImportError::Field(format!("{scope}.panel.url")));
    }
    let path = url.path().trim_end_matches('/').to_owned();
    url.set_path(&path);
    // Preserve explicit ports, including :443/:80, as Go's instance IDs do.
    let authority = raw
        .trim()
        .split_once("://")
        .map(|(_, tail)| tail.split('/').next().unwrap_or(""))
        .unwrap_or("")
        .to_ascii_lowercase();
    let normalized = format!("{}://{}{}", url.scheme(), authority, path);
    let seed = format!(
        "{}{}",
        authority,
        if path.is_empty() {
            String::new()
        } else {
            format!("-{path}")
        }
    );
    let mut slug = String::new();
    for character in seed.to_ascii_lowercase().chars() {
        if character.is_ascii_alphanumeric() {
            slug.push(character);
        } else if !slug.ends_with('-') {
            slug.push('-');
        }
    }
    let slug = slug
        .trim_matches('-')
        .chars()
        .take(48)
        .collect::<String>()
        .trim_end_matches('-')
        .to_owned();
    Ok((
        normalized,
        if slug.is_empty() {
            "panel".into()
        } else {
            slug
        },
    ))
}
fn absolute_path(raw: &str, base: &Path) -> Result<PathBuf, ImportError> {
    if raw.is_empty() || raw.contains('\0') {
        return Err(ImportError::Field("path".into()));
    }
    let normalized = raw.replace('\\', "/");
    let absolute = normalized.starts_with('/')
        || (normalized.len() > 2
            && normalized.as_bytes()[1] == b':'
            && normalized.as_bytes()[2] == b'/');
    let joined = if absolute {
        normalized
    } else {
        format!(
            "{}/{}",
            base.to_string_lossy().replace('\\', "/"),
            normalized
        )
    };
    let mut parts: Vec<&str> = Vec::new();
    for part in joined.split('/') {
        match part {
            "." => {}
            ".." => {
                if parts.len() <= 1 {
                    return Err(ImportError::Field("path escapes root".into()));
                }
                parts.pop();
            }
            _ => parts.push(part),
        }
    }
    Ok(PathBuf::from(parts.join("/")))
}
fn layout_key(path: &Path) -> String {
    let resolved = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    let key = resolved
        .to_string_lossy()
        .replace('\\', "/")
        .trim_end_matches('/')
        .to_owned();
    if key.as_bytes().get(1) == Some(&b':') {
        key.to_ascii_lowercase()
    } else {
        key
    }
}
fn validate_layout(nodes: &[NodeConfig], machines: &[MachineConfig]) -> Result<(), ImportError> {
    let mut paths: Vec<(String, String)> = Vec::new();
    let mut bindings = BTreeSet::new();
    let mut health = BTreeMap::new();
    for node in nodes.iter().chain(machines.iter().map(|m| &m.template)) {
        let path = layout_key(&node.kernel.config_dir);
        for (other, owner) in &paths {
            if path == *other
                || path.starts_with(&format!("{other}/"))
                || other.starts_with(&format!("{path}/"))
            {
                return Err(ImportError::Conflict(format!(
                    "state_dir overlap for {} and {owner}",
                    node.id
                )));
            }
        }
        paths.push((path, node.id.clone()));
        if node.health_port > 0 {
            if health
                .get(&node.health_port)
                .is_some_and(|owner| owner != &node.instance_id)
            {
                return Err(ImportError::Conflict(
                    "health_port shared across instances".into(),
                ));
            }
            health.insert(node.health_port, node.instance_id.clone());
        }
        if node.standalone.is_none() && node.runtime["machine_id"].is_null() {
            let binding = format!(
                "{}|{}",
                node.runtime["panel_url"].as_str().unwrap_or(""),
                node.runtime["node_id"]
            );
            if !bindings.insert(binding) {
                return Err(ImportError::Conflict("duplicate panel/node binding".into()));
            }
        }
    }
    let mut machine_ids = BTreeSet::new();
    for machine in machines {
        if !machine_ids.insert(format!("{}|{}", machine.panel_url, machine.machine_id)) {
            return Err(ImportError::Conflict(
                "duplicate panel/machine binding".into(),
            ));
        }
    }
    Ok(())
}
