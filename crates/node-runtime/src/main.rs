use node_admin::{EnvSecrets, SecretPlan, SecretResolver};
use node_kernel::{SingBoxConfigBuilder, SingBoxProcessKernel, SingBoxProcessKernelConfig};
use node_panel::{Auth, Panel, WsClient};
use node_runtime::{
    NodeRuntime, RuntimeConfig,
    administration::{self, PreparedNode, Services},
    observations,
};
use std::{
    collections::{HashMap, HashSet},
    fs::File,
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio::sync::watch;
type Failure = Box<dyn std::error::Error + Send + Sync>;

fn main() {
    let threads = std::thread::available_parallelism()
        .map(usize::from)
        .unwrap_or(2)
        .clamp(2, 8);
    let result = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(threads)
        .enable_all()
        .max_blocking_threads(128)
        .build()
        .map_err(|error| error.to_string())
        .and_then(|runtime| runtime.block_on(run()).map_err(|error| error.to_string()));
    if let Err(error) = result {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
async fn run() -> Result<(), Failure> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args == ["generate-reality-keypair"] {
        let (private, public) = node_native::generate_reality_keypair()?;
        println!(
            "{}",
            serde_json::json!({"private_key":private,"public_key":public})
        );
        return Ok(());
    }
    if args == ["generate-reality-mldsa65"] {
        let (seed, verify) = node_native::generate_reality_mldsa65_keypair()?;
        println!(
            "{}",
            serde_json::json!({"mldsa65_seed":seed,"mldsa65_verify":verify})
        );
        return Ok(());
    }
    if args
        .first()
        .is_some_and(|arg| matches!(arg.as_str(), "run" | "check"))
    {
        node_native::run_cli(&args).await?;
        return Ok(());
    }
    if args.is_empty() || args == ["--help"] {
        println!(
            "xboard-node-rust\nUsage: --config <runtime.json|fleet.json> [--secrets <private.json>] [--check]\n       --config <single-node.json> --traffic-status\n       --config <single-node.json> --traffic-resolve <batch-id> delivered|not-delivered\n       --import-go-yaml <config.yml> --output <fleet.json> [--secrets-output <private.json>] [--original-cwd <directory>]\n       generate-reality-keypair\n       generate-reality-mldsa65\nFleet nodes share one Rust process; each has its own listeners, state and report outbox. Imported YAML stores secret references separately.\n--check does not contact panels, issue certificates or start a data plane. Stop the node and reconcile the exact uncertain panel batch before --traffic-resolve."
        );
        return Ok(());
    }
    if args.first().is_some_and(|arg| arg == "--import-go-yaml") {
        return import_yaml(&args);
    }
    if args.len() < 2 || args[0] != "--config" {
        return Err("invalid arguments; use --help".into());
    }
    let mut private = None;
    let mut check = false;
    let mut traffic = None;
    let mut index = 2;
    while index < args.len() {
        match args[index].as_str() {
            "--secrets" if index + 1 < args.len() && private.is_none() => {
                private = Some(PathBuf::from(&args[index + 1]));
                index += 2;
            }
            "--check" if !check => {
                check = true;
                index += 1;
            }
            "--traffic-status" if traffic.is_none() => {
                traffic = Some(None);
                index += 1;
            }
            "--traffic-resolve"
                if index + 2 < args.len()
                    && traffic.is_none()
                    && matches!(args[index + 2].as_str(), "delivered" | "not-delivered") =>
            {
                traffic = Some(Some((
                    args[index + 1]
                        .parse::<u64>()
                        .map_err(|_| "invalid traffic batch id")?,
                    args[index + 2] == "delivered",
                )));
                index += 3;
            }
            _ => return Err("invalid arguments; use --help".into()),
        }
    }
    if check && traffic.is_some() {
        return Err("configuration check and traffic reconciliation are separate commands".into());
    }
    let value: serde_json::Value =
        serde_json::from_slice(&read_bounded(Path::new(&args[1]), 4 * 1024 * 1024)?)
            .map_err(|_| "invalid runtime configuration JSON")?;
    let secrets: Arc<dyn SecretResolver> = match private {
        Some(path) => Arc::new(
            SecretPlan::read_private_json(&path)
                .map_err(|_| "private secret store unavailable, invalid or not private")?,
        ),
        None => Arc::new(EnvSecrets),
    };
    let mut machines = Vec::new();
    let mut nodes = Vec::new();
    let fleet = value.get("nodes").is_some();
    if value.get("required_runtime_features").is_some() || value.get("machines").is_some() {
        let fleet: node_admin::FleetConfig =
            serde_json::from_value(value).map_err(|_| "invalid imported fleet configuration")?;
        if fleet.version != 1 || fleet.nodes.len() + fleet.machines.len() > 64 {
            return Err("invalid fleet version or size".into());
        }
        fleet.validate_runtime_features(administration::RUNTIME_FEATURES)?;
        nodes = fleet
            .nodes
            .into_iter()
            .map(PreparedNode::imported)
            .collect::<Result<_, _>>()?;
        machines = fleet.machines;
    } else if fleet {
        let mut fleet: node_runtime::fleet::FleetConfig =
            serde_json::from_value(value).map_err(|_| "invalid fleet configuration")?;
        fleet.validate()?;
        nodes = fleet.nodes.into_iter().map(PreparedNode::simple).collect();
    } else {
        let config: RuntimeConfig =
            serde_json::from_value(value).map_err(|_| "invalid runtime configuration")?;
        config.validate()?;
        nodes.push(PreparedNode::simple(config));
    }
    validate_nodes(&nodes)?;
    node_runtime::health_fleet::validate(&nodes)?;
    let mut health_ports: HashSet<_> = nodes
        .iter()
        .filter_map(|node| node.settings.as_ref().map(|s| s.health_port))
        .filter(|port| *port > 0)
        .collect();
    let mut machine_ids = HashSet::new();
    for machine in &machines {
        let auth = Auth::machine("validation", machine.machine_id, 0);
        let panel = if machine
            .template
            .runtime
            .get("allow_loopback_http")
            .and_then(serde_json::Value::as_bool)
            == Some(true)
        {
            Panel::new_for_test(&machine.panel_url, auth)
        } else {
            Panel::new(&machine.panel_url, auth)
        }?;
        if !machine_ids.insert(panel.traffic_identity())
            || machine.template.health_port > 0
                && !health_ports.insert(machine.template.health_port)
        {
            return Err("duplicate machine or health port".into());
        }
    }
    if nodes.is_empty() && machines.is_empty() {
        return Err("fleet has no nodes or machines".into());
    }
    if let Some(resolution) = traffic {
        if fleet
            || nodes.len() != 1
            || !machines.is_empty()
            || nodes[0]
                .settings
                .as_ref()
                .is_some_and(|s| s.standalone.is_some())
        {
            return Err("use a single-panel node configuration for traffic reconciliation".into());
        }
        let config = &nodes[0].runtime;
        let panel = panel_for_config(config, auth(config, "local-inspection".into()))?;
        let mut outbox =
            node_runtime::traffic::Outbox::open(&config.state_dir, panel.traffic_identity())?;
        if let Some((id, delivered)) = resolution {
            outbox.resolve(id, delivered)?;
        }
        println!("{}", outbox.status());
        return Ok(());
    }
    if check {
        println!(
            "runtime/fleet settings valid; panel reachability, certificates and data plane have not been tested"
        );
        return Ok(());
    }
    let health_groups = node_runtime::health_fleet::prepare(&mut nodes);
    let (stop_tx, stop_rx) = watch::channel(false);
    let signals = stop_tx.clone();
    let signal = node_runtime::OwnedTask::new(tokio::spawn(async move {
        wait_for_shutdown().await;
        let _ = signals.send(true);
    }));
    let services = Services::new(secrets, stop_rx.clone());
    let claims = Arc::new(node_runtime::fleet::Claims::default());
    let mut static_nodes = Vec::new();
    for node in nodes {
        let claim = claims.acquire(node_identity(&node)?, &node.runtime.state_dir)?;
        static_nodes.push((node, claim));
    }
    let mut tasks = tokio::task::JoinSet::new();
    for group in health_groups {
        let stop = stop_rx.clone();
        tasks.spawn(async move {
            group
                .run(stop)
                .await
                .map_err(|error| Box::new(error) as Failure)
        });
    }
    for (node, claim) in static_nodes {
        let services = services.clone();
        let stop = stop_rx.clone();
        tasks.spawn(async move {
            let _claim = claim;
            run_restartable(node, services, stop).await
        });
    }
    for machine in machines {
        let services = services.clone();
        let stop = stop_rx.clone();
        let claims = claims.clone();
        tasks.spawn(async move { run_machine(machine, services, claims, stop).await });
    }
    let mut failure = None;
    while let Some(completed) = tasks.join_next().await {
        match completed {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                eprintln!("fleet worker stopped: {error}");
                failure = Some(error);
                let _ = stop_tx.send(true);
            }
            Err(_) => {
                failure = Some("fleet worker failed".into());
                let _ = stop_tx.send(true);
            }
        }
    }
    let _ = stop_tx.send(true);
    services.join().await;
    signal.abort();
    let _ = signal.await;
    match failure {
        Some(error) => Err(error),
        None => Ok(()),
    }
}
fn read_bounded(path: &Path, max: usize) -> Result<Vec<u8>, Failure> {
    let mut bytes = Vec::new();
    File::open(path)
        .map_err(|_| "configuration file unavailable")?
        .take(max as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > max {
        return Err("configuration exceeds size limit".into());
    }
    Ok(bytes)
}
fn import_yaml(args: &[String]) -> Result<(), Failure> {
    if args.len() < 4 || !args.len().is_multiple_of(2) {
        return Err("invalid import arguments; use --help".into());
    }
    let mut output = None;
    let mut private = None;
    let mut cwd = std::env::current_dir()?;
    for pair in args[2..].as_chunks::<2>().0 {
        match pair[0].as_str() {
            "--output" if output.is_none() => output = Some(PathBuf::from(&pair[1])),
            "--secrets-output" if private.is_none() => private = Some(PathBuf::from(&pair[1])),
            "--original-cwd" => cwd = PathBuf::from(&pair[1]),
            _ => return Err("invalid import arguments".into()),
        }
    }
    let output = output.ok_or("import output is required")?;
    if !cwd.is_absolute() {
        return Err("original working directory must be absolute".into());
    }
    let input = String::from_utf8(read_bounded(Path::new(&args[1]), 4 * 1024 * 1024)?)
        .map_err(|_| "YAML must be UTF-8")?;
    let imported =
        node_admin::import_go_yaml_with_working_directory(&input, Path::new(&args[1]), &cwd)?;
    imported
        .fleet
        .validate_runtime_features(administration::RUNTIME_FEATURES)?;
    if output.exists() || private.as_ref().is_some_and(|p| p.exists()) {
        return Err("import destinations already exist; select new output paths".into());
    }
    if !imported.secrets.is_empty() && private.is_none() {
        return Err("inline YAML secrets require --secrets-output <private.json>".into());
    }
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = options.open(&output)?;
    let result = (|| -> Result<(), Failure> {
        let data = serde_json::to_vec_pretty(&imported.fleet)?;
        if let Some(path) = &private {
            imported.secrets.write_private_json(path)?;
        }
        file.write_all(&data)?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        drop(file);
        let _ = std::fs::remove_file(&output);
        return result;
    }
    println!(
        "Imported {} nodes and {} machines. Public fleet contains references; private values are not printed.",
        imported.fleet.nodes.len(),
        imported.fleet.machines.len()
    );
    Ok(())
}
fn validate_nodes(nodes: &[PreparedNode]) -> Result<(), Failure> {
    let mut identities = HashSet::new();
    let mut dirs: HashSet<PathBuf> = HashSet::new();
    for node in nodes {
        let c = &node.runtime;
        let directory = node_runtime::fleet::state_identity(&c.state_dir)?;
        if !identities.insert(node_identity(node)?)
            || dirs
                .iter()
                .any(|held| held.starts_with(&directory) || directory.starts_with(held))
        {
            return Err("duplicate or overlapping fleet destination/state directory".into());
        }
        dirs.insert(directory);
    }
    Ok(())
}
fn node_identity(node: &PreparedNode) -> Result<String, Failure> {
    if let Some(settings) = &node.settings
        && settings.standalone.is_some()
    {
        Ok(serde_json::json!(["standalone", settings.instance_id, settings.id]).to_string())
    } else {
        Ok(
            panel_for_config(&node.runtime, auth(&node.runtime, "validation".into()))?
                .traffic_identity(),
        )
    }
}
async fn run_restartable(
    node: PreparedNode,
    services: Arc<Services>,
    mut stop: watch::Receiver<bool>,
) -> Result<(), Failure> {
    let log = Arc::new(node_runtime::logging::Log::new(
        node.settings
            .as_ref()
            .map(|s| s.log.level.as_str())
            .unwrap_or("info"),
        node.settings
            .as_ref()
            .map(|s| s.log.output.as_str())
            .unwrap_or("stderr"),
        node.settings
            .as_ref()
            .map(|s| format!("{}/{}", s.instance_id, s.id))
            .unwrap_or_else(|| node.runtime.node_id.to_string()),
    )?);
    let mut delay = 1u64;
    loop {
        if *stop.borrow() {
            return Ok(());
        }
        node.health.update(false, &Default::default(), Some(0));
        node.health.clear_activity();
        if let Err(error) =
            run_config(node.clone(), services.clone(), log.clone(), stop.clone()).await
        {
            log.write(
                "error",
                &format!("node {} stopped: {error}", node.runtime.node_id),
            );
        }
        if *stop.borrow() {
            return Ok(());
        }
        tokio::select! {_=tokio::time::sleep(Duration::from_secs(delay))=>{},changed=stop.changed()=>{if changed.is_err(){return Ok(());}}}
        delay = (delay * 2).min(60);
    }
}
async fn run_config(
    node: PreparedNode,
    services: Arc<Services>,
    log: Arc<node_runtime::logging::Log>,
    stop_rx: watch::Receiver<bool>,
) -> Result<(), Failure> {
    let config = node.runtime;
    let settings = node.settings;
    let health = node.health;
    let local = settings
        .as_ref()
        .and_then(|settings| settings.standalone.clone())
        .map(|reference| {
            Arc::new(administration::LocalSource {
                reference,
                secrets: services.secrets.clone(),
            }) as Arc<dyn administration::LocalSnapshotSource>
        });
    let token = if local.is_some() {
        "standalone-unused".into()
    } else {
        services
            .secrets
            .get(&config.token_env)
            .ok_or("panel token reference is missing")?
            .expose()
            .to_owned()
    };
    let auth = auth(&config, token);
    let panel = panel_for_config(&config, auth.clone())?;
    let tuning = settings
        .as_ref()
        .map(|s| s.websocket.clone())
        .unwrap_or_default();
    let backoff_initial = tuning.backoff_initial.max(1);
    let backoff_max = if tuning.backoff_max == 0 {
        60
    } else {
        tuning.backoff_max
    };
    if backoff_max < backoff_initial {
        return Err("websocket backoff maximum is below initial delay".into());
    }
    let ws = if config.websocket {
        match panel.handshake().await {
            Ok(handshake) if handshake.websocket.enabled => match WsClient::for_panel(
                &config.panel_url,
                &handshake.websocket.ws_url,
                auth,
                Duration::from_secs(backoff_initial),
                Duration::from_secs(backoff_max),
            ) {
                Ok(client) => Some(client.with_tuning(
                    Duration::from_secs(if tuning.handshake_timeout == 0 {
                        15
                    } else {
                        tuning.handshake_timeout
                    }),
                    Duration::from_secs(30),
                )?),
                Err(_) => {
                    log.write(
                        "warn",
                        "websocket endpoint rejected; REST polling remains active",
                    );
                    None
                }
            },
            _ => None,
        }
    } else {
        None
    };
    let builtin = config.singbox_executable.is_none();
    let traffic_enabled = config.traffic_reporting.unwrap_or(builtin);
    let mut args = if builtin {
        vec![
            "run".into(),
            "--traffic-enabled".into(),
            traffic_enabled.to_string(),
        ]
    } else {
        vec!["run".into()]
    };
    if builtin && traffic_enabled {
        args.extend([
            "--traffic-state".into(),
            config.state_dir.to_string_lossy().into_owned(),
            "--traffic-destination".into(),
            node_native::traffic_destination(&panel.traffic_identity()),
            "--traffic-checkpoint-ms".into(),
            config.traffic_checkpoint_ms.to_string(),
        ]);
    }
    args.push("-c".into());
    let state = config.state_dir.clone();
    let executable = config
        .singbox_executable
        .clone()
        .unwrap_or(std::env::current_exe()?);
    let mut kernel = SingBoxProcessKernel::new(
        SingBoxProcessKernelConfig {
            executable,
            args,
            state_dir: state.clone(),
            readiness_timeout: Duration::from_secs(30),
            readiness_addr: None,
        },
        if builtin {
            SingBoxConfigBuilder::native()
                .with_dns(config.dns.clone())
                .with_geo_data_dir(
                    settings
                        .as_ref()
                        .map(|settings| settings.kernel.geo_data_dir.clone()),
                )
        } else {
            SingBoxConfigBuilder::new()
        },
    )
    .without_environment([config.token_env.clone()]);
    if builtin || config.native_user_updates {
        kernel = kernel.with_native_user_updates()?;
    }
    #[cfg(unix)]
    if config.embedded {
        kernel = kernel.with_embedded(Arc::new(node_runtime::embedded::Launcher(
            tokio::runtime::Handle::current(),
        )));
    }
    let health_port = settings
        .as_ref()
        .map(|settings| settings.health_port)
        .unwrap_or(0);
    let periods = settings
        .as_ref()
        .map(|s| s.intervals.clone())
        .unwrap_or_default();
    let track = if periods.track_interval == 0 {
        config.report_seconds.min(60)
    } else {
        periods.track_interval
    };
    let device = if periods.device_report_interval == 0 {
        60
    } else {
        periods.device_report_interval
    };
    let hook = administration::Hook::new(settings, state.clone(), services);
    let mut runtime = NodeRuntime::new(panel, kernel, config.node_id)
        .with_administration(
            hook,
            local.clone(),
            health.clone(),
            state.clone(),
            Duration::from_secs(track),
            if builtin {
                Some(Duration::from_secs(device))
            } else {
                None
            },
        )
        .with_status_period(if builtin && local.is_none() {
            Some(Duration::from_secs(if tuning.status_interval == 0 {
                60
            } else {
                tuning.status_interval
            }))
        } else {
            None
        })
        .with_log(log.clone());
    if traffic_enabled {
        runtime = runtime.with_traffic(&state, Duration::from_secs(config.report_seconds))?;
    }
    let health_task = if health_port > 0 {
        Some(health.listen(health_port).await?)
    } else {
        None
    };
    let result = runtime
        .run(Duration::from_secs(config.poll_seconds), ws, stop_rx)
        .await;
    log.write("info", &serde_json::to_string(runtime.metrics())?);
    if let Some(task) = health_task {
        task.shutdown().await;
    }
    result?;
    Ok(())
}
struct DiscoveredNode {
    kind: String,
    stop: watch::Sender<bool>,
    task: Option<tokio::task::JoinHandle<Result<(), Failure>>>,
    health: Arc<observations::Health>,
    _claim: node_runtime::fleet::Claim,
}
impl Drop for DiscoveredNode {
    fn drop(&mut self) {
        let _ = self.stop.send(true);
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}
async fn run_machine(
    machine: node_admin::MachineConfig,
    services: Arc<Services>,
    claims: Arc<node_runtime::fleet::Claims>,
    mut stop: watch::Receiver<bool>,
) -> Result<(), Failure> {
    let token = services
        .secrets
        .get(&machine.token_env)
        .ok_or("machine token reference is missing")?
        .expose()
        .to_owned();
    let c = RuntimeConfig {
        panel_url: machine.panel_url.clone(),
        machine_id: Some(machine.machine_id),
        node_id: 1,
        token_env: machine.token_env.clone(),
        state_dir: machine.state_dir.clone(),
        embedded: true,
        dns: None,
        allow_loopback_http: machine
            .template
            .runtime
            .get("allow_loopback_http")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false),
        node_type: None,
        singbox_executable: None,
        poll_seconds: 30,
        websocket: false,
        native_user_updates: true,
        traffic_reporting: Some(true),
        report_seconds: 60,
        traffic_checkpoint_ms: 1000,
    };
    let panel = panel_for_config(&c, Auth::machine(token, machine.machine_id, 0))?;
    let discovery = machine.template.websocket.discovery_interval;
    let mut period = tokio::time::interval(Duration::from_secs(if discovery == 0 {
        60
    } else {
        discovery
    }));
    period.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let health = Arc::new(observations::Health::default());
    let health_task = if machine.template.health_port > 0 {
        Some(health.clone().listen(machine.template.health_port).await?)
    } else {
        None
    };
    let mut nodes: HashMap<u32, DiscoveredNode> = HashMap::new();
    let mut discovery_ready = false;
    let mut health_period = tokio::time::interval(Duration::from_secs(1));
    health_period.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut collector = observations::Collector::default();
    let _ = collector.sample(&machine.state_dir);
    let mut status_period = tokio::time::interval(Duration::from_secs(
        if machine.template.websocket.status_interval == 0 {
            60
        } else {
            machine.template.websocket.status_interval
        },
    ));
    status_period.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    while !*stop.borrow() {
        tokio::select! {changed=stop.changed()=>{if changed.is_err(){break;}},_=health_period.tick()=>{health.update_fleet(nodes.iter().map(|(id,node)|(*id,node.health.clone())),discovery_ready);},_=status_period.tick()=>{let status=collector.sample(&machine.state_dir);if status.get("cpu").is_some() && status.get("mem").is_some(){let result=tokio::select!{_=stop.changed()=>{break;},result=panel.machine_status(status)=>result};if let Err(error)=result {eprintln!("machine {} status failed: {error}",machine.machine_id);}}},_=period.tick()=>{
            let result=tokio::select! {changed=stop.changed()=>{let _=changed;break;},result=panel.machine_nodes()=>result};
            match result {Err(error)=>{discovery_ready=false;eprintln!("machine {} discovery failed: {error}",machine.machine_id);health.update_fleet(nodes.iter().map(|(id,node)|(*id,node.health.clone())),false);},Ok(discovered)=>{
                discovery_ready=true;
                let wanted:HashMap<_,_>=discovered.iter().map(|n|(n.id,n.kind.as_str())).collect();
                health.expect_nodes(wanted.len());
                let removed:Vec<_>=nodes.iter().filter(|(id,node)|wanted.get(id).is_none_or(|kind|**kind!=node.kind) || node.task.as_ref().is_none_or(|task|task.is_finished())).map(|(id,_)|*id).collect();
                for id in removed {if let Some(mut node)=nodes.remove(&id){let _=node.stop.send(true);if let Some(task)=node.task.take() && !matches!(task.await,Ok(Ok(()))){eprintln!("machine node {id} worker failed during removal");}}}
                for entry in discovered {if nodes.contains_key(&entry.id){continue;}let mut settings=match machine.expand(entry.id,&entry.kind){Ok(settings)=>settings,Err(_)=>{eprintln!("machine node {} has invalid settings",entry.id);continue;}};settings.runtime["machine_id"]=serde_json::json!(machine.machine_id);settings.runtime["token_env"]=serde_json::json!(machine.token_env);settings.runtime["panel_url"]=serde_json::json!(machine.panel_url);
                    // The machine health endpoint aggregates the actual nodes.
                    settings.health_port=0;
                    let node=match PreparedNode::imported(settings){Ok(node)=>node,Err(_)=>{eprintln!("machine node {} rejected by configuration validation",entry.id);continue;}};let identity=panel_for_config(&node.runtime,auth(&node.runtime,"validation".into()))?.traffic_identity();
                    let claim=match claims.acquire(identity,&node.runtime.state_dir){Ok(claim)=>claim,Err(_)=>{eprintln!("machine node {} rejected: duplicate destination/state or fleet capacity reached",entry.id);continue;}};
                    let node_health=node.health.clone();let(node_stop,node_rx)=watch::channel(false);let services=services.clone();let task=tokio::spawn(async move{run_restartable(node,services,node_rx).await});nodes.insert(entry.id,DiscoveredNode {kind:entry.kind,stop:node_stop,task:Some(task),health:node_health,_claim:claim});
                }
                health.update_fleet(nodes.iter().map(|(id,node)|(*id,node.health.clone())),true);
            }}
        }}
    }
    for node in nodes.values() {
        let _ = node.stop.send(true);
    }
    for mut node in nodes.into_values() {
        if let Some(task) = node.task.take()
            && !matches!(task.await, Ok(Ok(())))
        {
            eprintln!("machine node worker failed during shutdown");
        }
    }
    health.expect_nodes(0);
    health.update_fleet(std::iter::empty(), false);
    if let Some(server) = health_task {
        server.shutdown().await;
    }
    Ok(())
}
fn auth(config: &RuntimeConfig, token: String) -> Auth {
    match config.machine_id {
        Some(id) => Auth::machine(token, id, config.node_id),
        None => Auth::legacy(
            token,
            config.node_id,
            config.node_type.clone().unwrap_or_default(),
        ),
    }
}
fn panel_for_config(config: &RuntimeConfig, auth: Auth) -> Result<Panel, node_panel::PanelError> {
    if config.allow_loopback_http {
        Panel::new_for_test(&config.panel_url, auth)
    } else {
        Panel::new(&config.panel_url, auth)
    }
}
async fn wait_for_shutdown() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        if let Ok(mut term) = signal(SignalKind::terminate()) {
            tokio::select! {_=tokio::signal::ctrl_c()=>{},_=term.recv()=>{}}
            return;
        }
    }
    let _ = tokio::signal::ctrl_c().await;
}
