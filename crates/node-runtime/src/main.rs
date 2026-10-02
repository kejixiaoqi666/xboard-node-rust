use node_kernel::{SingBoxConfigBuilder, SingBoxProcessKernel, SingBoxProcessKernelConfig};
use node_panel::{Auth, Panel, WsClient};
use node_runtime::{NodeRuntime, RuntimeConfig};
use std::{fs::File, io::Read, time::Duration};
use tokio::sync::watch;

fn main() {
    let result = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(2)
        .build()
        .map_err(|error| error.to_string())
        .and_then(|runtime| runtime.block_on(run()).map_err(|error| error.to_string()));
    if let Err(error) = result {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args
        .first()
        .is_some_and(|arg| matches!(arg.as_str(), "run" | "check"))
    {
        node_native::run_cli(&args).await?;
        return Ok(());
    }
    if args == ["--help"] || args.is_empty() {
        println!(
            "xboard-node-rust (experimental)\nUsage: xboard-node-rust --config <runtime.json> [--check | --traffic-status | --traffic-resolve <batch-id> delivered|not-delivered]\nToken is read from the environment variable named by token_env.\n--check validates runtime settings without contacting the panel or starting a kernel.\nTraffic status/reconciliation is local only; stop the node first and verify the exact uncertain batch against panel records before resolving it."
        );
        return Ok(());
    }
    if !(args.len() == 2
        || (args.len() == 3 && matches!(args[2].as_str(), "--check" | "--traffic-status"))
        || (args.len() == 5
            && args[2] == "--traffic-resolve"
            && matches!(args[4].as_str(), "delivered" | "not-delivered")))
        || args[0] != "--config"
    {
        return Err("invalid arguments; use --help".into());
    }
    let mut bytes = Vec::new();
    File::open(&args[1])
        .map_err(|_| "could not open runtime configuration")?
        .take(64 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > 64 * 1024 {
        return Err("runtime configuration exceeds 64 KiB".into());
    }
    let config: RuntimeConfig =
        serde_json::from_slice(&bytes).map_err(|_| "invalid runtime configuration JSON")?;
    config.validate()?;
    if args
        .get(2)
        .is_some_and(|arg| matches!(arg.as_str(), "--traffic-status" | "--traffic-resolve"))
    {
        // Destination validation uses a synthetic credential; no real token or
        // panel request is needed to inspect/reconcile the private local outbox.
        let panel = panel_for_config(&config, auth(&config, "local-inspection".into()))?;
        let mut outbox =
            node_runtime::traffic::Outbox::open(&config.state_dir, panel.traffic_identity())?;
        if args[2] == "--traffic-resolve" {
            let id = args[3]
                .parse::<u64>()
                .map_err(|_| "invalid traffic batch id")?;
            outbox.resolve(id, args[4] == "delivered")?;
        }
        println!("{}", outbox.status());
        return Ok(());
    }
    if args.last().is_some_and(|arg| arg == "--check") {
        // Validate URL/auth shape using a placeholder, without reading real credentials.
        let auth = auth(&config, "configuration-check-placeholder".into());
        panel_for_config(&config, auth)?;
        println!("runtime settings valid; kernel/panel compatibility not tested");
        return Ok(());
    }
    let token =
        std::env::var(&config.token_env).map_err(|_| "token environment variable is missing")?;
    let auth = auth(&config, token);
    let panel = panel_for_config(&config, auth.clone())?;
    let ws = if config.websocket {
        match panel.handshake().await {
            Ok(handshake) if handshake.websocket.enabled => match WsClient::for_panel(
                &config.panel_url,
                &handshake.websocket.ws_url,
                auth,
                Duration::from_secs(1),
                Duration::from_secs(60),
            ) {
                Ok(client) => Some(client),
                Err(_) => {
                    eprintln!("websocket endpoint is not trusted/valid; using REST polling");
                    None
                }
            },
            Ok(_) => None,
            Err(_) => {
                eprintln!("websocket handshake unavailable; using REST polling");
                None
            }
        }
    } else {
        None
    };
    let builtin = config.singbox_executable.is_none();
    let traffic_enabled = config.traffic_reporting.unwrap_or(builtin);
    let mut kernel_args = if builtin {
        vec![
            "run".into(),
            "--traffic-enabled".into(),
            traffic_enabled.to_string(),
        ]
    } else {
        vec!["run".into()]
    };
    if builtin && traffic_enabled {
        kernel_args.extend([
            "--traffic-state".into(),
            config.state_dir.to_string_lossy().into_owned(),
            "--traffic-destination".into(),
            node_native::traffic_destination(&panel.traffic_identity()),
            "--traffic-checkpoint-ms".into(),
            config.traffic_checkpoint_ms.to_string(),
        ]);
    }
    kernel_args.push("-c".into());
    let state_dir = config.state_dir.clone();
    let executable = match config.singbox_executable {
        Some(path) => path,
        None => std::env::current_exe()?,
    };
    let mut kernel = SingBoxProcessKernel::new(
        SingBoxProcessKernelConfig {
            executable,
            args: kernel_args,
            state_dir: config.state_dir,
            readiness_timeout: Duration::from_secs(5),
            readiness_addr: None,
        },
        if builtin {
            SingBoxConfigBuilder::native().with_dns(config.dns.clone())
        } else {
            SingBoxConfigBuilder::new()
        },
    )
    .without_environment([config.token_env.clone()]);
    if builtin || config.native_user_updates {
        kernel = kernel.with_native_user_updates()?;
    }
    let mut runtime = NodeRuntime::new(panel, kernel, config.node_id);
    if traffic_enabled {
        runtime = runtime.with_traffic(&state_dir, Duration::from_secs(config.report_seconds))?;
    }
    let (stop_tx, stop_rx) = watch::channel(false);
    tokio::spawn(async move {
        wait_for_shutdown().await;
        let _ = stop_tx.send(true);
    });
    runtime
        .run(Duration::from_secs(config.poll_seconds), ws, stop_rx)
        .await?;
    println!("{}", serde_json::to_string(runtime.metrics())?);
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
            tokio::select! { _ = tokio::signal::ctrl_c() => {}, _ = term.recv() => {} }
            return;
        }
    }
    let _ = tokio::signal::ctrl_c().await;
}
