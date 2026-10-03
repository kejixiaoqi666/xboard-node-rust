use crate::user_control::{Replacement, UserControl, file_digest};
use crate::{EmbeddedLauncher, EmbeddedWorker};
use crate::{KernelAdapter, KernelError, KernelStatus};
use node_core::{NodeSpec, UserSpec};
use serde::Serialize;
use std::fs::{self, OpenOptions};
use std::io::{self, BufWriter, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

#[derive(Clone, Debug)]
pub struct ProcessKernelConfig {
    pub executable: PathBuf,
    pub args: Vec<String>,
    pub state_dir: PathBuf,
    pub readiness_timeout: Duration,
    pub readiness_addr: Option<SocketAddr>,
}

#[derive(Clone)]
pub struct ProcessKernel {
    config: ProcessKernelConfig,
    inner: Arc<Mutex<ProcessState>>,
    environment_remove: Vec<String>,
    native_user_updates: bool,
    embedded: Option<Arc<dyn EmbeddedLauncher>>,
}

#[derive(Default)]
struct ProcessState {
    child: Option<KernelChild>,
    active: Option<ProcessCandidate>,
    control: Option<UserControl>,
    // A successful structured traffic barrier is part of this child
    // lifecycle.  Do not issue the same bounded quiesce request again from
    // the generic stop path; on a slow embedded worker that would consume
    // the service manager's whole stop budget before the worker is reaped.
    quiesced: bool,
}

const MAX_CANDIDATE_BYTES: usize = 16 * 1024 * 1024;

struct LimitedWriter<W> {
    inner: W,
    remaining: usize,
}

impl<W: Write> Write for LimitedWriter<W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.remaining {
            return Err(io::Error::other("candidate exceeds 16 MiB"));
        }
        let written = self.inner.write(bytes)?;
        self.remaining -= written;
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

#[cfg(test)]
mod writer_tests {
    use super::{LimitedWriter, MAX_CANDIDATE_BYTES};
    use std::io::{self, Write};

    #[test]
    fn encoded_output_accepts_exact_limit_and_rejects_one_more_byte() {
        let mut value = "a".repeat(MAX_CANDIDATE_BYTES - 2);
        let mut writer = LimitedWriter {
            inner: io::sink(),
            remaining: MAX_CANDIDATE_BYTES,
        };
        serde_json::to_writer(&mut writer, &value).unwrap();
        assert_eq!(writer.remaining, 0);
        value.push('a');
        let mut writer = LimitedWriter {
            inner: io::sink(),
            remaining: MAX_CANDIDATE_BYTES,
        };
        assert!(serde_json::to_writer(&mut writer, &value).is_err());
    }

    #[test]
    fn partial_writes_charge_only_successfully_written_bytes() {
        struct Partial(Vec<u8>);
        impl Write for Partial {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                let size = bytes.len().min(2);
                self.0.extend_from_slice(&bytes[..size]);
                Ok(size)
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let mut writer = LimitedWriter {
            inner: Partial(Vec::new()),
            remaining: 5,
        };
        writer.write_all(b"12345").unwrap();
        assert_eq!(writer.inner.0, b"12345");
        assert_eq!(writer.remaining, 0);
        assert!(writer.write_all(b"6").is_err());
        assert_eq!(writer.inner.0, b"12345");
    }
}

enum KernelChild {
    Process(Child),
    Embedded(Box<dyn EmbeddedWorker>),
}
struct Exit(bool);
impl Exit {
    fn success(&self) -> bool {
        self.0
    }
}
impl KernelChild {
    fn try_wait(&mut self) -> io::Result<Option<Exit>> {
        match self {
            Self::Process(child) => child
                .try_wait()
                .map(|exit| exit.map(|status| Exit(status.success()))),
            Self::Embedded(worker) => worker
                .running()
                .map(|running| if running { None } else { Some(Exit(false)) }),
        }
    }
    fn kill(&mut self) -> io::Result<()> {
        match self {
            Self::Process(child) => child.kill(),
            Self::Embedded(worker) => worker.stop(),
        }
    }
    fn wait(&mut self) -> io::Result<Exit> {
        match self {
            Self::Process(child) => child.wait().map(|exit| Exit(exit.success())),
            Self::Embedded(worker) => worker.stop().map(|()| Exit(true)),
        }
    }
}
fn terminate(child: &mut KernelChild) -> Result<(), KernelError> {
    if child
        .try_wait()
        .map_err(|_| KernelError::Activate("child status unavailable".into()))?
        .is_none()
    {
        child
            .kill()
            .map_err(|_| KernelError::Activate("could not stop child".into()))?;
    }
    child
        .wait()
        .map_err(|_| KernelError::Activate("could not reap child".into()))?;
    Ok(())
}

impl Drop for ProcessState {
    fn drop(&mut self) {
        if let Some(child) = &mut self.child {
            let _ = terminate(child);
        }
    }
}

#[derive(Serialize)]
struct ProcessConfig<'a> {
    node: &'a NodeSpec,
    users: &'a [UserSpec],
}

/// Owns only a uniquely created candidate file, never an input configuration.
#[derive(Debug)]
pub struct ProcessCandidate {
    config_path: PathBuf,
    listener_port: u16,
    readiness_addr: Option<SocketAddr>,
}
impl Drop for ProcessCandidate {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.config_path);
    }
}

impl ProcessKernel {
    pub fn new(config: ProcessKernelConfig) -> Self {
        Self {
            config,
            inner: Arc::new(Mutex::new(ProcessState::default())),
            environment_remove: Vec::new(),
            native_user_updates: false,
            embedded: None,
        }
    }

    pub fn stop(&self) -> Result<(), KernelError> {
        let mut state = self
            .inner
            .lock()
            .map_err(|_| KernelError::Rollback("lock poisoned".into()))?;
        self.quiesce_before_restart(&mut state);
        if let Some(child) = &mut state.child {
            terminate(child)?;
        }
        state.child = None;
        state.control = None;
        state.quiesced = false;
        state.active = None;
        Ok(())
    }
    pub fn activity(&self) -> Result<node_core::ActivitySnapshot, KernelError> {
        let state = self
            .inner
            .lock()
            .map_err(|_| KernelError::Activate("lock poisoned".into()))?;
        let control = state
            .control
            .as_ref()
            .ok_or_else(|| KernelError::Activate("activity control unavailable".into()))?;
        crate::traffic_control::activity(&control.path)
    }
    pub fn traffic_snapshot(&self) -> Result<Option<node_core::TrafficSnapshot>, KernelError> {
        let state = self
            .inner
            .lock()
            .map_err(|_| KernelError::Activate("lock poisoned".into()))?;
        let control = state
            .control
            .as_ref()
            .ok_or_else(|| KernelError::Activate("traffic control unavailable".into()))?;
        crate::traffic_control::snapshot(&control.path)
    }
    pub fn traffic_ack(&self, snapshot: &node_core::TrafficSnapshot) -> Result<(), KernelError> {
        let state = self
            .inner
            .lock()
            .map_err(|_| KernelError::Activate("lock poisoned".into()))?;
        let control = state
            .control
            .as_ref()
            .ok_or_else(|| KernelError::Activate("traffic control unavailable".into()))?;
        crate::traffic_control::ack(&control.path, snapshot)
    }
    pub fn traffic_quiesce(&self) -> Result<bool, KernelError> {
        let mut state = self
            .inner
            .lock()
            .map_err(|_| KernelError::Activate("lock poisoned".into()))?;
        if state.quiesced {
            return Ok(true);
        }
        let control = state
            .control
            .as_ref()
            .ok_or_else(|| KernelError::Activate("traffic control unavailable".into()))?;
        crate::traffic_control::quiesce(&control.path)?;
        state.quiesced = true;
        Ok(true)
    }
    fn quiesce_before_restart(&self, state: &mut ProcessState) {
        if state.quiesced {
            return;
        }
        if self.config.args.iter().any(|arg| arg == "--traffic-state")
            && state
                .child
                .as_mut()
                .is_some_and(|child| matches!(child.try_wait(), Ok(None)))
            && let Some(control) = &state.control
        {
            if crate::traffic_control::quiesce(&control.path).is_ok() {
                state.quiesced = true;
            } else {
                eprintln!(
                    "native final checkpoint unconfirmed; recovery is limited to the last durable checkpoint"
                );
            }
        }
    }
    pub fn without_environment(mut self, keys: impl IntoIterator<Item = String>) -> Self {
        self.environment_remove = keys.into_iter().collect();
        self
    }
    pub fn with_embedded(mut self, launcher: Arc<dyn EmbeddedLauncher>) -> Self {
        self.embedded = Some(launcher);
        self
    }
    pub(crate) fn with_native_user_updates(mut self) -> Result<Self, KernelError> {
        if !cfg!(unix) {
            return Err(KernelError::Invalid(
                "native user updates require Unix".into(),
            ));
        }
        self.native_user_updates = true;
        Ok(self)
    }
    fn command(&self) -> Command {
        let mut command = Command::new(&self.config.executable);
        for key in &self.environment_remove {
            command.env_remove(key);
        }
        command
    }

    fn validate_config(&self) -> Result<(), KernelError> {
        if self.config.executable.as_os_str().is_empty()
            || self.config.state_dir.as_os_str().is_empty()
        {
            return Err(KernelError::Prepare(
                "empty executable or state directory".into(),
            ));
        }
        if self.config.args.len() > 64 || self.config.args.iter().any(|arg| arg.len() > 4096) {
            return Err(KernelError::Prepare(
                "command arguments exceed bounds".into(),
            ));
        }
        if self.config.readiness_timeout.is_zero()
            || self.config.readiness_timeout > Duration::from_secs(30)
        {
            return Err(KernelError::Prepare(
                "readiness timeout must be within (0, 30s]".into(),
            ));
        }
        Ok(())
    }

    pub(crate) fn prepare_bytes(
        &self,
        bytes: &[u8],
        port: u16,
        address: Option<SocketAddr>,
    ) -> Result<ProcessCandidate, KernelError> {
        self.validate_config()?;
        if bytes.len() > MAX_CANDIDATE_BYTES {
            return Err(KernelError::Prepare("candidate exceeds 16 MiB".into()));
        }
        self.prepare_with_writer(port, address, |file| {
            file.write_all(bytes)
                .map_err(|_| KernelError::Prepare("could not persist candidate".into()))
        })
    }

    pub(crate) fn prepare_serialized<T: Serialize>(
        &self,
        value: &T,
        port: u16,
        address: Option<SocketAddr>,
    ) -> Result<ProcessCandidate, KernelError> {
        self.prepare_with_writer(port, address, |file| {
            let mut writer = LimitedWriter {
                inner: BufWriter::with_capacity(64 * 1024, file),
                remaining: MAX_CANDIDATE_BYTES,
            };
            serde_json::to_writer(&mut writer, value)
                .map_err(|e| KernelError::Prepare(format!("encode sing-box config: {e}")))?;
            writer
                .flush()
                .map_err(|_| KernelError::Prepare("could not persist candidate".into()))
        })
    }

    fn prepare_with_writer(
        &self,
        port: u16,
        address: Option<SocketAddr>,
        write: impl FnOnce(&mut fs::File) -> Result<(), KernelError>,
    ) -> Result<ProcessCandidate, KernelError> {
        self.validate_config()?;
        let mut directory = fs::DirBuilder::new();
        directory.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            directory.mode(0o700);
        }
        directory
            .create(&self.config.state_dir)
            .map_err(|_| KernelError::Prepare("could not create state directory".into()))?;
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        let path = self
            .config
            .state_dir
            .join(format!("candidate-{}-{id}.json", std::process::id()));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options
            .open(&path)
            .map_err(|_| KernelError::Prepare("could not create unique candidate".into()))?;
        let candidate = ProcessCandidate {
            config_path: path,
            listener_port: port,
            readiness_addr: address,
        };
        write(&mut file)?;
        file.sync_all()
            .map_err(|_| KernelError::Prepare("could not persist candidate".into()))?;
        Ok(candidate)
    }

    pub(crate) fn check_candidate(&self, candidate: &ProcessCandidate) -> Result<(), KernelError> {
        if let Some(launcher) = &self.embedded {
            return launcher.check(&self.config.args, &candidate.config_path);
        }
        let mut args = self.config.args.clone();
        if args.first().is_some_and(|arg| arg == "run") {
            args[0] = "check".into();
        } else {
            return Err(KernelError::Prepare(
                "sing-box command must start with run".into(),
            ));
        }
        let mut child = KernelChild::Process(
            self.command()
                .args(args)
                .arg(&candidate.config_path)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .map_err(|_| KernelError::Prepare("could not start config check".into()))?,
        );
        let deadline = Instant::now() + self.config.readiness_timeout;
        loop {
            match child.try_wait() {
                Ok(Some(status)) if status.success() => return Ok(()),
                Ok(Some(_)) => {
                    return Err(KernelError::Prepare("kernel rejected configuration".into()));
                }
                Err(_) => {
                    let _ = terminate(&mut child);
                    return Err(KernelError::Prepare(
                        "config check status unavailable".into(),
                    ));
                }
                Ok(None) => {}
            }
            if Instant::now() >= deadline {
                let _ = terminate(&mut child);
                return Err(KernelError::Prepare("config check timed out".into()));
            }
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn launch(
        &self,
        candidate: &ProcessCandidate,
    ) -> Result<(KernelChild, Option<UserControl>), KernelError> {
        // A listener from another process must not make this child look ready.
        if candidate.readiness_addr.is_some_and(|addr| {
            TcpStream::connect_timeout(&addr, Duration::from_millis(50)).is_ok()
        }) {
            return Err(KernelError::Activate(
                "candidate listener already occupied".into(),
            ));
        }
        let mut command = self.command();
        command.args(&self.config.args).arg(&candidate.config_path);
        let control = if self.native_user_updates {
            static NEXT_CONTROL: AtomicU64 = AtomicU64::new(0);
            let id = NEXT_CONTROL.fetch_add(1, Ordering::Relaxed);
            let path = self
                .config
                .state_dir
                .join(format!("u-{}-{id}.sock", std::process::id()));
            if std::fs::symlink_metadata(&path).is_ok() {
                return Err(KernelError::Activate(
                    "control socket path already exists".into(),
                ));
            }
            // Reject excessive Unix paths before starting a child.
            #[cfg(unix)]
            socket2::SockAddr::unix(&path)
                .map_err(|_| KernelError::Activate("control socket path too long".into()))?;
            command.arg("--control-socket").arg(&path);
            Some(UserControl { path })
        } else {
            None
        };
        let digest = if control.is_some() {
            Some(file_digest(&candidate.config_path)?)
        } else {
            None
        };
        let mut child = if let Some(launcher) = &self.embedded {
            KernelChild::Embedded(launcher.start(
                &self.config.args,
                &candidate.config_path,
                control.as_ref().map(|c| c.path.as_path()),
            )?)
        } else {
            KernelChild::Process(
                command
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
                    .map_err(|_| KernelError::Activate("could not spawn kernel".into()))?,
            )
        };
        let started = Instant::now();
        let deadline = started + self.config.readiness_timeout;
        loop {
            match child.try_wait() {
                Ok(Some(_)) => {
                    return Err(KernelError::Activate(
                        "candidate exited before readiness".into(),
                    ));
                }
                Err(_) => {
                    let _ = terminate(&mut child);
                    return Err(KernelError::Activate("readiness status unavailable".into()));
                }
                Ok(None) => {}
            }
            let listener_ready = match candidate.readiness_addr {
                Some(addr) => TcpStream::connect_timeout(&addr, Duration::from_millis(50)).is_ok(),
                None if control.is_some() => true,
                None => Instant::now() >= deadline,
            };
            let control_ready = match (&control, &digest) {
                (Some(control), Some(digest)) if listener_ready => {
                    control.status_digest().is_ok_and(|value| value == *digest)
                }
                (None, None) => true,
                _ => false,
            };
            if listener_ready
                && control_ready
                && started.elapsed()
                    >= self
                        .config
                        .readiness_timeout
                        .min(Duration::from_millis(100))
            {
                return Ok((child, control));
            }
            if Instant::now() >= deadline {
                let _ = terminate(&mut child);
                return Err(KernelError::Activate(
                    "listener readiness probe timed out".into(),
                ));
            }
            thread::sleep(Duration::from_millis(10));
        }
    }
}

impl KernelAdapter for ProcessKernel {
    type Candidate = ProcessCandidate;
    fn name(&self) -> &'static str {
        "external-process"
    }

    fn prepare(
        &self,
        config: &NodeSpec,
        users: &[UserSpec],
    ) -> Result<Self::Candidate, KernelError> {
        node_core::RuntimeState::new(config.clone(), users.to_vec())
            .map_err(|e| KernelError::Invalid(e.to_string()))?;
        let bytes = serde_json::to_vec(&ProcessConfig {
            node: config,
            users,
        })
        .map_err(|_| KernelError::Prepare("could not encode candidate".into()))?;
        let addr = self
            .config
            .readiness_addr
            .map(|addr| SocketAddr::new(addr.ip(), config.server_port));
        self.prepare_bytes(&bytes, config.server_port, addr)
    }

    fn activate(&self, candidate: Self::Candidate) -> Result<(), KernelError> {
        let mut state = self
            .inner
            .lock()
            .map_err(|_| KernelError::Activate("lock poisoned".into()))?;
        if self.native_user_updates
            && state
                .child
                .as_mut()
                .is_some_and(|child| matches!(child.try_wait(), Ok(None)))
        {
            let previous = state
                .active
                .as_ref()
                .ok_or_else(|| KernelError::Activate("active candidate unavailable".into()))?;
            let previous_digest = file_digest(&previous.config_path)?;
            let next_digest = file_digest(&candidate.config_path)?;
            let control = state
                .control
                .as_ref()
                .ok_or_else(|| KernelError::Activate("native control unavailable".into()))?;
            match control.replace(&previous_digest, &next_digest, &candidate.config_path) {
                Replacement::Applied => {
                    state.active = Some(candidate);
                    state.quiesced = false;
                    return Ok(());
                }
                Replacement::RestartRequired => {}
                Replacement::Rejected => {
                    return Err(KernelError::Activate(
                        "native user update rejected; previous snapshot retained".into(),
                    ));
                }
                Replacement::Uncertain => {
                    // Do not keep serving an unknown user set while claiming
                    // the old snapshot. The runtime recovers last-known-good.
                    self.quiesce_before_restart(&mut state);
                    if let Some(child) = &mut state.child {
                        terminate(child)?;
                    }
                    state.child = None;
                    state.control = None;
                    state.quiesced = false;
                    return Err(KernelError::Activate(
                        "native update state unavailable; kernel stopped for recovery".into(),
                    ));
                }
            }
        }
        let same_listener = state
            .active
            .as_ref()
            .is_some_and(|active| active.listener_port == candidate.listener_port);
        // Persistent native counters have one writer across listener changes.
        // Stop the old writer before opening the replacement's same store.
        let restart_previous =
            same_listener || self.config.args.iter().any(|arg| arg == "--traffic-state");
        if restart_previous {
            // A validated same-port update has a short stop/start interruption.
            // Retain the previous private file until candidate readiness succeeds.
            self.quiesce_before_restart(&mut state);
            if let Some(child) = &mut state.child {
                terminate(child)?;
            }
            state.child = None;
            state.control = None;
            state.quiesced = false;
        }
        let (child, control) = match self.launch(&candidate) {
            Ok(child) => child,
            Err(error) => {
                if restart_previous && state.active.is_some() {
                    let old = state
                        .active
                        .as_ref()
                        .expect("same listener implies active candidate");
                    match self.launch(old) {
                        Ok((restored, restored_control)) => {
                            state.child = Some(restored);
                            state.control = restored_control;
                        }
                        Err(_) => {
                            return Err(KernelError::Rollback(
                                "candidate failed and previous listener could not be restored"
                                    .into(),
                            ));
                        }
                    }
                }
                return Err(error);
            }
        };
        if let Some(old) = &mut state.child
            && let Err(error) = terminate(old)
        {
            let mut candidate_child = child;
            let _ = terminate(&mut candidate_child);
            return Err(error);
        }
        state.child = Some(child);
        state.control = control;
        state.quiesced = false;
        state.active = Some(candidate);
        Ok(())
    }

    fn rollback(&self) -> Result<(), KernelError> {
        Ok(())
    }

    fn status(&self) -> KernelStatus {
        match self.inner.lock() {
            Ok(mut state) => match state.child.as_mut().map(KernelChild::try_wait) {
                Some(Ok(None)) => KernelStatus::Ready,
                _ => KernelStatus::Stopped,
            },
            Err(_) => KernelStatus::Stopped,
        }
    }
}
