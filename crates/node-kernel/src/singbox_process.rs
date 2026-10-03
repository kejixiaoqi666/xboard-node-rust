use crate::{
    KernelAdapter, KernelError, KernelStatus, ProcessCandidate, ProcessKernel, ProcessKernelConfig,
    SingBoxConfigBuilder,
};
use node_core::{NodeSpec, UserSpec};

pub struct SingBoxProcessKernel {
    process: ProcessKernel,
    builder: SingBoxConfigBuilder,
}

pub type SingBoxProcessKernelConfig = ProcessKernelConfig;

impl SingBoxProcessKernel {
    pub fn new(config: SingBoxProcessKernelConfig, builder: SingBoxConfigBuilder) -> Self {
        Self {
            process: ProcessKernel::new(config),
            builder,
        }
    }
    pub fn stop(&self) -> Result<(), KernelError> {
        self.process.stop()
    }
    pub fn traffic_snapshot(&self) -> Result<Option<node_core::TrafficSnapshot>, KernelError> {
        self.process.traffic_snapshot()
    }
    pub fn activity(&self) -> Result<node_core::ActivitySnapshot, KernelError> {
        self.process.activity()
    }
    pub fn traffic_ack(&self, snapshot: &node_core::TrafficSnapshot) -> Result<(), KernelError> {
        self.process.traffic_ack(snapshot)
    }
    pub fn traffic_quiesce(&self) -> Result<bool, KernelError> {
        self.process.traffic_quiesce()
    }
    pub fn without_environment(mut self, keys: impl IntoIterator<Item = String>) -> Self {
        self.process = self.process.without_environment(keys);
        self
    }
    pub fn with_embedded(mut self, launcher: std::sync::Arc<dyn crate::EmbeddedLauncher>) -> Self {
        self.process = self.process.with_embedded(launcher);
        self
    }
    /// Opt-in companion kernel; stock sing-box does not implement this protocol.
    pub fn with_native_user_updates(mut self) -> Result<Self, KernelError> {
        self.process = self.process.with_native_user_updates()?;
        Ok(self)
    }
}

impl KernelAdapter for SingBoxProcessKernel {
    type Candidate = ProcessCandidate;

    fn name(&self) -> &'static str {
        "sing-box"
    }

    fn prepare(
        &self,
        config: &NodeSpec,
        users: &[UserSpec],
    ) -> Result<Self::Candidate, KernelError> {
        let json = self.builder.serializable(config, users)?;
        let ip: std::net::IpAddr = config
            .listen_ip
            .as_deref()
            .unwrap_or("::")
            .parse()
            .map_err(|_| KernelError::Invalid("listen_ip must be an IP address".into()))?;
        let ip = if ip.is_unspecified() {
            if ip.is_ipv4() {
                "127.0.0.1".parse().unwrap()
            } else {
                "::1".parse().unwrap()
            }
        } else {
            ip
        };
        let candidate = self.process.prepare_serialized(
            &json,
            config.server_port,
            if matches!(config.protocol.as_str(), "hysteria2" | "tuic") {
                None
            } else {
                Some(std::net::SocketAddr::new(ip, config.server_port))
            },
        )?;
        self.process.check_candidate(&candidate)?;
        Ok(candidate)
    }

    fn activate(&self, candidate: Self::Candidate) -> Result<(), KernelError> {
        <ProcessKernel as KernelAdapter>::activate(&self.process, candidate)
    }

    fn rollback(&self) -> Result<(), KernelError> {
        self.process.rollback()
    }
    fn status(&self) -> KernelStatus {
        self.process.status()
    }
}
