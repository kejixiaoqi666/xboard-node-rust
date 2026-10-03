//! SIP003 external transport-plugin process contract. Listener ownership,
//! readiness and graceful termination belong to the caller's runtime.
use node_session::Destination;
use std::{ffi::OsString, io, net::SocketAddr, path::PathBuf, process::Stdio};

#[derive(Clone)]
pub struct Sip003Config {
    /// An explicitly configured executable; no shell or PATH lookup is used.
    pub binary: PathBuf,
    pub arguments: Vec<OsString>,
    /// Plugin-specific options may contain credentials and are never Debug logged.
    pub options: Option<OsString>,
}
impl std::fmt::Debug for Sip003Config {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Sip003Config")
            .field("binary", &self.binary)
            .field("arguments", &"[REDACTED]")
            .field("options", &"[REDACTED]")
            .finish()
    }
}
impl Sip003Config {
    /// Build an owned command for a SIP003 plugin. In server mode `remote` is
    /// the public listener and `local` is the private native SS listener. The
    /// configured options select the plugin's server mode, as defined by SIP003.
    pub fn command(
        &self,
        remote: &Destination,
        local: SocketAddr,
    ) -> io::Result<tokio::process::Command> {
        Destination::new(remote.host.clone(), remote.port)?;
        if !self.binary.is_absolute()
            || !self.binary.is_file()
            || local.port() == 0
            || !local.ip().is_loopback()
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "SIP003 requires an absolute executable and private loopback endpoint",
            ));
        }
        let mut command = tokio::process::Command::new(&self.binary);
        command
            .args(&self.arguments)
            .env("SS_REMOTE_HOST", &remote.host)
            .env("SS_REMOTE_PORT", remote.port.to_string())
            .env("SS_LOCAL_HOST", local.ip().to_string())
            .env("SS_LOCAL_PORT", local.port().to_string())
            .env_remove("SS_PLUGIN_OPTIONS")
            .kill_on_drop(true)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        if let Some(options) = &self.options {
            command.env("SS_PLUGIN_OPTIONS", options);
        }
        #[cfg(windows)]
        {
            command.creation_flags(0x08000000);
        }
        Ok(command)
    }
}
