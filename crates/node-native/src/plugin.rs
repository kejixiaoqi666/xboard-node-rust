//! Own the optional SIP003 child for the full listener lifetime.
use crate::{Error, config};
use std::{net::SocketAddr, time::Duration};
use tokio::{net::TcpStream, process::Child};

pub(crate) struct Process {
    child: Child,
    group: i32,
}
impl Process {
    pub(crate) async fn start(
        config: &config::Plugin,
        remote: SocketAddr,
        local: SocketAddr,
        shutdown: impl std::future::Future<Output = ()>,
    ) -> Result<Option<Self>, Error> {
        use std::os::unix::process::CommandExt;
        let reservation = tokio::net::TcpListener::bind(remote).await?;
        drop(reservation);
        let destination = node_session::Destination::new(remote.ip().to_string(), remote.port())?;
        let mut command = config.sip003().command(&destination, local)?;
        command.as_std_mut().process_group(0);
        let child = command.spawn()?;
        let group = child
            .id()
            .and_then(|id| i32::try_from(id).ok())
            .ok_or(Error::Task)?;
        let mut process = Self { child, group };
        let probe = SocketAddr::new(
            if remote.ip().is_unspecified() {
                if remote.is_ipv4() {
                    std::net::Ipv4Addr::LOCALHOST.into()
                } else {
                    std::net::Ipv6Addr::LOCALHOST.into()
                }
            } else {
                remote.ip()
            },
            remote.port(),
        );
        let ready = async {
            loop {
                if process.child.try_wait()?.is_some() {
                    return Err(Error::Task);
                }
                if matches!(
                    tokio::time::timeout(Duration::from_millis(150), TcpStream::connect(probe))
                        .await,
                    Ok(Ok(_))
                ) {
                    return Ok(());
                }
                tokio::time::sleep(Duration::from_millis(30)).await;
            }
        };
        let outcome = tokio::select! {
            biased;
            _ = shutdown => Ok(false),
            result = tokio::time::timeout(Duration::from_secs(15), ready) => {
                match result {Ok(result)=>result.map(|()|true),Err(_)=>Err(Error::Task)}
            },
        };
        match outcome {
            Ok(true) => Ok(Some(process)),
            Ok(false) => {
                process.stop().await?;
                Ok(None)
            }
            Err(error) => {
                let _ = process.stop().await;
                Err(error)
            }
        }
    }
    pub(crate) async fn wait(&mut self) -> Result<(), Error> {
        self.child.wait().await?;
        Err(Error::Task)
    }
    pub(crate) async fn stop(&mut self) -> Result<(), Error> {
        if self.child.try_wait()?.is_none() {
            // This is the private group assigned by Command, never a host-wide signal.
            unsafe {
                libc::kill(-self.group, libc::SIGTERM);
            }
            match tokio::time::timeout(Duration::from_secs(2), self.child.wait()).await {
                Ok(result) => {
                    result?;
                }
                Err(_) => {
                    unsafe {
                        libc::kill(-self.group, libc::SIGKILL);
                    }
                    self.child.wait().await?;
                }
            }
        }
        // Reap descendants even when the immediate plugin exited first.
        if self.group > 0 {
            unsafe {
                libc::kill(-self.group, libc::SIGKILL);
            }
        }
        self.group = 0;
        Ok(())
    }
}
impl Drop for Process {
    fn drop(&mut self) {
        if self.group > 0 {
            unsafe {
                libc::kill(-self.group, libc::SIGKILL);
            }
        }
    }
}
