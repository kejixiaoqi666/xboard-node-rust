//! Fleet kernels execute in the controller process, with per-node task ownership.
#![cfg(unix)]
use node_kernel::{EmbeddedLauncher, EmbeddedWorker, KernelError};
use std::{io, path::Path, time::Duration};
use tokio::{runtime::Handle, sync::watch, task::JoinHandle};

// A direct embedded stop can enter the same native cleanup path as the
// structured traffic_quiesce request.  Keep a margin beyond that protocol
// deadline so the synchronous worker join cannot abort the final checkpoint.
const EMBEDDED_SHUTDOWN_TIMEOUT_SECS: u64 = node_core::TRAFFIC_QUIESCE_TIMEOUT_SECS + 15;
pub struct Launcher(pub Handle);
struct Worker {
    runtime: Handle,
    stop: watch::Sender<bool>,
    task: Option<JoinHandle<Result<(), node_native::Error>>>,
}
impl EmbeddedLauncher for Launcher {
    fn check(&self, _args: &[String], path: &Path) -> Result<(), KernelError> {
        let candidate = node_native::config::read_candidate(path)
            .map_err(|_| KernelError::Prepare("native candidate rejected".into()))?;
        node_native::config::tls_config(candidate.base.tls.as_ref())
            .map_err(|_| KernelError::Prepare("native TLS candidate rejected".into()))?;
        Ok(())
    }
    fn start(
        &self,
        args: &[String],
        config: &Path,
        control: Option<&Path>,
    ) -> Result<Box<dyn EmbeddedWorker>, KernelError> {
        if self.0.runtime_flavor() != tokio::runtime::RuntimeFlavor::MultiThread {
            return Err(KernelError::Activate(
                "embedded fleet requires a multithreaded Tokio runtime".into(),
            ));
        }
        let control = control.ok_or_else(|| {
            KernelError::Activate("embedded kernel requires private control".into())
        })?;
        let mut args = args.to_vec();
        args.push(config.to_string_lossy().into_owned());
        args.extend([
            "--control-socket".into(),
            control.to_string_lossy().into_owned(),
        ]);
        let (stop, rx) = watch::channel(false);
        let task = self
            .0
            .spawn(async move { node_native::run_embedded(&args, rx).await });
        Ok(Box::new(Worker {
            runtime: self.0.clone(),
            stop,
            task: Some(task),
        }))
    }
}
impl EmbeddedWorker for Worker {
    fn running(&mut self) -> io::Result<bool> {
        Ok(self.task.as_ref().is_some_and(|task| !task.is_finished()))
    }
    fn stop(&mut self) -> io::Result<()> {
        let Some(mut task) = self.task.take() else {
            return Ok(());
        };
        let _ = self.stop.send(true);
        let wait = async {
            match tokio::time::timeout(
                Duration::from_secs(EMBEDDED_SHUTDOWN_TIMEOUT_SECS),
                &mut task,
            )
            .await
            {
                Ok(Ok(Ok(()))) => Ok(()),
                Ok(_) => Err(io::Error::other("embedded kernel shutdown failed")),
                Err(_) => {
                    task.abort();
                    let _ = task.await;
                    Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "embedded kernel did not complete shutdown",
                    ))
                }
            }
        };
        if Handle::try_current().is_ok_and(|handle| {
            handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread
        }) {
            // Kernel ownership can be dropped by an async controller worker.
            // Fleet runtimes are multithreaded, so allow their other workers to
            // drive the node while this synchronous lifecycle API joins it.
            tokio::task::block_in_place(|| self.runtime.block_on(wait))
        } else if Handle::try_current().is_ok() {
            // A caller's current-thread runtime cannot use block_in_place.
            // The owned fleet runtime still runs on its independent workers.
            std::thread::scope(|scope| {
                scope
                    .spawn(|| self.runtime.block_on(wait))
                    .join()
                    .map_err(|_| io::Error::other("embedded shutdown join failed"))?
            })
        } else {
            self.runtime.block_on(wait)
        }
    }
}
impl Drop for Worker {
    fn drop(&mut self) {
        let _ = self.stop.send(true);
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}
