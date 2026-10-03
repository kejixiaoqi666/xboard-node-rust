//! Runtime-owned native tasks reuse kernel transactions and private control.
use crate::KernelError;
use std::{io, path::Path};
pub trait EmbeddedWorker: Send {
    fn running(&mut self) -> io::Result<bool>;
    /// Cancel and join every payload writer before successful completion.
    fn stop(&mut self) -> io::Result<()>;
}
pub trait EmbeddedLauncher: Send + Sync {
    fn check(&self, args: &[String], config: &Path) -> Result<(), KernelError>;
    fn start(
        &self,
        args: &[String],
        config: &Path,
        control: Option<&Path>,
    ) -> Result<Box<dyn EmbeddedWorker>, KernelError>;
}
