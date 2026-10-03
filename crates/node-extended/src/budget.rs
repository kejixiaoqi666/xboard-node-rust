use std::{
    io,
    sync::{Arc, Mutex},
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// A lazily bound listener budget, shared by Config clones. Only the listener
/// owner should replace this Arc; closing one connection never closes the budget.
#[derive(Default)]
pub struct SharedBudget(Mutex<Option<Budget>>);
#[derive(Clone)]
pub(crate) struct Budget {
    bytes_limit: usize,
    sessions_limit: usize,
    pub bytes: Arc<Semaphore>,
    sessions: Arc<Semaphore>,
}
impl SharedBudget {
    pub(crate) fn bind(&self, bytes: usize, sessions: usize) -> io::Result<Budget> {
        let mut state = self
            .0
            .lock()
            .map_err(|_| io::Error::other("listener queue budget lock poisoned"))?;
        if let Some(budget) = state.as_ref() {
            if budget.bytes_limit != bytes || budget.sessions_limit != sessions {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "shared listener budget used with conflicting limits",
                ));
            }
            return Ok(budget.clone());
        }
        let budget = Budget {
            bytes_limit: bytes,
            sessions_limit: sessions,
            bytes: Arc::new(Semaphore::new(bytes)),
            sessions: Arc::new(Semaphore::new(sessions)),
        };
        *state = Some(budget.clone());
        Ok(budget)
    }
    pub fn available_bytes(&self) -> Option<usize> {
        self.0
            .lock()
            .ok()?
            .as_ref()
            .map(|b| b.bytes.available_permits())
    }
    pub fn available_sessions(&self) -> Option<usize> {
        self.0
            .lock()
            .ok()?
            .as_ref()
            .map(|b| b.sessions.available_permits())
    }
}
impl Budget {
    pub fn session(&self) -> io::Result<OwnedSemaphorePermit> {
        self.sessions.clone().try_acquire_owned().map_err(|_| {
            io::Error::new(
                io::ErrorKind::WouldBlock,
                "listener multiplexed session budget is full",
            )
        })
    }
    pub fn reserve_bytes(&self, count: usize) -> io::Result<OwnedSemaphorePermit> {
        self.bytes
            .clone()
            .try_acquire_many_owned(count as u32)
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "listener multiplexed byte queue is full",
                )
            })
    }
    pub fn reserve_receive_window(
        &self,
        receive: usize,
        send_headroom: usize,
    ) -> io::Result<OwnedSemaphorePermit> {
        let mut admission = self.reserve_bytes(receive + send_headroom)?;
        let receive = admission.split(receive).expect("reserved receive window");
        drop(admission);
        Ok(receive)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn h2_receive_windows_cannot_reserve_the_last_send_headroom() {
        let shared = SharedBudget::default();
        let budget = shared.bind(2 * 65535, 2).unwrap();
        let receive = budget.reserve_receive_window(65535, 16384).unwrap();
        assert_eq!(shared.available_bytes(), Some(65535));
        assert!(budget.reserve_receive_window(65535, 16384).is_err());
        assert_eq!(shared.available_bytes(), Some(65535));
        drop(receive);
        assert_eq!(shared.available_bytes(), Some(2 * 65535));
        assert!(shared.bind(65535, 2).is_err());
    }
}
