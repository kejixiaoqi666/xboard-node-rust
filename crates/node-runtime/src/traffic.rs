//! Private durable outbox. Ambiguous HTTP delivery requires explicit reconciliation.
use node_core::{MAX_TRAFFIC_ROWS, TrafficSnapshot};
use node_panel::ReportOutcome;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};
use thiserror::Error;

const MAX_BYTES: u64 = 32 * 1024 * 1024;
const MAX_USERS: usize = 65536;
const MAX_EPOCHS: usize = 4096;

#[derive(Debug, Error)]
pub enum TrafficError {
    #[error("traffic journal I/O failed; restart and inspect persisted state")]
    Io,
    #[error("invalid, corrupt or incompatible traffic journal/snapshot")]
    Invalid,
    #[error("traffic state is locked by another process")]
    Locked,
    #[error("traffic accounting bound reached")]
    Bound,
    #[error("traffic batch requires delivery reconciliation")]
    Uncertain,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Stage {
    Prepared,
    Sending,
    Uncertain,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Batch {
    pub id: u64,
    pub stage: Stage,
    pub traffic: BTreeMap<i64, [i64; 2]>,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    sequence: u64,
    digest: String,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Book {
    version: u32,
    destination: String,
    pending: BTreeMap<i64, [u64; 2]>,
    receipts: BTreeMap<String, Receipt>,
    next_batch: u64,
    flight: Option<Batch>,
    #[serde(default)]
    cursor: Option<i64>,
}

pub struct Outbox {
    directory: PathBuf,
    book: Book,
    _lock: File,
    failed: bool,
}

fn private_file(path: &Path) -> Result<(), TrafficError> {
    let meta = fs::symlink_metadata(path).map_err(|_| TrafficError::Io)?;
    if !meta.is_file() {
        return Err(TrafficError::Invalid);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if meta.permissions().mode() & 0o077 != 0 {
            return Err(TrafficError::Invalid);
        }
    }
    Ok(())
}
fn options() -> OpenOptions {
    let mut options = OpenOptions::new();
    options.read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
}

impl Outbox {
    /// Exclusive OS lock survives until drop; a stale lock file is never deleted.
    pub fn open(directory: &Path, destination: String) -> Result<Self, TrafficError> {
        if !directory.is_absolute() || destination.is_empty() || destination.len() > 8192 {
            return Err(TrafficError::Invalid);
        }
        if !directory.try_exists().map_err(|_| TrafficError::Io)? {
            fs::create_dir_all(directory).map_err(|_| TrafficError::Io)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(directory, fs::Permissions::from_mode(0o700))
                    .map_err(|_| TrafficError::Io)?;
            }
        }
        let meta = fs::symlink_metadata(directory).map_err(|_| TrafficError::Io)?;
        if !meta.is_dir() {
            return Err(TrafficError::Invalid);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if meta.permissions().mode() & 0o077 != 0 {
                return Err(TrafficError::Invalid);
            }
        }
        let lock_path = directory.join("traffic.lock");
        if fs::symlink_metadata(&lock_path).is_ok() {
            private_file(&lock_path)?;
        }
        let lock = options()
            .create(true)
            .truncate(false)
            .open(&lock_path)
            .map_err(|_| TrafficError::Io)?;
        lock.try_lock().map_err(|_| TrafficError::Locked)?;
        let path = directory.join("traffic.json");
        let book = match fs::symlink_metadata(&path) {
            Ok(_) => {
                private_file(&path)?;
                let mut bytes = Vec::new();
                File::open(&path)
                    .map_err(|_| TrafficError::Io)?
                    .take(MAX_BYTES + 1)
                    .read_to_end(&mut bytes)
                    .map_err(|_| TrafficError::Io)?;
                if bytes.len() as u64 > MAX_BYTES {
                    return Err(TrafficError::Bound);
                }
                serde_json::from_slice::<Book>(&bytes).map_err(|_| TrafficError::Invalid)?
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Book {
                version: 1,
                destination: destination.clone(),
                pending: BTreeMap::new(),
                receipts: BTreeMap::new(),
                next_batch: 1,
                flight: None,
                cursor: None,
            },
            Err(_) => return Err(TrafficError::Io),
        };
        if book.version != 1
            || book.cursor.is_some_and(|id| id <= 0)
            || book.destination != destination
            || book.next_batch == 0
            || book.pending.len() > MAX_USERS
            || book.receipts.len() > MAX_EPOCHS
            || book
                .pending
                .iter()
                .any(|(id, bytes)| *id <= 0 || *bytes == [0, 0])
            || book.receipts.iter().any(|(epoch, r)| {
                epoch.len() != 32
                    || !epoch.bytes().all(|b| b.is_ascii_hexdigit())
                    || r.sequence == 0
                    || r.digest.len() != 64
                    || !r.digest.bytes().all(|b| b.is_ascii_hexdigit())
            })
            || book.flight.as_ref().is_some_and(|b| {
                b.id == 0
                    || b.id >= book.next_batch
                    || b.traffic.is_empty()
                    || b.traffic.len() > MAX_TRAFFIC_ROWS
                    || b.traffic.iter().any(|(id, bytes)| {
                        *id <= 0 || *bytes == [0, 0] || bytes.iter().any(|n| *n < 0)
                    })
            })
        {
            return Err(TrafficError::Invalid);
        }
        let mut result = Self {
            directory: directory.into(),
            book,
            _lock: lock,
            failed: false,
        };
        let mut book = result.book.clone();
        if let Some(batch) = &mut book.flight
            && batch.stage == Stage::Sending
        {
            batch.stage = Stage::Uncertain;
        }
        result.commit(book)?;
        Ok(result)
    }

    fn commit(&mut self, book: Book) -> Result<(), TrafficError> {
        if self.failed {
            return Err(TrafficError::Io);
        }
        let result = self.persist(&book);
        if result.is_err() {
            // Rename may have committed before a directory fsync failed. Never
            // overwrite that unknown state from a stale in-memory copy.
            self.failed = true;
        }
        result?;
        self.book = book;
        Ok(())
    }
    fn persist(&self, book: &Book) -> Result<(), TrafficError> {
        let bytes = serde_json::to_vec(book).map_err(|_| TrafficError::Invalid)?;
        if bytes.len() as u64 > MAX_BYTES {
            return Err(TrafficError::Bound);
        }
        let path = self.directory.join("traffic.json");
        if fs::symlink_metadata(&path).is_ok() {
            private_file(&path)?;
        }
        // PID plus a process-local sequence avoids touching prior crash leftovers.
        static SEQUENCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let temporary = self.directory.join(format!(
            "traffic-{}-{}-{}.tmp",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|_| TrafficError::Io)?
                .as_nanos(),
            SEQUENCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let mut created = false;
        let result = (|| {
            let mut file = options()
                .create_new(true)
                .open(&temporary)
                .map_err(|_| TrafficError::Io)?;
            created = true;
            file.write_all(&bytes).map_err(|_| TrafficError::Io)?;
            file.sync_all().map_err(|_| TrafficError::Io)?;
            drop(file);
            fs::rename(&temporary, &path).map_err(|_| TrafficError::Io)?;
            #[cfg(unix)]
            File::open(&self.directory)
                .and_then(|f| f.sync_all())
                .map_err(|_| TrafficError::Io)?;
            Ok(())
        })();
        if result.is_err() && created {
            let _ = fs::remove_file(&temporary);
        }
        result
    }

    /// Persist the receipt and bytes together, BEFORE acknowledging the kernel.
    pub fn collect(&mut self, snapshot: &TrafficSnapshot) -> Result<bool, TrafficError> {
        if self.failed {
            return Err(TrafficError::Io);
        }
        if !snapshot.validate() {
            return Err(TrafficError::Invalid);
        }
        let digest = snapshot.digest();
        if let Some(receipt) = self.book.receipts.get(&snapshot.epoch) {
            if snapshot.sequence == receipt.sequence {
                return if digest == receipt.digest {
                    Ok(false)
                } else {
                    Err(TrafficError::Invalid)
                };
            }
            if snapshot.sequence != receipt.sequence.checked_add(1).ok_or(TrafficError::Bound)? {
                return Err(TrafficError::Invalid);
            }
        } else if snapshot.sequence != 1 {
            return Err(TrafficError::Invalid);
        }
        let mut book = self.book.clone();
        for (id, bytes) in &snapshot.traffic {
            let parsed = id.parse::<i64>().map_err(|_| TrafficError::Invalid)?;
            if parsed <= 0 || parsed.to_string() != *id {
                return Err(TrafficError::Invalid);
            }
            let count = book.pending.entry(parsed).or_default();
            for (direction, amount) in bytes.iter().enumerate() {
                count[direction] = count[direction]
                    .checked_add(*amount)
                    .ok_or(TrafficError::Bound)?;
            }
        }
        book.receipts.insert(
            snapshot.epoch.clone(),
            Receipt {
                sequence: snapshot.sequence,
                digest,
            },
        );
        if book.pending.len() > MAX_USERS || book.receipts.len() > MAX_EPOCHS {
            return Err(TrafficError::Bound);
        }
        self.commit(book)?;
        Ok(true)
    }

    pub fn prepare(&mut self) -> Result<Option<Batch>, TrafficError> {
        if self.failed {
            return Err(TrafficError::Io);
        }
        if let Some(batch) = &self.book.flight {
            return if batch.stage == Stage::Prepared {
                Ok(Some(batch.clone()))
            } else {
                Err(TrafficError::Uncertain)
            };
        }
        if self.book.pending.is_empty() {
            return Ok(None);
        }
        let mut book = self.book.clone();
        let mut traffic = BTreeMap::new();
        let cursor = book.cursor;
        let ids: Vec<_> = book
            .pending
            .keys()
            .filter(|id| cursor.is_none_or(|c| **id > c))
            .chain(
                book.pending
                    .keys()
                    .filter(|id| cursor.is_some_and(|c| **id <= c)),
            )
            .take(MAX_TRAFFIC_ROWS)
            .copied()
            .collect();
        book.cursor = ids.last().copied();
        for id in ids {
            let bytes = book
                .pending
                .get_mut(&id)
                .expect("selected pending identity");
            let take = bytes.map(|n| n.min(i64::MAX as u64) as i64);
            bytes[0] -= take[0] as u64;
            bytes[1] -= take[1] as u64;
            traffic.insert(id, take);
        }
        book.pending.retain(|_, bytes| *bytes != [0, 0]);
        let batch = Batch {
            id: book.next_batch,
            stage: Stage::Prepared,
            traffic,
        };
        book.next_batch = book.next_batch.checked_add(1).ok_or(TrafficError::Bound)?;
        book.flight = Some(batch.clone());
        self.commit(book)?;
        Ok(Some(batch))
    }
    pub fn sending(&mut self, id: u64) -> Result<(), TrafficError> {
        let mut book = self.book.clone();
        let batch = book.flight.as_mut().ok_or(TrafficError::Invalid)?;
        if batch.id != id || batch.stage != Stage::Prepared {
            return Err(TrafficError::Invalid);
        }
        batch.stage = Stage::Sending;
        self.commit(book)
    }
    pub fn finish(&mut self, id: u64, outcome: ReportOutcome) -> Result<(), TrafficError> {
        let mut book = self.book.clone();
        let batch = book.flight.as_mut().ok_or(TrafficError::Invalid)?;
        if batch.id != id || batch.stage != Stage::Sending {
            return Err(TrafficError::Invalid);
        }
        match outcome {
            ReportOutcome::Acknowledged => book.flight = None,
            ReportOutcome::NotSent => batch.stage = Stage::Prepared,
            ReportOutcome::Uncertain => batch.stage = Stage::Uncertain,
        }
        self.commit(book)
    }
    /// Call only after the operator verifies this exact batch against the panel.
    pub fn resolve(&mut self, id: u64, delivered: bool) -> Result<(), TrafficError> {
        let mut book = self.book.clone();
        let batch = book.flight.as_mut().ok_or(TrafficError::Invalid)?;
        if batch.id != id || batch.stage != Stage::Uncertain {
            return Err(TrafficError::Invalid);
        }
        if delivered {
            book.flight = None;
        } else {
            batch.stage = Stage::Prepared;
        }
        self.commit(book)
    }
    pub fn status(&self) -> serde_json::Value {
        let mut pending_bytes = [0_u64; 2];
        for bytes in self.book.pending.values() {
            pending_bytes[0] = pending_bytes[0].saturating_add(bytes[0]);
            pending_bytes[1] = pending_bytes[1].saturating_add(bytes[1]);
        }
        let (state, next_action, requires_reconciliation, batch_users, batch_bytes) =
            match self.book.flight.as_ref() {
                None if self.book.pending.is_empty() => ("idle", "none", false, 0, [0_i64, 0_i64]),
                None => ("pending", "report", false, 0, [0_i64, 0_i64]),
                Some(batch) => {
                    let mut bytes = [0_i64; 2];
                    for value in batch.traffic.values() {
                        bytes[0] = bytes[0].saturating_add(value[0]);
                        bytes[1] = bytes[1].saturating_add(value[1]);
                    }
                    match batch.stage {
                        Stage::Prepared => ("prepared", "send", false, batch.traffic.len(), bytes),
                        Stage::Sending => (
                            "sending",
                            "await_report_result",
                            false,
                            batch.traffic.len(),
                            bytes,
                        ),
                        Stage::Uncertain => (
                            "uncertain",
                            "inspect_panel_then_traffic_resolve",
                            true,
                            batch.traffic.len(),
                            bytes,
                        ),
                    }
                }
            };
        serde_json::json!({"destination":self.book.destination,"pending":self.book.pending,
            "batch":self.book.flight,"epochs":self.book.receipts.len(),"io_failed":self.failed,
            "summary":{"state":state,"next_action":next_action,
            "requires_reconciliation":requires_reconciliation,
            "pending_users":self.book.pending.len(),"pending_bytes":pending_bytes,
            "batch_users":batch_users,"batch_bytes":batch_bytes}})
    }
    pub fn abandon_sending(&mut self) -> Result<(), TrafficError> {
        if let Some(batch) = &self.book.flight
            && batch.stage == Stage::Sending
        {
            return self.finish(batch.id, ReportOutcome::Uncertain);
        }
        Ok(())
    }
}
