//! Private atomic native-counter checkpoints; not a transaction with the socket.
use node_core::TrafficSnapshot;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
};

const MAX_BYTES: u64 = 32 * 1024 * 1024;
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Book {
    pub version: u32,
    pub destination: String,
    pub epoch: String,
    pub sequence: u64,
    pub counters: BTreeMap<String, [u64; 2]>,
    pub frozen: Option<TrafficSnapshot>,
    pub cursor: Option<String>,
}
impl Book {
    fn valid(&self, destination: &str) -> bool {
        self.version == 1
            && self.destination == destination
            && self.epoch.len() == 32
            && self.epoch.bytes().all(|b| b.is_ascii_hexdigit())
            && self.counters.len() <= 65536
            && self
                .counters
                .iter()
                .all(|(id, bytes)| valid_id(id) && *bytes != [0, 0])
            && self.cursor.as_ref().is_none_or(|id| valid_id(id))
            && self.frozen.as_ref().is_none_or(|s| {
                s.validate()
                    && s.epoch == self.epoch
                    && s.sequence == self.sequence
                    && s.traffic.iter().all(|(id, frozen)| {
                        self.counters
                            .get(id)
                            .is_some_and(|all| all[0] >= frozen[0] && all[1] >= frozen[1])
                    })
            })
    }
}
pub(crate) fn valid_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 128 && !id.chars().any(char::is_control)
}
pub(crate) struct Store {
    directory: PathBuf,
    _lock: File,
    failed: AtomicBool,
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
fn private_file(path: &Path) -> io::Result<()> {
    let meta = fs::symlink_metadata(path)?;
    if !meta.is_file() {
        return Err(io::Error::other("invalid native traffic file"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if meta.permissions().mode() & 0o077 != 0 {
            return Err(io::Error::other("native traffic file must be private"));
        }
    }
    Ok(())
}
fn present_private_file(path: &Path) -> io::Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => {
            private_file(path)?;
            Ok(true)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}
impl Store {
    pub(crate) fn open(directory: &Path, destination: &str) -> io::Result<(Self, Option<Book>)> {
        if !directory.is_absolute() || destination.is_empty() || destination.len() > 8192 {
            return Err(io::Error::other("invalid native traffic destination"));
        }
        let meta = fs::symlink_metadata(directory)?;
        if !meta.is_dir() {
            return Err(io::Error::other("invalid native traffic directory"));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if meta.permissions().mode() & 0o077 != 0 {
                return Err(io::Error::other("native traffic directory must be private"));
            }
        }
        let lock_path = directory.join("native-traffic.lock");
        present_private_file(&lock_path)?;
        let lock = options().create(true).truncate(false).open(lock_path)?;
        lock.try_lock()
            .map_err(|_| io::Error::other("native traffic store already locked"))?;
        let path = directory.join("native-traffic.json");
        let book = if present_private_file(&path)? {
            let mut bytes = Vec::new();
            File::open(&path)?
                .take(MAX_BYTES + 1)
                .read_to_end(&mut bytes)?;
            if bytes.len() as u64 > MAX_BYTES {
                return Err(io::Error::other("native traffic file exceeds bound"));
            }
            let book: Book = serde_json::from_slice(&bytes)
                .map_err(|_| io::Error::other("invalid native traffic checkpoint"))?;
            if !book.valid(destination) {
                return Err(io::Error::other("native traffic checkpoint mismatch"));
            }
            Some(book)
        } else {
            None
        };
        Ok((
            Self {
                directory: directory.into(),
                _lock: lock,
                failed: AtomicBool::new(false),
            },
            book,
        ))
    }
    pub(crate) fn commit(&self, book: &Book) -> io::Result<()> {
        self.healthy()?;
        let body = serde_json::to_vec(book).map_err(io::Error::other)?;
        if body.len() as u64 > MAX_BYTES {
            return Err(io::Error::other("native traffic checkpoint exceeds bound"));
        }
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(io::Error::other)?
            .as_nanos();
        let path = self.directory.join(format!(
            "native-traffic-{}-{time}-{}.tmp",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let mut owned = false;
        let result = (|| {
            let mut file = options().create_new(true).open(&path)?;
            owned = true;
            file.write_all(&body)?;
            file.sync_all()?;
            drop(file);
            fs::rename(&path, self.directory.join("native-traffic.json"))?;
            #[cfg(unix)]
            File::open(&self.directory)?.sync_all()?;
            Ok(())
        })();
        if result.is_err() {
            self.failed.store(true, Ordering::Release);
            if owned {
                let _ = fs::remove_file(&path);
            }
        }
        result
    }
    pub(crate) fn healthy(&self) -> io::Result<()> {
        if self.failed.load(Ordering::Acquire) {
            Err(io::Error::other(
                "native traffic storage failed; restart and inspect",
            ))
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    pub(crate) struct Directory(pub PathBuf);
    impl Directory {
        pub(crate) fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let time = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "xbord-native-traffic-test-{}-{time}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
            }
            Self(path)
        }
    }
    impl Drop for Directory {
        fn drop(&mut self) {
            let path = self.0.canonicalize().unwrap();
            assert_eq!(
                path.parent().unwrap(),
                std::env::temp_dir().canonicalize().unwrap()
            );
            assert!(
                path.file_name()
                    .unwrap()
                    .to_string_lossy()
                    .starts_with("xbord-native-traffic-test-")
            );
            fs::remove_dir_all(path).unwrap();
        }
    }
    fn book() -> Book {
        Book {
            version: 1,
            destination: "fixture-destination".into(),
            epoch: "a".repeat(32),
            sequence: 0,
            counters: BTreeMap::from([("1".into(), [9, 11])]),
            frozen: None,
            cursor: None,
        }
    }
    #[test]
    fn checkpoint_reopen_lock_destination_and_corruption() {
        let dir = Directory::new();
        let (store, previous) = Store::open(&dir.0, "fixture-destination").unwrap();
        assert!(previous.is_none());
        store.commit(&book()).unwrap();
        assert!(Store::open(&dir.0, "fixture-destination").is_err());
        drop(store);
        assert!(Store::open(&dir.0, "other-node").is_err());
        let (store, previous) = Store::open(&dir.0, "fixture-destination").unwrap();
        assert_eq!(previous.unwrap().counters["1"], [9, 11]);
        drop(store);
        fs::write(dir.0.join("native-traffic.json"), b"truncated").unwrap();
        assert!(Store::open(&dir.0, "fixture-destination").is_err());
    }
    #[test]
    fn invalid_frozen_counters_and_storage_errors_are_not_accepted() {
        let dir = Directory::new();
        let mut invalid = book();
        invalid.sequence = 1;
        invalid.frozen = Some(TrafficSnapshot {
            epoch: invalid.epoch.clone(),
            sequence: 1,
            traffic: BTreeMap::from([("1".into(), [10, 11])]),
        });
        let (store, _) = Store::open(&dir.0, "fixture-destination").unwrap();
        store.commit(&invalid).unwrap();
        drop(store);
        assert!(Store::open(&dir.0, "fixture-destination").is_err());
        fs::remove_file(dir.0.join("native-traffic.json")).unwrap();
        let (store, _) = Store::open(&dir.0, "fixture-destination").unwrap();
        fs::create_dir(dir.0.join("native-traffic.json")).unwrap();
        assert!(store.commit(&book()).is_err());
        assert!(store.healthy().is_err());
        fs::remove_dir(dir.0.join("native-traffic.json")).unwrap();
        assert!(store.commit(&book()).is_err());
    }
    #[cfg(unix)]
    #[test]
    fn unsafe_paths_and_permissions_are_rejected() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let dir = Directory::new();
        symlink(dir.0.join("missing"), dir.0.join("native-traffic.lock")).unwrap();
        assert!(Store::open(&dir.0, "fixture-destination").is_err());
        fs::remove_file(dir.0.join("native-traffic.lock")).unwrap();
        let (store, _) = Store::open(&dir.0, "fixture-destination").unwrap();
        store.commit(&book()).unwrap();
        drop(store);
        fs::set_permissions(
            dir.0.join("native-traffic.json"),
            fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        assert!(Store::open(&dir.0, "fixture-destination").is_err());
    }
}
