use crate::{
    dns::{CloudflareProvider, DnsLease, DnsProvider, DnsRecord, ExternalHookProvider},
    secrets::{EnvSecrets, Secret, SecretResolver},
    storage,
};
use instant_acme::{
    Account, AuthorizationStatus, ChallengeType, Identifier, NewAccount, NewOrder, OrderStatus,
    RetryPolicy,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, HashMap},
    fmt,
    io::BufReader,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use thiserror::Error;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::watch,
    task::JoinSet,
};
use zeroize::Zeroize;
type PemMaterial = (Vec<u8>, Vec<u8>);

#[derive(Debug, Error)]
pub enum CertificateError {
    #[error("invalid certificate configuration: {0}")]
    Config(&'static str),
    #[error("certificate storage operation failed")]
    Storage,
    #[error("certificate directory is locked by another renewal")]
    Busy,
    #[error("invalid, expired, mismatched or malformed certificate material")]
    Material,
    #[error("ACME operation failed at {0}")]
    Acme(&'static str),
    #[error("DNS operation failed at {0}")]
    Dns(&'static str),
    #[error("ACME challenge server operation failed")]
    Http,
}

/// Public configuration only serializes references. Inline panel secrets may be
/// deserialized into memory but are always redacted and skipped on serialization.
#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct CertConfig {
    pub cert_mode: String,
    #[serde(rename = "mode", skip_serializing)]
    pub mode_fallback: String,
    pub auto_tls: bool,
    pub domain: String,
    pub email: String,
    pub cert_file: Option<PathBuf>,
    pub key_file: Option<PathBuf>,
    pub cert_dir: Option<PathBuf>,
    pub http_port: u16,
    pub dns_provider: String,
    #[serde(skip_serializing)]
    pub dns_env: BTreeMap<String, Secret>,
    pub dns_env_refs: BTreeMap<String, String>,
    pub dns_zone_id: Option<String>,
    pub dns_hook: Option<PathBuf>,
    #[serde(skip_serializing)]
    pub cert_content: Secret,
    #[serde(skip_serializing)]
    pub key_content: Secret,
    pub cert_content_env: Option<String>,
    pub key_content_env: Option<String>,
    pub acme_directory: Option<String>,
    pub acme_ca_file: Option<PathBuf>,
    /// Test-only opt in; HTTPS remains mandatory for any non-loopback CA.
    pub allow_loopback_acme_http: bool,
    pub renew_before_seconds: Option<u64>,
    pub challenge_timeout_seconds: Option<u64>,
    pub dns_propagation_timeout_seconds: Option<u64>,
}
impl fmt::Debug for CertConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CertConfig")
            .field("mode", &self.cert_mode)
            .field("domain", &self.domain)
            .field("dns_provider", &self.dns_provider)
            .field("inline_secrets", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}
impl CertConfig {
    pub fn mode(&self) -> &str {
        let explicit = if !self.cert_mode.trim().is_empty() {
            self.cert_mode.trim()
        } else {
            self.mode_fallback.trim()
        };
        if !explicit.is_empty() {
            for supported in ["none", "http", "dns", "self", "file", "content"] {
                if explicit.eq_ignore_ascii_case(supported) {
                    return supported;
                }
            }
            return explicit;
        }
        if self.auto_tls {
            "http"
        } else if (!self.cert_content.is_empty() || self.cert_content_env.is_some())
            && (!self.key_content.is_empty() || self.key_content_env.is_some())
        {
            "content"
        } else if self.cert_file.is_some() && self.key_file.is_some() {
            "file"
        } else {
            "none"
        }
    }
    pub fn http_port(&self) -> u16 {
        if self.http_port == 0 {
            80
        } else {
            self.http_port
        }
    }
    pub fn validate(&self) -> Result<(), CertificateError> {
        let mode = self.mode();
        if !matches!(mode, "none" | "http" | "dns" | "self" | "file" | "content") {
            return Err(CertificateError::Config("unsupported mode"));
        }
        if matches!(mode, "http" | "dns") {
            if !valid_domain(&self.domain, mode == "dns")
                || (mode == "http" && self.domain.starts_with("*."))
            {
                return Err(CertificateError::Config("ACME requires a valid DNS name"));
            }
            let directory = url::Url::parse(self.directory())
                .map_err(|_| CertificateError::Config("invalid ACME directory"))?;
            let local = matches!(
                directory.host_str(),
                Some("localhost" | "127.0.0.1" | "::1")
            );
            if !directory.username().is_empty()
                || directory.password().is_some()
                || directory.fragment().is_some()
                || (directory.scheme() != "https"
                    && !(self.allow_loopback_acme_http && local && directory.scheme() == "http"))
            {
                return Err(CertificateError::Config("ACME directory requires HTTPS"));
            }
        }
        if mode == "file" && (self.cert_file.is_none() || self.key_file.is_none()) {
            return Err(CertificateError::Config(
                "file mode requires cert_file and key_file",
            ));
        }
        if self
            .challenge_timeout_seconds
            .is_some_and(|s| !(1..=1800).contains(&s))
            || self
                .dns_propagation_timeout_seconds
                .is_some_and(|s| !(1..=3600).contains(&s))
        {
            return Err(CertificateError::Config("invalid timeout"));
        }
        for reference in self
            .dns_env_refs
            .values()
            .chain(self.cert_content_env.iter())
            .chain(self.key_content_env.iter())
        {
            if !crate::secrets::valid_env_name(reference) {
                return Err(CertificateError::Config(
                    "invalid secret environment reference",
                ));
            }
        }
        Ok(())
    }
    fn directory(&self) -> &str {
        self.acme_directory
            .as_deref()
            .unwrap_or("https://acme-v02.api.letsencrypt.org/directory")
    }
    fn fingerprint(&self) -> String {
        let public = serde_json::json!({"mode":self.mode(),"domain":self.domain.to_ascii_lowercase(),"directory":self.directory(),"email":self.email});
        format!("{:x}", Sha256::digest(public.to_string().as_bytes()))
    }
}
pub fn valid_domain(domain: &str, wildcard: bool) -> bool {
    let name = if wildcard {
        domain.strip_prefix("*.").unwrap_or(domain)
    } else {
        domain
    };
    !name.is_empty()
        && name.len() <= 253
        && name.is_ascii()
        && name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CertificateFiles {
    pub cert: PathBuf,
    pub key: PathBuf,
    pub next_renew_unix: i64,
    pub not_after_unix: i64,
    pub generation: String,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Current {
    fingerprint: String,
    generation: String,
    next_renew_unix: i64,
    not_after_unix: i64,
}

#[derive(Clone, Default)]
pub struct ChallengeStore(Arc<Mutex<HashMap<(String, String), ChallengeEntry>>>);
struct ChallengeEntry {
    body: String,
    expires: Instant,
    owner: String,
}
struct ChallengeLease {
    store: ChallengeStore,
    domain: String,
    token: String,
    owner: String,
}
impl Drop for ChallengeLease {
    fn drop(&mut self) {
        if let Ok(mut entries) = self.store.0.lock() {
            let key = (self.domain.clone(), self.token.clone());
            if entries
                .get(&key)
                .is_some_and(|entry| entry.owner == self.owner)
            {
                entries.remove(&key);
            }
        }
    }
}
impl ChallengeStore {
    fn present(
        &self,
        domain: &str,
        token: &str,
        body: &str,
        lifetime: Duration,
    ) -> Result<ChallengeLease, CertificateError> {
        if !valid_domain(domain, false)
            || !valid_token(token)
            || body.len() > 1024
            || !body
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
        {
            return Err(CertificateError::Config("invalid HTTP challenge"));
        }
        let owner = random_id()?;
        let key = (domain.to_ascii_lowercase(), token.to_owned());
        let mut entries = self.0.lock().map_err(|_| CertificateError::Http)?;
        entries.retain(|_, entry| entry.expires > Instant::now());
        if entries.contains_key(&key) {
            return Err(CertificateError::Busy);
        }
        entries.insert(
            key,
            ChallengeEntry {
                body: body.to_owned(),
                expires: Instant::now() + lifetime,
                owner: owner.clone(),
            },
        );
        Ok(ChallengeLease {
            store: self.clone(),
            domain: domain.to_ascii_lowercase(),
            token: token.to_owned(),
            owner,
        })
    }
    /// Only exact active challenge paths and their domain Host header are served.
    /// A caller can attach this to its existing dedicated port-80 listener.
    pub fn response(&self, method: &str, host: &str, path: &str) -> Option<String> {
        if method != "GET" || host.bytes().any(|b| b.is_ascii_whitespace()) {
            return None;
        }
        let domain = match host.split_once(':') {
            Some((name, port)) if port.parse::<u16>().is_ok_and(|p| p > 0) => name,
            Some(_) => return None,
            None => host,
        }
        .trim_end_matches('.')
        .to_ascii_lowercase();
        if !valid_domain(&domain, false) {
            return None;
        }
        let token = path.strip_prefix("/.well-known/acme-challenge/")?;
        if !valid_token(token) {
            return None;
        }
        let mut entries = self.0.lock().ok()?;
        let key = (domain, token.to_owned());
        if entries
            .get(&key)
            .is_some_and(|entry| entry.expires <= Instant::now())
        {
            entries.remove(&key);
            return None;
        }
        entries.get(&key).map(|entry| entry.body.clone())
    }
    /// Bind this before calling ensure. The CA still connects to public port 80;
    /// a different local port only works when forwarded explicitly or in Pebble.
    pub async fn serve_http(
        &self,
        bind: SocketAddr,
        mut shutdown: watch::Receiver<bool>,
    ) -> Result<(), CertificateError> {
        let listener = TcpListener::bind(bind)
            .await
            .map_err(|_| CertificateError::Http)?;
        self.serve_listener(listener, &mut shutdown).await
    }
    pub async fn serve_listener(
        &self,
        listener: TcpListener,
        shutdown: &mut watch::Receiver<bool>,
    ) -> Result<(), CertificateError> {
        let mut tasks = JoinSet::new();
        loop {
            if *shutdown.borrow() {
                break;
            }
            tokio::select! {
                accepted=listener.accept(), if tasks.len()<64 => {
                    let (mut socket,_)=accepted.map_err(|_|CertificateError::Http)?;
                    let store=self.clone();
                    tasks.spawn(async move {
                        let _=tokio::time::timeout(Duration::from_secs(5),async {
                            let mut request=Vec::with_capacity(1024);
                            loop {
                                let mut chunk=[0u8;512];
                                let read=socket.read(&mut chunk).await?;
                                if read==0 {return Ok::<(),std::io::Error>(());}
                                request.extend_from_slice(&chunk[..read]);
                                if request.len()>8192 {return Ok(());}
                                if request.windows(4).any(|w|w==b"\r\n\r\n") {break;}
                            }
                            let body=std::str::from_utf8(&request).ok().and_then(|text| {
                                let mut lines=text.split("\r\n");
                                let first:Vec<_>=lines.next()?.split(' ').collect();
                                if first.len()!=3 || !matches!(first[2],"HTTP/1.0"|"HTTP/1.1") {return None;}
                                let mut host=None;
                                for line in lines.take_while(|line|!line.is_empty()) {
                                    let (name,value)=line.split_once(':')?;
                                    if name.eq_ignore_ascii_case("host") {if host.is_some(){return None;} host=Some(value.trim());}
                                }
                                store.response(first[0],host?,first[1])
                            });
                            let (status,body)=match body {Some(body)=>("200 OK",body),None=>("404 Not Found",String::new())};
                            let response=format!("HTTP/1.1 {status}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n{body}",body.len());
                            socket.write_all(response.as_bytes()).await?;
                            socket.shutdown().await
                        }).await;
                    });
                }
                changed=shutdown.changed()=> {if changed.is_err() {break;} }
                _=tasks.join_next(),if !tasks.is_empty()=> {}
            }
        }
        tasks.abort_all();
        Ok(())
    }
}
fn valid_token(token: &str) -> bool {
    (22..=512).contains(&token.len())
        && token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}
fn random_id() -> Result<String, CertificateError> {
    // A fresh crypto key gives a collision-resistant generation name without
    // introducing a second RNG backend into the certificate crate.
    let key = rcgen::KeyPair::generate().map_err(|_| CertificateError::Material)?;
    Ok(format!("{:x}", Sha256::digest(key.public_key_pem().as_bytes()))[..24].to_owned())
}

pub struct CertificateManager {
    pub challenges: ChallengeStore,
    secrets: Arc<dyn SecretResolver>,
    dns: Option<Arc<dyn DnsProvider>>,
}
struct DnsCleanupGuard {
    provider: Option<Arc<dyn DnsProvider>>,
    leases: Vec<DnsLease>,
}
impl Drop for DnsCleanupGuard {
    fn drop(&mut self) {
        // If the caller cancels ensure, the order's owned records still get a
        // bounded best-effort cleanup while the runtime remains available.
        if let (Some(provider), Ok(runtime)) =
            (self.provider.clone(), tokio::runtime::Handle::try_current())
        {
            for lease in std::mem::take(&mut self.leases) {
                let provider = provider.clone();
                runtime.spawn(async move {
                    let _ = tokio::time::timeout(Duration::from_secs(30), provider.cleanup(&lease))
                        .await;
                });
            }
        }
    }
}
impl Default for CertificateManager {
    fn default() -> Self {
        Self::new(ChallengeStore::default())
    }
}
impl CertificateManager {
    pub fn new(challenges: ChallengeStore) -> Self {
        Self {
            challenges,
            secrets: Arc::new(EnvSecrets),
            dns: None,
        }
    }
    pub fn with_secrets(mut self, secrets: Arc<dyn SecretResolver>) -> Self {
        self.secrets = secrets;
        self
    }
    pub fn with_dns_provider(mut self, dns: Arc<dyn DnsProvider>) -> Self {
        self.dns = Some(dns);
        self
    }
    pub async fn ensure(
        &self,
        cfg: &CertConfig,
        state_dir: &Path,
    ) -> Result<Option<CertificateFiles>, CertificateError> {
        self.ensure_at(
            cfg,
            state_dir,
            time::OffsetDateTime::now_utc().unix_timestamp(),
            false,
        )
        .await
    }
    /// Explicit forced renewal is useful for operations and isolated CA tests.
    pub async fn renew(
        &self,
        cfg: &CertConfig,
        state_dir: &Path,
    ) -> Result<Option<CertificateFiles>, CertificateError> {
        self.ensure_at(
            cfg,
            state_dir,
            time::OffsetDateTime::now_utc().unix_timestamp(),
            true,
        )
        .await
    }
    pub async fn ensure_at(
        &self,
        cfg: &CertConfig,
        state_dir: &Path,
        now: i64,
        force: bool,
    ) -> Result<Option<CertificateFiles>, CertificateError> {
        cfg.validate()?;
        if cfg.mode() == "none" {
            return Ok(None);
        }
        let directory = cfg
            .cert_dir
            .clone()
            .unwrap_or_else(|| state_dir.join("certs"));
        let _lock = storage::DirectoryLock::acquire(&directory).map_err(|error| {
            if error.kind() == std::io::ErrorKind::WouldBlock {
                CertificateError::Busy
            } else {
                CertificateError::Storage
            }
        })?;
        let old = self.current(&directory)?;
        if !force
            && matches!(cfg.mode(), "self" | "http" | "dns")
            && let Some((current, files)) = &old
            && current.fingerprint == cfg.fingerprint()
            && now < files.next_renew_unix
        {
            let cert = storage::read_bounded(&files.cert, 1024 * 1024)
                .map_err(|_| CertificateError::Storage)?;
            let mut key = storage::read_bounded(&files.key, 1024 * 1024)
                .map_err(|_| CertificateError::Storage)?;
            let checked = validate_material(&cert, &key, cfg, now);
            key.zeroize();
            if checked.is_ok() {
                return Ok(Some(files.clone()));
            }
        }
        // The Go manager persisted these flat names. Adopt a valid unexpired
        // pair into the atomic version store before making any new CA request.
        let adopt_legacy = !force
            && old.is_none()
            && (matches!(cfg.mode(), "self" | "http" | "dns")
                || (cfg.mode() == "content"
                    && self
                        .resolve(&cfg.cert_content, &cfg.cert_content_env)
                        .is_none()
                    && self
                        .resolve(&cfg.key_content, &cfg.key_content_env)
                        .is_none()));
        let legacy = if adopt_legacy {
            legacy_material(cfg, &directory, now)?
        } else {
            None
        };
        let (cert, mut key) = if let Some(material) = legacy {
            material
        } else {
            match cfg.mode() {
                "self" => self_signed(cfg, now)?,
                "file" => {
                    let cert = storage::read_bounded(
                        cfg.cert_file.as_ref().ok_or(CertificateError::Material)?,
                        1024 * 1024,
                    )
                    .map_err(|_| CertificateError::Storage)?;
                    let key = storage::read_bounded(
                        cfg.key_file.as_ref().ok_or(CertificateError::Material)?,
                        1024 * 1024,
                    )
                    .map_err(|_| CertificateError::Storage)?;
                    (cert, key)
                }
                "content" => {
                    let cert = self.resolve(&cfg.cert_content, &cfg.cert_content_env);
                    let key = self.resolve(&cfg.key_content, &cfg.key_content_env);
                    match (cert, key) {
                        (Some(cert), Some(key)) => (
                            cert.expose().as_bytes().to_vec(),
                            key.expose().as_bytes().to_vec(),
                        ),
                        _ => {
                            if let Some((current, files)) = old
                                && current.fingerprint == cfg.fingerprint()
                                && files.not_after_unix > now
                            {
                                let cert = storage::read_bounded(&files.cert, 1024 * 1024)
                                    .map_err(|_| CertificateError::Storage)?;
                                let mut key = storage::read_bounded(&files.key, 1024 * 1024)
                                    .map_err(|_| CertificateError::Storage)?;
                                let valid = validate_material(&cert, &key, cfg, now);
                                key.zeroize();
                                valid?;
                                return Ok(Some(files));
                            }
                            return Err(CertificateError::Config(
                                "content mode requires both PEM secret references",
                            ));
                        }
                    }
                }
                "http" | "dns" => self.obtain(cfg, &directory).await?,
                _ => return Err(CertificateError::Config("unsupported mode")),
            }
        };
        let result = (|| {
            // ACME issuance may cross a second boundary; validate the newly
            // issued notBefore at completion time rather than request time.
            let validation_now = if matches!(cfg.mode(), "http" | "dns") {
                now.max(time::OffsetDateTime::now_utc().unix_timestamp())
            } else {
                now
            };
            let (not_before, not_after) = validate_material(&cert, &key, cfg, validation_now)?;
            if let Some((current, files)) = &old
                && current.fingerprint == cfg.fingerprint()
                && storage::read_bounded(&files.cert, 1024 * 1024)
                    .ok()
                    .as_deref()
                    == Some(cert.as_slice())
            {
                return Ok(Some(files.clone()));
            }
            let generation = random_id()?;
            let version_dir = directory.join(&generation);
            storage::private_dir(&version_dir).map_err(|_| CertificateError::Storage)?;
            let cert_path = version_dir.join("cert.pem");
            let key_path = version_dir.join("key.pem");
            storage::create_private(&cert_path, &cert).map_err(|_| CertificateError::Storage)?;
            storage::create_private(&key_path, &key).map_err(|_| CertificateError::Storage)?;
            #[cfg(unix)]
            std::fs::File::open(&version_dir)
                .and_then(|directory| directory.sync_all())
                .map_err(|_| CertificateError::Storage)?;
            let current = Current {
                fingerprint: cfg.fingerprint(),
                generation: generation.clone(),
                next_renew_unix: renewal_time(cfg, not_before, not_after),
                not_after_unix: not_after,
            };
            let pointer = serde_json::to_vec(&current).map_err(|_| CertificateError::Storage)?;
            storage::atomic_private(&directory.join("current.json"), &pointer)
                .map_err(|_| CertificateError::Storage)?;
            Ok(Some(CertificateFiles {
                cert: cert_path,
                key: key_path,
                next_renew_unix: current.next_renew_unix,
                not_after_unix: not_after,
                generation,
            }))
        })();
        key.zeroize();
        result
    }
    fn resolve(&self, direct: &Secret, reference: &Option<String>) -> Option<Secret> {
        if !direct.is_empty() {
            Some(direct.clone())
        } else {
            reference.as_ref().and_then(|name| self.secrets.get(name))
        }
    }
    /// Read the last successfully committed pair even after renewal failed.
    pub fn read_current(
        &self,
        cfg: &CertConfig,
        state_dir: &Path,
    ) -> Result<Option<CertificateFiles>, CertificateError> {
        let directory = cfg
            .cert_dir
            .clone()
            .unwrap_or_else(|| state_dir.join("certs"));
        self.current(&directory)
            .map(|pair| pair.map(|(_, files)| files))
    }
    fn current(
        &self,
        directory: &Path,
    ) -> Result<Option<(Current, CertificateFiles)>, CertificateError> {
        let path = directory.join("current.json");
        if !path.exists() {
            return Ok(None);
        }
        storage::check_private(&path).map_err(|_| CertificateError::Storage)?;
        let data = storage::read_bounded(&path, 8192).map_err(|_| CertificateError::Storage)?;
        let current: Current =
            serde_json::from_slice(&data).map_err(|_| CertificateError::Storage)?;
        if current.generation.len() != 24
            || !current.generation.bytes().all(|b| b.is_ascii_hexdigit())
        {
            return Err(CertificateError::Storage);
        }
        let cert = directory.join(&current.generation).join("cert.pem");
        let key = directory.join(&current.generation).join("key.pem");
        storage::check_private(&cert).map_err(|_| CertificateError::Storage)?;
        storage::check_private(&key).map_err(|_| CertificateError::Storage)?;
        let files = CertificateFiles {
            cert,
            key,
            generation: current.generation.clone(),
            next_renew_unix: current.next_renew_unix,
            not_after_unix: current.not_after_unix,
        };
        Ok(Some((current, files)))
    }
    fn dns_provider(&self, cfg: &CertConfig) -> Result<Arc<dyn DnsProvider>, CertificateError> {
        if let Some(provider) = &self.dns {
            return Ok(provider.clone());
        }
        if let Some(hook) = &cfg.dns_hook {
            let mut credentials = cfg.dns_env.clone();
            for (key, reference) in &cfg.dns_env_refs {
                credentials.insert(
                    key.clone(),
                    self.secrets
                        .get(reference)
                        .ok_or(CertificateError::Config("missing DNS hook credential"))?,
                );
            }
            return Ok(Arc::new(ExternalHookProvider {
                executable: hook.clone(),
                credentials,
                timeout: Duration::from_secs(60),
            }));
        }
        if matches!(
            cfg.dns_provider.to_ascii_lowercase().as_str(),
            "cf" | "cloudflare"
        ) {
            return Ok(Arc::new(CloudflareProvider::from_refs(
                &cfg.dns_env_refs,
                &cfg.dns_env,
                self.secrets.as_ref(),
                cfg.dns_zone_id.clone(),
            )?));
        }
        Err(CertificateError::Config(
            "DNS provider requires cloudflare or an explicit external hook",
        ))
    }
    async fn obtain(
        &self,
        cfg: &CertConfig,
        directory: &Path,
    ) -> Result<(Vec<u8>, Vec<u8>), CertificateError> {
        let timeout = Duration::from_secs(cfg.challenge_timeout_seconds.unwrap_or(180));
        let account_dir = directory.join("accounts");
        storage::private_dir(&account_dir).map_err(|_| CertificateError::Storage)?;
        let account_name = format!(
            "{:x}",
            Sha256::digest(format!("{}|{}", cfg.directory(), cfg.email).as_bytes())
        );
        let account_path = account_dir.join(format!("{account_name}.json"));
        let builder = match &cfg.acme_ca_file {
            Some(root) => Account::builder_with_root(root),
            None => Account::builder(),
        }
        .map_err(|_| CertificateError::Acme("client initialization"))?;
        let account = if account_path.exists() {
            storage::check_private(&account_path).map_err(|_| CertificateError::Storage)?;
            let mut bytes = storage::read_bounded(&account_path, 64 * 1024)
                .map_err(|_| CertificateError::Storage)?;
            let credentials = serde_json::from_slice(&bytes).map_err(|_| CertificateError::Storage);
            bytes.zeroize();
            tokio::time::timeout(timeout, builder.from_credentials(credentials?))
                .await
                .map_err(|_| CertificateError::Acme("account restore timeout"))?
                .map_err(|_| CertificateError::Acme("account restore"))?
        } else {
            let mail = (!cfg.email.is_empty()).then(|| format!("mailto:{}", cfg.email));
            let contacts: Vec<&str> = mail.iter().map(String::as_str).collect();
            let (account, credentials) = tokio::time::timeout(
                timeout,
                builder.create(
                    &NewAccount {
                        contact: &contacts,
                        terms_of_service_agreed: true,
                        only_return_existing: false,
                    },
                    cfg.directory().to_owned(),
                    None,
                ),
            )
            .await
            .map_err(|_| CertificateError::Acme("account creation timeout"))?
            .map_err(|_| CertificateError::Acme("account creation"))?;
            let mut bytes =
                serde_json::to_vec(&credentials).map_err(|_| CertificateError::Storage)?;
            let written = storage::create_private(&account_path, &bytes);
            bytes.zeroize();
            written.map_err(|_| CertificateError::Storage)?;
            account
        };
        let identifiers = [Identifier::Dns(cfg.domain.to_ascii_lowercase())];
        let mut order =
            tokio::time::timeout(timeout, account.new_order(&NewOrder::new(&identifiers)))
                .await
                .map_err(|_| CertificateError::Acme("order creation timeout"))?
                .map_err(|_| CertificateError::Acme("order creation"))?;
        let dns = if cfg.mode() == "dns" {
            Some(self.dns_provider(cfg)?)
        } else {
            None
        };
        let mut http_leases = Vec::new();
        let mut dns_cleanup = DnsCleanupGuard {
            provider: dns.clone(),
            leases: Vec::new(),
        };
        let issued = tokio::time::timeout(timeout, async {
            let mut authorizations = order.authorizations();
            while let Some(result) = authorizations.next().await {
                let mut authz =
                    result.map_err(|_| CertificateError::Acme("authorization retrieval"))?;
                match authz.status {
                    AuthorizationStatus::Valid => continue,
                    AuthorizationStatus::Pending => {}
                    _ => return Err(CertificateError::Acme("authorization rejected")),
                }
                let kind = if dns.is_some() {
                    ChallengeType::Dns01
                } else {
                    ChallengeType::Http01
                };
                let mut challenge = authz
                    .challenge(kind)
                    .ok_or(CertificateError::Acme("required challenge unavailable"))?;
                if let Some(provider) = &dns {
                    let record = DnsRecord {
                        name: format!(
                            "_acme-challenge.{}",
                            challenge.identifier().to_string().trim_start_matches("*.")
                        ),
                        value: challenge.key_authorization().dns_value(),
                    };
                    let lease = provider.present(&record).await?;
                    dns_cleanup.leases.push(lease);
                    let deadline = Instant::now()
                        + Duration::from_secs(cfg.dns_propagation_timeout_seconds.unwrap_or(120));
                    loop {
                        if provider.propagated(&record).await? {
                            break;
                        }
                        if Instant::now() >= deadline {
                            return Err(CertificateError::Dns("propagation timeout"));
                        }
                        tokio::time::sleep(Duration::from_secs(2)).await;
                    }
                } else {
                    let domain = challenge.identifier().to_string();
                    http_leases.push(self.challenges.present(
                        &domain,
                        &challenge.token,
                        challenge.key_authorization().as_str(),
                        timeout,
                    )?);
                }
                challenge
                    .set_ready()
                    .await
                    .map_err(|_| CertificateError::Acme("challenge activation"))?;
            }
            let policy = RetryPolicy::new()
                .initial_delay(Duration::from_millis(250))
                .timeout(timeout);
            if order
                .poll_ready(&policy)
                .await
                .map_err(|_| CertificateError::Acme("authorization polling"))?
                != OrderStatus::Ready
            {
                return Err(CertificateError::Acme("authorization rejected"));
            }
            let key = rcgen::KeyPair::generate().map_err(|_| CertificateError::Material)?;
            let params = rcgen::CertificateParams::new(vec![cfg.domain.to_ascii_lowercase()])
                .map_err(|_| CertificateError::Material)?;
            let csr = params
                .serialize_request(&key)
                .map_err(|_| CertificateError::Material)?;
            order
                .finalize_csr(csr.der())
                .await
                .map_err(|_| CertificateError::Acme("order finalization"))?;
            let cert = order
                .poll_certificate(&policy)
                .await
                .map_err(|_| CertificateError::Acme("certificate polling"))?;
            Ok((cert.into_bytes(), key.serialize_pem().into_bytes()))
        })
        .await
        .map_err(|_| CertificateError::Acme("issuance timeout"));
        // Cleanup is attempted on every ordinary failure and timeout, and only
        // record IDs created by this order are deleted. HTTP leases also drop.
        let mut cleanup_error = None;
        if let Some(provider) = &dns {
            for lease in dns_cleanup.leases.iter().rev() {
                match tokio::time::timeout(Duration::from_secs(30), provider.cleanup(lease)).await {
                    Ok(Ok(())) => {}
                    _ => cleanup_error = Some(CertificateError::Dns("challenge cleanup")),
                }
            }
        }
        // Retain failed leases in the guard for another bounded cleanup attempt.
        if cleanup_error.is_none() {
            dns_cleanup.leases.clear();
        }
        drop(http_leases);
        let mut pair = issued??;
        if let Some(error) = cleanup_error {
            pair.1.zeroize();
            return Err(error);
        }
        Ok(pair)
    }
}

fn renewal_time(cfg: &CertConfig, not_before: i64, not_after: i64) -> i64 {
    let window = cfg
        .renew_before_seconds
        .unwrap_or(30 * 86400)
        .min((not_after - not_before).max(3) as u64 / 3)
        .min(i64::MAX as u64) as i64;
    not_after - window
}
fn legacy_material(
    cfg: &CertConfig,
    directory: &Path,
    now: i64,
) -> Result<Option<PemMaterial>, CertificateError> {
    let cert_path = directory.join("cert.pem");
    let key_path = directory.join("key.pem");
    if !cert_path.exists() && !key_path.exists() {
        return Ok(None);
    }
    if !cert_path.exists() || !key_path.exists() {
        return Err(CertificateError::Material);
    }
    storage::check_private(&key_path).map_err(|_| CertificateError::Storage)?;
    let cert =
        storage::read_bounded(&cert_path, 1024 * 1024).map_err(|_| CertificateError::Storage)?;
    let mut key =
        storage::read_bounded(&key_path, 1024 * 1024).map_err(|_| CertificateError::Storage)?;
    if let Ok((before, after)) = validate_material(&cert, &key, cfg, now)
        && now < renewal_time(cfg, before, after)
    {
        // Switching from a persisted self-signed certificate to ACME must
        // actually obtain an issuer-signed certificate, rather than adopting it.
        let chain = rustls_pemfile::certs(&mut BufReader::new(cert.as_slice()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| CertificateError::Material)?;
        let (_, leaf) = x509_parser::parse_x509_certificate(chain[0].as_ref())
            .map_err(|_| CertificateError::Material)?;
        if !matches!(cfg.mode(), "http" | "dns") || leaf.subject() != leaf.issuer() {
            return Ok(Some((cert, key)));
        }
    }
    key.zeroize();
    Ok(None)
}

fn self_signed(cfg: &CertConfig, now: i64) -> Result<(Vec<u8>, Vec<u8>), CertificateError> {
    let domain = if cfg.domain.is_empty() {
        "localhost"
    } else {
        &cfg.domain
    };
    let mut params = rcgen::CertificateParams::new(vec![domain.to_owned()])
        .map_err(|_| CertificateError::Material)?;
    params.not_before = time::OffsetDateTime::from_unix_timestamp(now - 3600)
        .map_err(|_| CertificateError::Material)?;
    params.not_after = time::OffsetDateTime::from_unix_timestamp(now + 10 * 365 * 86400)
        .map_err(|_| CertificateError::Material)?;
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, domain);
    params.key_usages = vec![
        rcgen::KeyUsagePurpose::DigitalSignature,
        rcgen::KeyUsagePurpose::KeyEncipherment,
    ];
    params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
    let key = rcgen::KeyPair::generate().map_err(|_| CertificateError::Material)?;
    let cert = params
        .self_signed(&key)
        .map_err(|_| CertificateError::Material)?;
    Ok((cert.pem().into_bytes(), key.serialize_pem().into_bytes()))
}
fn validate_material(
    cert: &[u8],
    key: &[u8],
    cfg: &CertConfig,
    now: i64,
) -> Result<(i64, i64), CertificateError> {
    if cert.is_empty() || key.is_empty() {
        return Err(CertificateError::Material);
    }
    let chain = rustls_pemfile::certs(&mut BufReader::new(cert))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| CertificateError::Material)?;
    if chain.is_empty() {
        return Err(CertificateError::Material);
    }
    let private = rustls_pemfile::private_key(&mut BufReader::new(key))
        .map_err(|_| CertificateError::Material)?
        .ok_or(CertificateError::Material)?;
    let provider = rustls::crypto::ring::default_provider();
    let certified = rustls::sign::CertifiedKey::from_der(chain.clone(), private, &provider)
        .map_err(|_| CertificateError::Material)?;
    certified
        .keys_match()
        .map_err(|_| CertificateError::Material)?;
    let (_, leaf) = x509_parser::parse_x509_certificate(chain[0].as_ref())
        .map_err(|_| CertificateError::Material)?;
    let before = leaf.validity().not_before.timestamp();
    let after = leaf.validity().not_after.timestamp();
    if before > now || after <= now {
        return Err(CertificateError::Material);
    }
    if !cfg.domain.is_empty() {
        let san = leaf
            .subject_alternative_name()
            .map_err(|_| CertificateError::Material)?
            .ok_or(CertificateError::Material)?;
        let matches = san.value.general_names.iter().any(|name| match name {
            x509_parser::extensions::GeneralName::DNSName(name) => {
                name.eq_ignore_ascii_case(&cfg.domain)
                    || (name.starts_with("*.")
                        && !cfg.domain.starts_with("*.")
                        && cfg
                            .domain
                            .split_once('.')
                            .is_some_and(|(_, tail)| tail.eq_ignore_ascii_case(&name[2..])))
            }
            x509_parser::extensions::GeneralName::IPAddress(bytes) => cfg
                .domain
                .parse::<std::net::IpAddr>()
                .ok()
                .is_some_and(|address| match address {
                    std::net::IpAddr::V4(address) => bytes == &address.octets().as_slice(),
                    std::net::IpAddr::V6(address) => bytes == &address.octets().as_slice(),
                }),
            _ => false,
        });
        if !matches {
            return Err(CertificateError::Material);
        }
    }
    Ok((before, after))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn challenge_store_restricts_host_method_path_token_and_lifetime_and_http_server() {
        let store = ChallengeStore::default();
        let token = "abcdefghijklmnopqrstuvwxyz0123456789";
        let body = format!("{token}.accountthumbprint");
        let lease = store
            .present("node.example.test", token, &body, Duration::from_secs(20))
            .unwrap();
        let path = format!("/.well-known/acme-challenge/{token}");
        assert_eq!(
            store.response("GET", "NODE.EXAMPLE.TEST:80", &path),
            Some(body.clone())
        );
        for (method, host, path) in [
            ("POST", "node.example.test", path.as_str()),
            ("GET", "wrong.example.test", path.as_str()),
            ("GET", "node.example.test", "/other"),
            (
                "GET",
                "node.example.test",
                "/.well-known/acme-challenge/../x",
            ),
            ("GET", "node.example.test", &format!("{path}?x=1")),
            ("GET", "node.example.test:invalid", path.as_str()),
        ] {
            assert!(store.response(method, host, path).is_none());
        }
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let (shutdown, mut receiver) = watch::channel(false);
        let clone = store.clone();
        let server =
            tokio::spawn(async move { clone.serve_listener(listener, &mut receiver).await });
        let mut socket = tokio::net::TcpStream::connect(address).await.unwrap();
        socket
            .write_all(format!("GET {path} HTTP/1.1\r\nHost: node.example.test\r\n\r\n").as_bytes())
            .await
            .unwrap();
        let mut response = String::new();
        socket.read_to_string(&mut response).await.unwrap();
        assert!(response.starts_with("HTTP/1.1 200 OK"));
        assert!(response.ends_with(&body));
        let mut duplicate = tokio::net::TcpStream::connect(address).await.unwrap();
        duplicate
            .write_all(
                format!(
                    "GET {path} HTTP/1.1\r\nHost: node.example.test\r\nHost: wrong.test\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let mut response = String::new();
        duplicate.read_to_string(&mut response).await.unwrap();
        assert!(response.starts_with("HTTP/1.1 404"));
        shutdown.send(true).unwrap();
        server.await.unwrap().unwrap();
        drop(lease);
        assert!(store.response("GET", "node.example.test", &path).is_none());
        let expired = store
            .present("node.example.test", token, &body, Duration::ZERO)
            .unwrap();
        assert!(store.response("GET", "node.example.test", &path).is_none());
        drop(expired);
    }
}
