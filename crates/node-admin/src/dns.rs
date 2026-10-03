//! DNS-01 provider adapters. Tests must use loopback endpoints, never live writes.
use crate::{
    certificate::CertificateError,
    secrets::{Secret, SecretResolver},
};
use async_trait::async_trait;
use serde::Deserialize;
use std::{collections::BTreeMap, path::PathBuf, process::Stdio, time::Duration};
use tokio::process::Command;

#[derive(Clone, Debug)]
pub struct DnsRecord {
    pub name: String,
    pub value: String,
}
#[derive(Clone, Debug)]
pub struct DnsLease {
    pub record: DnsRecord,
    pub zone_id: String,
    pub record_id: String,
}

#[async_trait]
pub trait DnsProvider: Send + Sync {
    async fn present(&self, record: &DnsRecord) -> Result<DnsLease, CertificateError>;
    async fn cleanup(&self, lease: &DnsLease) -> Result<(), CertificateError>;
    /// An external hook may implement its own authoritative propagation checks.
    async fn propagated(&self, record: &DnsRecord) -> Result<bool, CertificateError> {
        system_txt_visible(record).await
    }
}
pub async fn system_txt_visible(record: &DnsRecord) -> Result<bool, CertificateError> {
    let resolver = hickory_resolver::Resolver::builder_tokio()
        .map_err(|_| CertificateError::Dns("resolver configuration"))?
        .build()
        .map_err(|_| CertificateError::Dns("resolver initialization"))?;
    match resolver.txt_lookup(&record.name).await {
        Ok(records) => Ok(records.answers().iter().any(|answer| match &answer.data {
            hickory_resolver::proto::rr::RData::TXT(txt) => {
                txt.txt_data
                    .iter()
                    .flat_map(|part| part.iter().copied())
                    .collect::<Vec<u8>>()
                    == record.value.as_bytes()
            }
            _ => false,
        })),
        Err(_) => Ok(false),
    }
}

pub struct CloudflareProvider {
    client: reqwest::Client,
    base: url::Url,
    token: Secret,
    zone_id: Option<String>,
}
#[derive(Deserialize)]
struct Envelope<T> {
    success: bool,
    result: T,
}
#[derive(Deserialize)]
struct Id {
    id: String,
}
impl CloudflareProvider {
    pub fn new(token: Secret, zone_id: Option<String>) -> Result<Self, CertificateError> {
        Self::with_endpoint(token, zone_id, "https://api.cloudflare.com/client/v4/")
    }
    /// Loopback HTTP is supported solely for isolated API contract tests.
    pub fn with_endpoint(
        token: Secret,
        zone_id: Option<String>,
        endpoint: &str,
    ) -> Result<Self, CertificateError> {
        let base = url::Url::parse(endpoint)
            .map_err(|_| CertificateError::Config("invalid DNS endpoint"))?;
        let local = matches!(base.host_str(), Some("localhost" | "127.0.0.1" | "::1"));
        if token.is_empty()
            || (base.scheme() != "https" && !(local && base.scheme() == "http"))
            || !base.username().is_empty()
            || base.password().is_some()
            || base.query().is_some()
            || base.fragment().is_some()
            || zone_id.as_deref().is_some_and(|s| !valid_id(s))
        {
            return Err(CertificateError::Config(
                "invalid DNS credentials or endpoint",
            ));
        }
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(20))
            .build()
            .map_err(|_| CertificateError::Dns("client initialization"))?;
        Ok(Self {
            client,
            base,
            token,
            zone_id,
        })
    }
    pub fn from_refs(
        refs: &BTreeMap<String, String>,
        direct: &BTreeMap<String, Secret>,
        secrets: &dyn SecretResolver,
        zone_id: Option<String>,
    ) -> Result<Self, CertificateError> {
        let names = [
            "CLOUDFLARE_DNS_API_TOKEN",
            "CF_API_TOKEN",
            "CLOUDFLARE_API_TOKEN",
        ];
        let token = names
            .iter()
            .find_map(|name| {
                direct
                    .get(*name)
                    .filter(|s| !s.is_empty())
                    .cloned()
                    .or_else(|| refs.get(*name).and_then(|reference| secrets.get(reference)))
                    .or_else(|| secrets.get(name))
            })
            .ok_or(CertificateError::Config(
                "missing Cloudflare token reference",
            ))?;
        Self::new(token, zone_id)
    }
    fn endpoint(&self, path: &str) -> Result<url::Url, CertificateError> {
        self.base
            .join(path)
            .map_err(|_| CertificateError::Dns("endpoint construction"))
    }
    async fn zone(&self, name: &str) -> Result<String, CertificateError> {
        if let Some(zone) = &self.zone_id {
            return Ok(zone.clone());
        }
        // Find the closest actual authoritative zone, not a guessed last-two-label suffix.
        let domain = name
            .trim_end_matches('.')
            .strip_prefix("_acme-challenge.")
            .ok_or(CertificateError::Dns("invalid challenge record name"))?;
        let labels: Vec<_> = domain.split('.').collect();
        for offset in 0..labels.len().saturating_sub(1) {
            let candidate = labels[offset..].join(".");
            let response = self
                .client
                .get(self.endpoint("zones")?)
                .bearer_auth(self.token.expose())
                .query(&[
                    ("name", candidate.as_str()),
                    ("status", "active"),
                    ("per_page", "2"),
                ])
                .send()
                .await
                .map_err(|_| CertificateError::Dns("zone lookup request"))?;
            if !response.status().is_success() {
                return Err(CertificateError::Dns("zone lookup rejected"));
            }
            let result: Envelope<Vec<Id>> = response
                .json()
                .await
                .map_err(|_| CertificateError::Dns("zone lookup response"))?;
            if !result.success {
                return Err(CertificateError::Dns("zone lookup rejected"));
            }
            if result.result.len() == 1 && valid_id(&result.result[0].id) {
                return Ok(result.result[0].id.clone());
            }
            if result.result.len() > 1 {
                return Err(CertificateError::Dns("ambiguous zone"));
            }
        }
        Err(CertificateError::Dns("zone not found"))
    }
}
fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}
#[async_trait]
impl DnsProvider for CloudflareProvider {
    async fn present(&self, record: &DnsRecord) -> Result<DnsLease, CertificateError> {
        validate_record(record)?;
        let zone_id = self.zone(&record.name).await?;
        let response = self.client.post(self.endpoint(&format!("zones/{zone_id}/dns_records"))?)
            .bearer_auth(self.token.expose())
            .json(&serde_json::json!({"type":"TXT", "name":record.name, "content":record.value, "ttl":120}))
            .send().await.map_err(|_| CertificateError::Dns("record creation request"))?;
        if !response.status().is_success() {
            return Err(CertificateError::Dns("record creation rejected"));
        }
        let result: Envelope<Id> = response
            .json()
            .await
            .map_err(|_| CertificateError::Dns("record creation response"))?;
        if !result.success || !valid_id(&result.result.id) {
            return Err(CertificateError::Dns("record creation rejected"));
        }
        Ok(DnsLease {
            record: record.clone(),
            zone_id,
            record_id: result.result.id,
        })
    }
    async fn cleanup(&self, lease: &DnsLease) -> Result<(), CertificateError> {
        if !valid_id(&lease.zone_id) || !valid_id(&lease.record_id) {
            return Err(CertificateError::Dns("invalid record ownership"));
        }
        let response = self
            .client
            .delete(self.endpoint(&format!(
                "zones/{}/dns_records/{}",
                lease.zone_id, lease.record_id
            ))?)
            .bearer_auth(self.token.expose())
            .send()
            .await
            .map_err(|_| CertificateError::Dns("record cleanup request"))?;
        if !response.status().is_success() {
            return Err(CertificateError::Dns("record cleanup rejected"));
        }
        let result: Envelope<serde_json::Value> = response
            .json()
            .await
            .map_err(|_| CertificateError::Dns("record cleanup response"))?;
        if !result.success {
            return Err(CertificateError::Dns("record cleanup rejected"));
        }
        Ok(())
    }
}

/// Provider-neutral executable contract: program OP NAME VALUE. Only configured
/// credential references enter its environment; stdout/stderr never enter logs.
pub struct ExternalHookProvider {
    pub executable: PathBuf,
    pub credentials: BTreeMap<String, Secret>,
    pub timeout: Duration,
}
impl ExternalHookProvider {
    async fn invoke(&self, operation: &str, record: &DnsRecord) -> Result<(), CertificateError> {
        validate_record(record)?;
        if !self.executable.is_absolute() || !self.executable.is_file() {
            return Err(CertificateError::Config(
                "DNS hook must be an absolute executable file",
            ));
        }
        let mut command = Command::new(&self.executable);
        command
            .args([operation, &record.name, &record.value])
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true);
        for (name, value) in &self.credentials {
            if !crate::secrets::valid_env_name(name) {
                return Err(CertificateError::Config(
                    "invalid DNS hook environment name",
                ));
            }
            command.env(name, value.expose());
        }
        let status = tokio::time::timeout(self.timeout, command.status())
            .await
            .map_err(|_| CertificateError::Dns("external hook timeout"))?
            .map_err(|_| CertificateError::Dns("external hook execution"))?;
        if !status.success() {
            return Err(CertificateError::Dns("external hook failed"));
        }
        Ok(())
    }
}
fn validate_record(record: &DnsRecord) -> Result<(), CertificateError> {
    let domain = record
        .name
        .trim_end_matches('.')
        .strip_prefix("_acme-challenge.")
        .ok_or(CertificateError::Dns("invalid challenge name"))?;
    if !crate::certificate::valid_domain(domain, false)
        || record.value.len() != 43
        || !record
            .value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(CertificateError::Dns("invalid challenge record"));
    }
    Ok(())
}
#[async_trait]
impl DnsProvider for ExternalHookProvider {
    async fn present(&self, record: &DnsRecord) -> Result<DnsLease, CertificateError> {
        self.invoke("present", record).await?;
        Ok(DnsLease {
            record: record.clone(),
            zone_id: String::new(),
            record_id: String::new(),
        })
    }
    async fn cleanup(&self, lease: &DnsLease) -> Result<(), CertificateError> {
        self.invoke("cleanup", &lease.record).await
    }
    async fn propagated(&self, record: &DnsRecord) -> Result<bool, CertificateError> {
        self.invoke("propagated", record).await.map(|_| true)
    }
}
