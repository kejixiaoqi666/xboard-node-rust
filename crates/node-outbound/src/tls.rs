use crate::{OutboundTls, invalid};
use rustls::{
    ClientConfig, RootCertStore,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, ServerName, UnixTime},
};
use std::{
    fs::File,
    io::{self, BufReader, Read},
    sync::Arc,
};

/// Certificate files are local, bounded, and parsed before a graph becomes active.
pub fn tls_client_config(paths: &[&str]) -> io::Result<ClientConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut roots = RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    if paths.len() > 64 {
        return Err(invalid("too many CA files"));
    }
    for path in paths {
        let file = File::open(path)?;
        if !file.metadata()?.is_file() || file.metadata()?.len() > 2 * 1024 * 1024 {
            return Err(invalid("CA file exceeds limit"));
        }
        let mut bytes = Vec::new();
        file.take(2 * 1024 * 1024 + 1).read_to_end(&mut bytes)?;
        if bytes.len() > 2 * 1024 * 1024 {
            return Err(invalid("CA file exceeds limit"));
        }
        let certs = rustls_pemfile::certs(&mut BufReader::new(bytes.as_slice()))
            .collect::<Result<Vec<_>, _>>()?;
        if certs.is_empty() || certs.len() > 256 {
            return Err(invalid("invalid CA file"));
        }
        for cert in certs {
            roots
                .add(cert)
                .map_err(|_| invalid("invalid CA certificate"))?;
        }
    }
    Ok(ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|_| invalid("TLS protocol configuration"))?
        .with_root_certificates(roots)
        .with_no_client_auth())
}
pub(crate) fn prepare(setting: &OutboundTls) -> io::Result<Arc<ClientConfig>> {
    let paths = setting
        .ca_file
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    let mut config = tls_client_config(&paths)?;
    config.alpn_protocols = setting.alpn.iter().map(|s| s.as_bytes().to_vec()).collect();
    if setting.insecure {
        config
            .dangerous()
            .set_certificate_verifier(Arc::new(Insecure(rustls::crypto::ring::default_provider())));
    }
    Ok(Arc::new(config))
}
#[derive(Debug)]
struct Insecure(rustls::crypto::CryptoProvider);
impl ServerCertVerifier for Insecure {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        sig: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            sig,
            &self.0.signature_verification_algorithms,
        )
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        sig: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            sig,
            &self.0.signature_verification_algorithms,
        )
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}
