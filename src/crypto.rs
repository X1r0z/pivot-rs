use std::sync::Arc;

use anyhow::Result;
use rcgen::{generate_simple_self_signed, CertifiedKey};
use rustls::{
    client::danger::ServerCertVerifier,
    pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer},
    ClientConfig, ServerConfig, SignatureScheme,
};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tracing::info;

pub fn get_tls_acceptor(host: &str) -> Result<TlsAcceptor> {
    info!("Generate self-signed tls certificate for {}", host);

    let subject_alt_names = vec![host.into()];
    let CertifiedKey { cert, key_pair } = generate_simple_self_signed(subject_alt_names)?;

    let cert_chain = CertificateDer::pem_slice_iter(cert.pem().as_bytes())
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let key_der = PrivateKeyDer::from_pem_slice(key_pair.serialize_pem().as_bytes())?;
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, key_der)?;

    Ok(TlsAcceptor::from(Arc::new(config)))
}

pub fn get_tls_connector() -> TlsConnector {
    let config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoCertVerifier))
        .with_no_client_auth();

    TlsConnector::from(Arc::new(config))
}

#[derive(Debug)]
struct NoCertVerifier;

impl ServerCertVerifier for NoCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn requires_raw_public_keys(&self) -> bool {
        false
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::ECDSA_SHA1_Legacy,
            SignatureScheme::ED25519,
            SignatureScheme::ED448,
            SignatureScheme::RSA_PKCS1_SHA1,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
        ]
    }
}
