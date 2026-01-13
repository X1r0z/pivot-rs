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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_tls_acceptor_localhost() {
        let acceptor = get_tls_acceptor("localhost");
        assert!(acceptor.is_ok());
    }

    #[test]
    fn test_get_tls_acceptor_ip_address() {
        let acceptor = get_tls_acceptor("127.0.0.1");
        assert!(acceptor.is_ok());
    }

    #[test]
    fn test_get_tls_acceptor_domain() {
        let acceptor = get_tls_acceptor("example.com");
        assert!(acceptor.is_ok());
    }

    #[test]
    fn test_get_tls_acceptor_with_port() {
        let acceptor = get_tls_acceptor("0.0.0.0:8443");
        assert!(acceptor.is_ok());
    }

    #[test]
    fn test_get_tls_connector() {
        let _connector = get_tls_connector();
    }

    #[test]
    fn test_no_cert_verifier_requires_raw_public_keys() {
        let verifier = NoCertVerifier;
        assert!(!verifier.requires_raw_public_keys());
    }

    #[test]
    fn test_no_cert_verifier_supported_schemes() {
        let verifier = NoCertVerifier;
        let schemes = verifier.supported_verify_schemes();

        assert!(!schemes.is_empty());
        assert!(schemes.contains(&SignatureScheme::ECDSA_NISTP256_SHA256));
        assert!(schemes.contains(&SignatureScheme::RSA_PKCS1_SHA256));
        assert!(schemes.contains(&SignatureScheme::ED25519));
    }

    #[tokio::test]
    async fn test_tls_acceptor_and_connector_handshake() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::{TcpListener, TcpStream};

        let acceptor = get_tls_acceptor("localhost").unwrap();
        let connector = get_tls_connector();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut tls_stream = acceptor.accept(stream).await.unwrap();

            let mut buf = [0u8; 5];
            tls_stream.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"hello");

            tls_stream.write_all(b"world").await.unwrap();
        });

        let client_task = tokio::spawn(async move {
            let stream = TcpStream::connect(addr).await.unwrap();
            let server_name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
            let mut tls_stream = connector.connect(server_name, stream).await.unwrap();

            tls_stream.write_all(b"hello").await.unwrap();

            let mut buf = [0u8; 5];
            tls_stream.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"world");
        });

        let (server_result, client_result) = tokio::join!(server_task, client_task);
        server_result.unwrap();
        client_result.unwrap();
    }
}
