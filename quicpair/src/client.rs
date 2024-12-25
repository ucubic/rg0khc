use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{Arc, OnceLock},
};

use quinn::{
    ClientConfig, Connection, Endpoint,
    crypto::rustls::QuicClientConfig,
    rustls::{
        self,
        pki_types::{CertificateDer, ServerName, UnixTime},
    },
};

use crate::{ClientId, Signature};
use anyhow::Result;
use x509_parser::prelude::{GeneralName, X509Certificate};

pub struct Client {
    connection: Connection,
}
impl Client {
    pub async fn connect(addr: SocketAddr) -> Result<(Self, Signature)> {
        let mut endpoint = Endpoint::client(SocketAddr::new(
            if addr.is_ipv4() {
                IpAddr::V4(Ipv4Addr::UNSPECIFIED)
            } else {
                IpAddr::V6(Ipv6Addr::UNSPECIFIED)
            },
            0,
        ))?;
        let verifier = QuicPairServerVerification::new();
        let key_lock = verifier.clone_lock();
        endpoint.set_default_client_config(ClientConfig::new(Arc::new(
            QuicClientConfig::try_from(
                rustls::ClientConfig::builder()
                    .dangerous()
                    .with_custom_certificate_verifier(verifier)
                    .with_no_client_auth(),
            )?,
        )));

        let connection = endpoint
            .connect(addr, super::QUICPAIR_SUBJECT_NAME)?
            .await?;

        let server_key = *key_lock
            .get()
            .expect("client connected but didn't set the server certificate??");

        Ok((Self { connection }, server_key))
    }

    pub async fn confirm_signature(self) -> Result<(ClientId, Connection)> {
        let Self { connection } = self;

        let mut rx = connection.accept_uni().await?;
        let mut client_id_bytes = [0u8; 2];
        rx.read_exact(&mut client_id_bytes).await?;
        let client_id = ClientId::from_u16(u16::from_le_bytes(client_id_bytes))?;
        drop(rx);

        Ok((client_id, connection))
    }
}

#[derive(Debug)]
struct QuicPairServerVerification {
    crypto: Arc<rustls::crypto::CryptoProvider>,
    server_key: Arc<OnceLock<Signature>>,
}

impl QuicPairServerVerification {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            crypto: Arc::new(rustls::crypto::ring::default_provider()),
            server_key: Arc::new(OnceLock::new()),
        })
    }

    fn clone_lock(&self) -> Arc<OnceLock<Signature>> {
        self.server_key.clone()
    }

    fn verify_cert(&self, certificate: &X509Certificate, subject_name: &str) -> bool {
        if certificate.signature != crate::CERT_ALGO {
            return false;
        }

        let Ok(Some(subject_alternative_name)) = certificate.subject_alternative_name() else {
            return false;
        };

        let &[GeneralName::DNSName(name)] = &*subject_alternative_name.value.general_names else {
            return false;
        };

        if name != subject_name {
            return false;
        }

        true
    }
}

impl rustls::client::danger::ServerCertVerifier for QuicPairServerVerification {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        let (_, certificate) = x509_parser::parse_x509_certificate(&end_entity).map_err(|_| {
            rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding)
        })?;

        if !self.verify_cert(&certificate, &server_name.to_str()) {
            return Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::Other(rustls::OtherError(Arc::from(Box::<
                    dyn std::error::Error + Send + Sync,
                >::from(
                    anyhow::anyhow!(
                    "certificate is valid but isn't of the same protocol; are you sure this is a valid server?",
                )
                )))),
            ));
        }

        let key_bytes: &[u8; 10] = certificate.signature_value.data[0..10]
            .try_into()
            .expect("unreachable");

        let key = Signature::from_le_bytes(*key_bytes);

        let res = self.server_key.set(key);
        assert!(
            res.is_ok(),
            "tried to verify multiple certs with QuicPairServerVerification"
        );

        // we actually don't know if we're getting mitm'ed at this point but we're gonna verify that later
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::General("tls 1.2 is not supported".into()))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.crypto.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.crypto
            .signature_verification_algorithms
            .supported_schemes()
    }
}
