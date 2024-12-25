use std::{collections::HashMap, hash::DefaultHasher, net::SocketAddr, sync::Arc};

use anyhow::{Context, Error, Result};
use quinn::{
    Connection, Endpoint, ServerConfig,
    rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer},
};
use tokio::{sync::mpsc, task::JoinHandle};
use x509_parser::{
    der_parser::oid,
    x509::{self, AlgorithmIdentifier},
};

use crate::{ClientId, Signature};

// pub fn server(addr: SocketAddr) -> anyhow::Result<(Key, impl Future<Output = Result<Connection>>)> {
//     let cert = rcgen::generate_simple_self_signed([super::QUICPAIR_SUBJECT_NAME.into()])?;

//     let (_, x509cert) = x509_parser::parse_x509_certificate(cert.cert.der())?;

//     let bytes = x509cert
//         .signature_value
//         .data
//         .get(0..10)
//         .context("identifier doesn't have enough entropy for a secure connection")?;
//     let bytes: &[u8; 10] = bytes.try_into().expect("unreachable");
//     let key = Key::from_le_bytes(*bytes);

//     let cert_der = CertificateDer::from(cert.cert);
//     let priv_key = PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());

//     let mut server_config = ServerConfig::with_single_cert(vec![cert_der], priv_key.into())?;
//     let transport_config = Arc::get_mut(&mut server_config.transport).expect("unreachable");
//     transport_config.max_concurrent_bidi_streams(1u8.into());
//     transport_config.max_concurrent_uni_streams(1u8.into());

//     let endpoint = Endpoint::server(server_config, addr)?;

//     let mut connections: HashMap<ClientId, Connection> = Default::default();

//     Ok((key, async move {
//         while let Some(incoming) = endpoint.accept().await {
//             let client_id = ClientId::generate();

//             tokio::spawn(async move {
//                 let conn = incoming.accept()?.await?;
//                 let mut tx = conn.open_uni().await?;

//                 // since we're in a spawn() this future will never be cancelled
//                 tx.write_all(&client_id.to_u16().to_le_bytes()).await?;

//                 drop(tx);

//                 Ok::<(), Error>(())
//             });
//         }

//         anyhow::bail!("endpoint closed before a connection could be made");
//     }))
// }

#[derive(Debug)]
pub struct Server {
    join_handle: JoinHandle<Result<Connection>>,
    rx: mpsc::Receiver<ClientDoesntExist>,
    tx: mpsc::Sender<BackendEvent>,
}

#[derive(Debug)]
pub struct ClientDoesntExist;
impl std::fmt::Display for ClientDoesntExist {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("client doesn't exist")
    }
}
impl std::error::Error for ClientDoesntExist {}

impl Server {
    pub async fn new(addr: SocketAddr) -> Result<(Self, Signature)> {
        let cert = rcgen::generate_simple_self_signed([super::QUICPAIR_SUBJECT_NAME.into()])?;

        let (_, x509cert) = x509_parser::parse_x509_certificate(cert.cert.der())?;

        let bytes = x509cert
            .signature_value
            .data
            .get(0..10)
            .context("identifier doesn't have enough entropy for a secure connection")?;
        let bytes: &[u8; 10] = bytes.try_into().expect("unreachable");
        let key = Signature::from_le_bytes(*bytes);

        let cert_der = CertificateDer::from(cert.cert);
        let priv_key = PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());

        let mut server_config = ServerConfig::with_single_cert(vec![cert_der], priv_key.into())?;
        let transport_config = Arc::get_mut(&mut server_config.transport).expect("unreachable");
        transport_config.max_concurrent_bidi_streams(1u8.into());
        transport_config.max_concurrent_uni_streams(0u8.into());

        let endpoint = Endpoint::server(server_config, addr)?;

        let (main_tx, spawn_rx) = mpsc::channel(4);
        let (spawn_tx, main_rx) = mpsc::channel(4);

        let this = Self {
            join_handle: tokio::spawn(run_server(endpoint, spawn_tx, spawn_rx, main_tx.clone())),
            tx: main_tx,
            rx: main_rx,
        };

        Ok((this, key))
    }

    pub async fn pair(
        mut self,
        id: ClientId,
    ) -> Result<Result<Connection, (Self, ClientDoesntExist)>> {
        // if there's an error sending, that's not our problem. it'll get caught in the match anyways
        let _ = self.tx.send(BackendEvent::TryClientId(id)).await;

        Ok(match self.rx.recv().await {
            Some(ClientDoesntExist) => Err((self, ClientDoesntExist)),
            None => {
                // the task disconnected; it either completed successfully or died
                let conn = self.join_handle.await??;

                // we have a connection! send a victory message so the client knows the pairing has succeeded
                let mut tx = conn.open_uni().await?;
                tx.write_all(&[1u8]).await?;
                drop(tx);

                Ok(conn)
            }
        })
    }
}

enum BackendEvent {
    TryClientId(ClientId),

    Open(ClientId, Connection),
    Closed(ClientId),
}

async fn run_server(
    endpoint: Endpoint,
    tx: mpsc::Sender<ClientDoesntExist>,
    mut rx: mpsc::Receiver<BackendEvent>,
    backend_tx: mpsc::Sender<BackendEvent>,
) -> Result<Connection> {
    let mut connections: HashMap<ClientId, Connection> = Default::default();

    loop {
        tokio::select! {
            incoming = endpoint.accept() => {
                let incoming = incoming.context("endpoint closed")?;

                let client_id = ClientId::generate();

                let backend_tx = backend_tx.clone();

                tokio::spawn(async move {
                    let conn = incoming.accept()?.await?;
                    let mut tx = conn.open_uni().await?;

                    // since we're in a spawn() this future will never be cancelled
                    tx.write_all(&client_id.to_u16().to_le_bytes()).await?;

                    drop(tx);

                    backend_tx.send(BackendEvent::Open(client_id, conn.clone())).await?;

                    conn.closed().await;

                    drop(conn);
                    backend_tx.send(BackendEvent::Closed(client_id)).await?;

                    Ok::<(), Error>(())
                });
            }
            ev = rx.recv() => match ev.context("channel closed")? {
                BackendEvent::TryClientId(client_id) => {
                    match connections.remove(&client_id) {
                        Some(conn) => {
                            // we did it! :D
                            return Ok(conn);
                        }
                        None => {
                            // we didn't do it :(
                            tx.send(ClientDoesntExist).await?;
                        }
                    }
                }
                BackendEvent::Open(client_id, connection) => {
                    connections.insert(client_id, connection);
                }
                BackendEvent::Closed(client_id) => {
                    connections.remove(&client_id);
                }
            }
        }
    }
}
