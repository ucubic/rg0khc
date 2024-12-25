use std::{
    env,
    io::{Write, stdout},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs},
};

use anyhow::{Context, Result};
use quicpair::ClientId;
use tokio::io::{self, AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader, stdin};

#[tokio::main]
pub async fn main() -> Result<()> {
    let mut args = env::args();
    let _ = args.next();

    match (args.next().as_deref(), args.next()) {
        (Some("client"), Some(addr)) => {
            let address = addr
                .to_socket_addrs()?
                .next()
                .with_context(|| format!("couldn't resolve {addr:?}"))?;

            run_client(address).await?;
        }
        (Some("server"), Some(addr)) => {
            let address = if let Ok(port) = addr.parse::<u16>() {
                // probably not entirely accurate but whatever
                let supports_dualstack = cfg!(unix);

                SocketAddr::new(
                    if supports_dualstack {
                        IpAddr::V6(Ipv6Addr::UNSPECIFIED)
                    } else {
                        IpAddr::V4(Ipv4Addr::UNSPECIFIED)
                    },
                    port,
                )
            } else {
                let address = addr
                    .to_socket_addrs()?
                    .next()
                    .with_context(|| format!("couldn't resolve {addr:?}"))?;

                address
            };

            run_server(address).await?;
        }
        _ => {
            eprintln!("usage:");
            eprintln!("    terminal server [port or address]");
            eprintln!("    terminal client address");
            eprintln!("examples:");
            eprintln!("    terminal server 3000");
            eprintln!("    terminal server 0.0.0.0:1234");
            eprintln!("    terminal client 192.168.1.123:1234");
            eprintln!("    terminal client [::1]:1234");
        }
    }

    Ok(())
}

async fn run_client(address: SocketAddr) -> Result<()> {
    let (client, server_key) = quicpair::Client::connect(address).await?;

    println!("The server's signature is: {}", server_key.to_passphrase());
    println!("Do NOT send the client key without first verifying the signature.");

    let mut stdin = BufReader::new(stdin()).lines();

    let verified = loop {
        print!("Is the signature correct? (y/n): ");
        stdout().flush()?;
        let line = stdin.next_line().await?.context("EOF?")?;

        match &*line.trim().to_lowercase() {
            "y" => break true,
            "n" => break false,
            _ => println!("...What?"),
        }
    };

    if !verified {
        println!(
            "Signature verification failed. This means the server is not who you think it is. However, the protocol matched, so the server is running compatible software."
        );
        println!(
            "This means you've either mistakenly connected to another server or that someone is trying to intercept your connection."
        );
        println!("Things to check:");
        println!("  - Are you connecting to the right address?");
        println!("  - Are you on a secure network?");
        println!("  - Is the server on a secure network?");
        return Ok(());
    }

    let (client_id, connection) = client.confirm_signature().await?;

    println!("Verified! Your client ID is {}.", client_id.to_word());

    let (mut tx, rx) = connection.open_bi().await?;

    tx.write_all(b"Hello from the client! A netcat-like interface has been opened.\n")
        .await?;

    netcat(tx, rx).await?;

    Ok(())
}

async fn run_server(address: SocketAddr) -> Result<()> {
    let (mut server, key) = quicpair::Server::new(address).await?;

    println!("The server's signature is: {}", key.to_passphrase());
    println!("Verify on the client that the signature is correct before continuing.");
    println!("When you've done that, enter the client ID.");

    let mut stdin = BufReader::new(stdin()).lines();

    let connection = loop {
        print!("Client ID: ");
        stdout().flush()?;
        let line = stdin.next_line().await?.context("EOF?")?;

        let id = match ClientId::from_word(&line) {
            Ok(id) => id,
            Err(err) => {
                println!("Invalid ID: {err}");
                continue;
            }
        };

        match server.pair(id).await? {
            Ok(conn) => break conn,
            Err((server2, err)) => {
                server = server2;
                println!("Invalid ID: {err}");
                continue;
            }
        }
    };

    let (mut tx, rx) = connection.accept_bi().await?;

    tx.write_all(b"Hello from the server! A netcat-like interface has been opened.\n")
        .await?;

    netcat(tx, rx).await?;

    Ok(())
}

async fn netcat(mut tx: quinn::SendStream, mut rx: quinn::RecvStream) -> Result<()> {
    let mut stdin = io::stdin();
    let mut stdout = io::stdout();

    let stdin_buf: &mut [u8] = &mut [0u8; 1024];
    let rx_buf: &mut [u8] = &mut [0u8; 1024];

    loop {
        tokio::select! {
            bytes = stdin.read(stdin_buf) => {
                tx.write_all(&stdin_buf[0..bytes?]).await?;
            }
            bytes = rx.read(rx_buf) => {
                match bytes? {
                    Some(bytes) => {
                        stdout.write_all(&rx_buf[0..bytes]).await?;
                    }
                    None => break,
                }
            }
        };
    }

    Ok(())
}
