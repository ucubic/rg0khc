//! # quicpair
//!
//! Decentralized pairing of devices over an insecure channel with QUIC. Probably secure.
//!

use std::sync::LazyLock;


/// The parameter to a `from_*` function was not a valid value of the type.
#[derive(Debug)]
pub struct Invalid;
impl std::fmt::Display for Invalid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("invalid value")
    }
}
impl std::error::Error for Invalid {}

#[derive(Debug, Hash, PartialEq, Eq, Clone, Copy)]
/// An 80-bit cryptographically secure signature.
pub struct Signature(u128);
impl Signature {
    pub fn from_u128(u128: u128) -> Result<Self, Invalid> {
        if u128 & !((1u128 << 80) - 1) != 0 {
            Err(Invalid)
        } else {
            Ok(Self(u128))
        }
    }
    // pub fn from_u128_lossy(u128: u128) -> Self {
    //     Self(u128 & ((1u128 << 80) - 1))
    // }
    pub fn from_le_bytes(bytes: [u8; 10]) -> Self {
        let mut new_bytes = [0u8; 16];
        new_bytes[0..10].copy_from_slice(&bytes);
        Self(u128::from_le_bytes(new_bytes))
    }

    pub fn to_u128(self) -> u128 {
        self.0
    }
}

#[derive(Debug, Hash, PartialEq, Eq, Clone, Copy)]
/// A non-cryptographic client ID. This is used for the server to identify the client _after_ the client has successfully connected.
///
// by the birthday paradox this should take O(65535) ids to collide but cm'on 65k clients is a bit much
pub struct ClientId(u16);
impl ClientId {
    const MAX_CLIENT_ID: u16 = 10321;

    pub fn from_u16(u16: u16) -> Result<Self, Invalid> {
        if u16 >= Self::MAX_CLIENT_ID {
            Err(Invalid)
        } else {
            Ok(Self(u16))
        }
    }
    pub fn to_u16(self) -> u16 {
        self.0
    }

    pub(crate) fn generate() -> Self {
        use std::{
            hash::{BuildHasher, Hasher, RandomState},
            sync::atomic::{AtomicU16, Ordering},
        };
        static COUNTER: AtomicU16 = AtomicU16::new(0);
        static OFFSET: LazyLock<u16> = LazyLock::new(|| {
            // cursed way of generating a random number
            RandomState::new().build_hasher().finish() as u16
        });

        let val = COUNTER.fetch_add(1, Ordering::Relaxed);

        Self((((val as u32) * 809 + *OFFSET as u32) % 10321) as u16)
    }
}

#[cfg(feature = "passphrase")]
mod passphrase;

mod client;
pub use client::Client;
mod server;
pub use server::Server;

const QUICPAIR_SUBJECT_NAME: &str = "quicpair.invalid";

use x509_parser::{der_parser::oid, x509::AlgorithmIdentifier};

const CERT_ALGO: AlgorithmIdentifier = AlgorithmIdentifier::new(oid!(1.2.840.10045.4.3.2), None);
