//! Key custody boundary. The reducer never holds a private key; the host supplies
//! a `DigestSigner`. `SecretKeySigner` is provided for hosts and tests that do
//! hold a raw secp256k1 key in memory (compact ECDSA over a 32-byte digest,
//! RFC 6979, the same signature form `signWithPrivKeyHex` produced).
use secp256k1::{Message, PublicKey, Secp256k1, SecretKey};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SignError {
    BadDigest,
    Unavailable,
}

impl std::fmt::Display for SignError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for SignError {}

pub trait DigestSigner {
    /// `digest_hex` is 64 lowercase hex characters; returns 128 hex characters.
    fn sign_digest(&self, digest_hex: &str) -> Result<String, SignError>;
}

pub fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn hex_decode(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    text.as_bytes()
        .chunks_exact(2)
        .map(|p| {
            std::str::from_utf8(p)
                .ok()
                .and_then(|t| u8::from_str_radix(t, 16).ok())
        })
        .collect()
}

pub struct SecretKeySigner {
    key: SecretKey,
}

impl SecretKeySigner {
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, SignError> {
        SecretKey::from_slice(bytes)
            .map(|key| Self { key })
            .map_err(|_| SignError::Unavailable)
    }

    pub fn public_key_hex(&self) -> String {
        let secp = Secp256k1::signing_only();
        hex_encode(&PublicKey::from_secret_key(&secp, &self.key).serialize())
    }
}

impl DigestSigner for SecretKeySigner {
    fn sign_digest(&self, digest_hex: &str) -> Result<String, SignError> {
        let bytes = hex_decode(digest_hex).ok_or(SignError::BadDigest)?;
        let digest: [u8; 32] = bytes.try_into().map_err(|_| SignError::BadDigest)?;
        let secp = Secp256k1::signing_only();
        let sig = secp.sign_ecdsa(&Message::from_digest(digest), &self.key);
        Ok(hex_encode(&sig.serialize_compact()))
    }
}
