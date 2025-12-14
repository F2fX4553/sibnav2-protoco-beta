use super::*;
use std::collections::HashMap;
use serde::{Serialize, Deserialize};
use zeroize::{Zeroize, ZeroizeOnDrop};
use rand_core::OsRng;
use parking_lot::RwLock;

/// Identity Key Pair
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct IdentityKeyPair {
    #[serde(with = "serde_bytes")]
    pub private: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub public: Vec<u8>,
}

impl IdentityKeyPair {
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(&mut OsRng);
        let public = PublicKey::from(&secret);
        
        Self {
            private: secret.to_bytes().to_vec(),
            public: public.as_bytes().to_vec(),
        }
    }
}

mod serde_bytes {
    use serde::{Serializer, Deserializer};
    pub fn serialize<S>(bytes: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
    where S: Serializer {
        serializer.serialize_bytes(bytes)
    }
    
    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where D: Deserializer<'de> {
        let bytes: Vec<u8> = serde::Deserialize::deserialize(deserializer)?;
        Ok(bytes)
    }
}

/// Secure Key Store
#[derive(Default)]
pub struct KeyStore {
    identity_key: RwLock<Option<IdentityKeyPair>>, 
    // In a real app we'd store pre-keys, signed pre-keys, etc.
}

impl KeyStore {
    pub fn new() -> ProtocolResult<Self> {
        // Auto-generate identity key on new store for simplicity in this blueprint
        let identity = IdentityKeyPair::generate();
        Ok(Self {
            identity_key: RwLock::new(Some(identity)),
        })
    }
    
    pub fn get_identity_keypair(&self) -> ProtocolResult<IdentityKeyPair> {
        let guard = self.identity_key.read();
        if let Some(key) = &*guard {
            // Manual clone because ZeroizeOnDrop prevents auto-derive clone sometimes or we want explicit copy
             Ok(IdentityKeyPair {
                 private: key.private.clone(),
                 public: key.public.clone(),
             })
        } else {
            Err(ProtocolError::InvalidState)
        }
    }
}
