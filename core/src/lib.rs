//! Secure Protocol Core - Secure Communication Protocol Kernel
//! Modular and secure implementation of Noise and Double Ratchet protocols.

#![warn(missing_docs)]
#![allow(unsafe_code)] // FFI requires unsafe
#![allow(clippy::needless_return)]
#![allow(clippy::redundant_clone)]

// System Modules
pub mod crypto;
pub mod ratchet;
pub mod handshake;
pub mod keystore;
pub mod error;

// FFI Modules
#[cfg(feature = "ffi")]
pub mod ffi;

// Re-exports
pub use crypto::*;
pub use ratchet::*;
pub use handshake::*;
pub use keystore::*;
pub use error::{ProtocolError, ProtocolResult};

use std::sync::Arc;
use parking_lot::RwLock;

/// Main System Context
pub struct SecureContext {
    keystore: Arc<RwLock<KeyStore>>,
    sessions: Arc<RwLock<SessionManager>>,
    config: Config,
    random: Arc<RwLock<SecureRandom>>,
}

/// System Configuration
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Config {
    /// Enable Forward Secrecy
    pub enable_forward_secrecy: bool,
    /// Enable Post-Compromise Security
    pub enable_post_compromise_security: bool,
    /// Max skipped messages
    pub max_skipped_messages: usize,
    /// Key rotation interval (seconds)
    pub key_rotation_interval: u64,
    /// Handshake timeout (seconds)
    pub handshake_timeout: u64,
    /// Message buffer size
    pub message_buffer_size: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            enable_forward_secrecy: true,
            enable_post_compromise_security: true,
            max_skipped_messages: 2000,
            key_rotation_interval: 86400, // 24 hours
            handshake_timeout: 30,
            message_buffer_size: 1024,
        }
    }
}

impl SecureContext {
    /// Create a new context
    pub fn new(config: Config) -> ProtocolResult<Self> {
        let keystore = KeyStore::new()?;
        let sessions = SessionManager::new();
        let random = SecureRandom::new()?;
        
        Ok(Self {
            keystore: Arc::new(RwLock::new(keystore)),
            sessions: Arc::new(RwLock::new(sessions)),
            config,
            random: Arc::new(RwLock::new(random)),
        })
    }
    
    /// Create a new session
    pub fn create_session(&self, peer_id: &[u8]) -> ProtocolResult<SessionHandle> {
        let mut sessions = self.sessions.write();
        sessions.create_session(peer_id, self.config.clone())
    }
    
    /// Perform handshake with peer
    pub fn perform_handshake(
        &self,
        session_id: &[u8],
        initiator: bool,
        peer_public_key: Option<&[u8]>,
        prologue: Option<&[u8]>,
    ) -> ProtocolResult<Vec<u8>> {
        let sessions = self.sessions.read();
        let session = sessions.get_session(session_id)?;
        
        let keystore = self.keystore.read();
        let random = self.random.read();
        
        let handshake = HandshakeBuilder::new()
            .with_config(self.config.clone())
            .with_keystore(&*keystore)
            .with_random(&*random)
            .with_initiator(initiator);
        
        // Convert Option<&[u8]> to Option key
        let handshake = if let Some(peer_key) = peer_public_key {
            handshake.with_peer_public_key(peer_key)?
        } else {
            handshake
        };
        
        let handshake = if let Some(prologue_data) = prologue {
            handshake.with_prologue(prologue_data)
        } else {
            handshake
        };
        
        let handshake = handshake.build()?;
        
        // In a real implementation, you would update the session with the handshake result
        // Here we just return the handshake message
        handshake.perform()
    }
    
    /// Encrypt a message
    pub fn encrypt_message(
        &self,
        session_id: &[u8],
        plaintext: &[u8],
        associated_data: Option<&[u8]>,
    ) -> ProtocolResult<Vec<u8>> {
        let sessions = self.sessions.read();
        let session = sessions.get_session(session_id)?;
        
        let mut session = session.write();
        let ad = associated_data.unwrap_or_default();
        
        session.encrypt(plaintext, ad)
    }
    
    /// Decrypt a message
    pub fn decrypt_message(
        &self,
        session_id: &[u8],
        ciphertext: &[u8],
        associated_data: Option<&[u8]>,
    ) -> ProtocolResult<Vec<u8>> {
        let sessions = self.sessions.read();
        let session = sessions.get_session(session_id)?;
        
        let mut session = session.write();
        let ad = associated_data.unwrap_or_default();
        
        session.decrypt(ciphertext, ad)
    }
    
    /// Deserialize session state
    pub fn deserialize_session_state(
        &self,
        session_id: &[u8],
        state: &[u8],
    ) -> ProtocolResult<()> {
        let sessions = self.sessions.read();
        let session = sessions.get_session(session_id)?;
        
        let mut session = session.write();
        session.deserialize_state(state) // Ensure this method exists in DoubleRatchetSession
    }
}

/// Session Manager
pub struct SessionManager {
    sessions: std::collections::HashMap<Vec<u8>, Arc<RwLock<DoubleRatchetSession>>>,
}

impl SessionManager {
    /// Create new session manager
    pub fn new() -> Self {
        Self {
            sessions: std::collections::HashMap::new(),
        }
    }
    
    /// Create a new session
    pub fn create_session(
        &mut self,
        peer_id: &[u8],
        config: Config,
    ) -> ProtocolResult<SessionHandle> {
        let session = DoubleRatchetSession::new(config)?;
        let session = Arc::new(RwLock::new(session));
        
        self.sessions.insert(peer_id.to_vec(), session.clone());
        
        Ok(SessionHandle {
            peer_id: peer_id.to_vec(),
            session,
        })
    }
    
    /// Get existing session
    pub fn get_session(
        &self,
        session_id: &[u8],
    ) -> ProtocolResult<Arc<RwLock<DoubleRatchetSession>>> {
        self.sessions
            .get(session_id)
            .cloned()
            .ok_or(ProtocolError::SessionNotFound)
    }
    
    /// Remove session
    pub fn remove_session(&mut self, session_id: &[u8]) -> bool {
        self.sessions.remove(session_id).is_some()
    }
}

/// Session Handle
#[derive(Clone)]
pub struct SessionHandle {
    peer_id: Vec<u8>,
    session: Arc<RwLock<DoubleRatchetSession>>,
}

impl SessionHandle {
    /// Get peer ID
    pub fn peer_id(&self) -> &[u8] {
        &self.peer_id
    }
    
    /// Get session
    pub fn session(&self) -> Arc<RwLock<DoubleRatchetSession>> {
        self.session.clone()
    }
}
