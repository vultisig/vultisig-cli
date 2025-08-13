use anyhow::{anyhow, Result};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};

use tracing::{info, error};

use crate::session::{SessionManager, SigningResult, SessionStatus};
use crate::tss::{TssMessage, create_tss_engine};
use crate::keyshare::{VultKeyshare, EcdsaKeyshareData, EddsaKeyshareData};

#[cfg(test)]
use futures_util;

/// MPC Coordinator that handles the actual threshold signing protocols
/// This bridges the gap between the session management and the MPC libraries
#[derive(Debug)]
pub struct MpcCoordinator {
    session_manager: Arc<SessionManager>,
    keyshare: Option<VultKeyshare>,
    // Active signing sessions with their message channels
    active_signings: Arc<RwLock<HashMap<String, MpcSigningSession>>>,
}

#[derive(Debug)]
struct MpcSigningSession {
    session_id: String,
    network: String,
    message_type: String,
    message_hash: Vec<u8>,
    // Channels for coordinating with mobile app
    mobile_tx: mpsc::UnboundedSender<TssMessage>,
    // State of the MPC protocol
    state: MpcSigningState,
}

#[derive(Debug, Clone)]
enum MpcSigningState {
    WaitingForMobile,
    Round1InProgress,
    Round2InProgress, 
    Round3InProgress,
    Completed,
    Failed(String),
}

impl MpcCoordinator {
    pub fn new(session_manager: Arc<SessionManager>) -> Self {
        Self {
            session_manager,
            keyshare: None,
            active_signings: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Set the keyshare for this coordinator
    pub fn set_keyshare(&mut self, keyshare: VultKeyshare) {
        self.keyshare = Some(keyshare);
    }

    /// Get the keyshare from this coordinator
    pub async fn get_keyshare(&self) -> Result<VultKeyshare> {
        self.keyshare.clone()
            .ok_or_else(|| anyhow!("No keyshare loaded in MPC coordinator"))
    }

    /// Get the session manager
    pub fn get_session_manager(&self) -> Arc<SessionManager> {
        self.session_manager.clone()
    }

    /// Get addresses for all supported networks from the keyshare
    pub async fn get_keyshare_addresses(&self) -> Result<HashMap<String, String>> {
        match &self.keyshare {
            Some(keyshare) => {
                let mut addresses = HashMap::new();
                
                // Only properly implemented networks (verified against keyshare test data)
                let supported_networks = [
                    // Bitcoin-like chains (using real Trust Wallet Core UTXO derivation)
                    "BTC", "LTC", "DOGE",
                    // Ethereum and EVM chains (using real Trust Wallet Core EVM derivation)
                    "ETH", "BSC", "MATIC", "AVAX", "Optimism", "Arbitrum", "Base",
                    // Cosmos ecosystem (using real Trust Wallet Core Cosmos derivation)
                    "THOR",
                    // Other chains (using real derivation)
                    "SOL"
                    // Note: ATOM, ADA, DOT, XRP, TRX, SUI, TON are excluded as they use
                    // generic placeholder addresses that don't match expected values
                ];
                
                for network in &supported_networks {
                    if let Ok(addr) = keyshare.derive_address(network) {
                        addresses.insert(network.to_string(), addr);
                    }
                }
                
                Ok(addresses)
            },
            None => Err(anyhow::anyhow!("No keyshare loaded")),
        }
    }

    /// Get addresses and public keys for all supported networks from the keyshare
    pub async fn get_keyshare_addresses_with_pubkeys(&self) -> Result<HashMap<String, (String, String)>> {
        match &self.keyshare {
            Some(keyshare) => {
                let mut result = HashMap::new();
                
                // Only properly implemented networks (verified against keyshare test data)
                let supported_networks = [
                    // Bitcoin-like chains (using real Trust Wallet Core UTXO derivation)
                    "BTC", "LTC", "DOGE",
                    // Ethereum and EVM chains (using real Trust Wallet Core EVM derivation)
                    "ETH", "BSC", "MATIC", "AVAX", "Optimism", "Arbitrum", "Base",
                    // Cosmos ecosystem (using real Trust Wallet Core Cosmos derivation)
                    "THOR",
                    // Other chains (using real derivation)
                    "SOL"
                    // Note: ATOM, ADA, DOT, XRP, TRX, SUI, TON are excluded as they use
                    // generic placeholder addresses that don't match expected values
                ];
                
                for network in &supported_networks {
                    if let Ok(addr) = keyshare.derive_address(network) {
                        // Get the appropriate public key based on network type
                        let pubkey = match *network {
                            // EdDSA networks (ed25519)
                            "SOL" => {
                                // For Solana, use EdDSA public key
                                keyshare.public_key_eddsa().to_string()
                            },
                            // ECDSA networks (secp256k1) - all others
                            _ => {
                                // For all other networks, use ECDSA public key
                                keyshare.public_key_ecdsa().to_string()
                            }
                        };
                        
                        result.insert(network.to_string(), (pubkey, addr));
                    }
                }
                
                Ok(result)
            },
            None => Err(anyhow::anyhow!("No keyshare loaded")),
        }
    }

    /// Get address for a specific network from the keyshare
    pub async fn get_keyshare_address(&self, network: &str) -> Result<String> {
        match &self.keyshare {
            Some(keyshare) => {
                keyshare.derive_address(network)
                    .map_err(|e| anyhow::anyhow!("Failed to derive address for {}: {}", network, e))
            },
            None => Err(anyhow::anyhow!("No keyshare loaded")),
        }
    }

    /// Start an MPC signing session for ECDSA (ETH, BTC, THOR)
    pub async fn start_ecdsa_signing(
        &self,
        session_id: String,
        network: String,
        message_type: String,
        message_hash: Vec<u8>,
        keyshare_data: EcdsaKeyshareData,
        use_relay: bool,
        _relay_client: Option<Arc<crate::relay_client::RelayClient>>,
    ) -> Result<()> {
        info!("🚀 MPC COORDINATOR: Starting ECDSA signing session");
        info!("📊 Session Details: id={}, network={}, type={}, relay={}", 
              session_id, network, message_type, use_relay);
        info!("🔑 Message Hash: {}", hex::encode(&message_hash));

        // Create message channels for mobile coordination
        let (mobile_tx, mobile_rx) = mpsc::unbounded_channel();

        let signing_session = MpcSigningSession {
            session_id: session_id.clone(),
            network: network.clone(),
            message_type,
            message_hash: message_hash.clone(),
            mobile_tx: mobile_tx.clone(),
            state: MpcSigningState::WaitingForMobile,
        };

        // Store the active signing session
        {
            let mut active = self.active_signings.write().await;
            active.insert(session_id.clone(), signing_session);
        }

        // Update session status
        self.session_manager
            .update_session_status(&session_id, SessionStatus::WaitingForMobile)
            .await?;

        // Start the actual TSS signing protocol using corrected API
        let tss_engine = create_tss_engine(
            &network,
            Some(keyshare_data.clone()),
            None
        )?;
        
        // Spawn the TSS signing task
        let session_manager = self.session_manager.clone();
        let session_id_clone = session_id.clone();
        
        tokio::spawn(async move {
            match tss_engine.sign_as_initiator(
                message_hash,
                mobile_tx,
                mobile_rx,
            ).await {
                Ok(signature) => {
                    info!("TSS signing completed successfully for session: {}", session_id_clone);
                    
                    // Create signing result
                    let result = SigningResult {
                        session_id: session_id_clone.clone(),
                        success: true,
                        signature: {
                            // Combine r and s into signature bytes
                            let mut sig_bytes = Vec::new();
                            sig_bytes.extend_from_slice(&signature.r);
                            sig_bytes.extend_from_slice(&signature.s);
                            sig_bytes
                        },
                        signed_tx: vec![], // Will be populated by transaction construction
                        error_message: String::new(),
                        metadata: HashMap::new(),
                    };

                    // Store result and update session
                    if let Err(e) = session_manager.store_result(session_id_clone.clone(), result).await {
                        error!("Failed to store signing result: {}", e);
                    }
                    if let Err(e) = session_manager
                        .update_session_status(&session_id_clone, SessionStatus::Completed)
                        .await {
                        error!("Failed to update session status: {}", e);
                    }
                }
                Err(e) => {
                    error!("TSS signing failed for session {}: {}", session_id_clone, e);
                    
                    let result = SigningResult {
                        session_id: session_id_clone.clone(),
                        success: false,
                        signature: vec![],
                        signed_tx: vec![],
                        error_message: e.to_string(),
                        metadata: HashMap::new(),
                    };

                    if let Err(e) = session_manager.store_result(session_id_clone.clone(), result).await {
                        error!("Failed to store error result: {}", e);
                    }
                    if let Err(e) = session_manager
                        .update_session_status(&session_id_clone, SessionStatus::Failed(e.to_string()))
                        .await {
                        error!("Failed to update session status: {}", e);
                    }
                }
            }
        });

        Ok(())
    }

    /// Start an MPC signing session for EdDSA (SOL)
    pub async fn start_eddsa_signing(
        &self,
        session_id: String,
        network: String,
        message_type: String,
        message_hash: Vec<u8>,
        keyshare_data: EddsaKeyshareData,
        use_relay: bool,
        _relay_client: Option<Arc<crate::relay_client::RelayClient>>,
    ) -> Result<()> {
        info!("Starting EdDSA MPC signing for session: {} (relay: {})", session_id, use_relay);
        
        // Create message channels for mobile coordination
        let (mobile_tx, mobile_rx) = mpsc::unbounded_channel();

        let signing_session = MpcSigningSession {
            session_id: session_id.clone(),
            network: network.clone(),
            message_type,
            message_hash: message_hash.clone(),
            mobile_tx: mobile_tx.clone(),
            state: MpcSigningState::WaitingForMobile,
        };

        // Store the active signing session
        {
            let mut active = self.active_signings.write().await;
            active.insert(session_id.clone(), signing_session);
        }

        // Update session status
        self.session_manager
            .update_session_status(&session_id, SessionStatus::WaitingForMobile)
            .await?;

        // Start the actual TSS signing protocol using corrected API
        let tss_engine = create_tss_engine(
            &network,
            None,
            Some(keyshare_data.clone())
        )?;
        
        // Spawn the TSS signing task
        let session_manager = self.session_manager.clone();
        let session_id_clone = session_id.clone();
        
        tokio::spawn(async move {
            match tss_engine.sign_as_initiator(
                message_hash,
                mobile_tx,
                mobile_rx,
            ).await {
                Ok(signature) => {
                    info!("EdDSA TSS signing completed successfully for session: {}", session_id_clone);
                    
                    // Create signing result
                    let result = SigningResult {
                        session_id: session_id_clone.clone(),
                        success: true,
                        signature: signature.r.clone(), // EdDSA signature is in r field
                        signed_tx: vec![], // Will be populated by transaction construction
                        error_message: String::new(),
                        metadata: HashMap::new(),
                    };

                    // Store result and update session
                    if let Err(e) = session_manager.store_result(session_id_clone.clone(), result).await {
                        error!("Failed to store EdDSA signing result: {}", e);
                    }
                    if let Err(e) = session_manager
                        .update_session_status(&session_id_clone, SessionStatus::Completed)
                        .await {
                        error!("Failed to update EdDSA session status: {}", e);
                    }
                }
                Err(e) => {
                    error!("EdDSA TSS signing failed for session {}: {}", session_id_clone, e);
                    
                    let result = SigningResult {
                        session_id: session_id_clone.clone(),
                        success: false,
                        signature: vec![],
                        signed_tx: vec![],
                        error_message: e.to_string(),
                        metadata: HashMap::new(),
                    };

                    if let Err(e) = session_manager.store_result(session_id_clone.clone(), result).await {
                        error!("Failed to store EdDSA error result: {}", e);
                    }
                    if let Err(e) = session_manager
                        .update_session_status(&session_id_clone, SessionStatus::Failed(e.to_string()))
                        .await {
                        error!("Failed to update EdDSA session status: {}", e);
                    }
                }
            }
        });

        Ok(())
    }

    /// Handle incoming TSS message from mobile app
    pub async fn handle_mobile_message(
        &self,
        session_id: &str,
        message: TssMessage,
    ) -> Result<()> {
        let mut active = self.active_signings.write().await;
        
        if let Some(signing_session) = active.get_mut(session_id) {
            // Forward the message to the TSS protocol handler
            if let Err(e) = signing_session.mobile_tx.send(message.clone()) {
                error!("Failed to forward message to TSS handler: {}", e);
                return Err(anyhow!("Failed to forward message to TSS handler: {}", e));
            }

            // Update state based on message type
            match message {
                TssMessage::SetupResponse { .. } => {
                    signing_session.state = MpcSigningState::Round1InProgress;
                }
                TssMessage::EcdsaRound1 { .. } | TssMessage::EddsaRound1 { .. } => {
                    signing_session.state = MpcSigningState::Round2InProgress;
                }
                TssMessage::EcdsaRound2 { .. } | TssMessage::EddsaRound2 { .. } => {
                    signing_session.state = MpcSigningState::Round3InProgress;
                }
                TssMessage::SigningComplete { signature, recovery_id: _ } => {
                    info!("Received signature from mobile for session: {}", session_id);
                    
                    // Create signing result
                    let result = SigningResult {
                        session_id: session_id.to_string(),
                        success: true,
                        signature,
                        signed_tx: vec![], // Will be populated by transaction construction
                        error_message: String::new(),
                        metadata: HashMap::new(),
                    };

                    // Store result and update session
                    self.session_manager.store_result(session_id.to_string(), result).await?;
                    self.session_manager
                        .update_session_status(session_id, SessionStatus::Completed)
                        .await?;

                    signing_session.state = MpcSigningState::Completed;
                }
                TssMessage::SigningError { error } => {
                    error!("Signing error from mobile for session {}: {}", session_id, error);
                    
                    let result = SigningResult {
                        session_id: session_id.to_string(),
                        success: false,
                        signature: vec![],
                        signed_tx: vec![],
                        error_message: error.clone(),
                        metadata: HashMap::new(),
                    };

                    self.session_manager.store_result(session_id.to_string(), result).await?;
                    self.session_manager
                        .update_session_status(session_id, SessionStatus::Failed(error.clone()))
                        .await?;

                    signing_session.state = MpcSigningState::Failed(error);
                }
                _ => {
                    // Handle protocol-specific messages - they're forwarded to TSS handler
                    info!("Forwarded TSS message to protocol handler for session: {}", session_id);
                }
            }
        } else {
            return Err(anyhow!("No active signing session found: {}", session_id));
        }

        Ok(())
    }

    /// Start local P2P signing (WiFi discovery)
    async fn start_local_signing(&self, session_id: &str) -> Result<()> {
        info!("Starting local P2P signing for session: {}", session_id);
        
        // Update state to indicate we're ready for mobile connection
        {
            let mut active = self.active_signings.write().await;
            if let Some(session) = active.get_mut(session_id) {
                session.state = MpcSigningState::Round1InProgress;
            }
        }
        
        // The actual TSS protocol will be handled when the mobile app connects
        // via WebSocket and starts sending MPC messages
        info!("Local signing session {} ready for mobile app connection", session_id);
        Ok(())
    }

    /// Start relay-based signing (via Vultisig relay server)
    async fn start_relay_signing(
        &self, 
        session_id: &str, 
        relay_client: Option<Arc<crate::relay_client::RelayClient>>
    ) -> Result<()> {
        info!("Starting relay-based signing for session: {}", session_id);
        
        let relay_client = relay_client
            .ok_or_else(|| anyhow!("Relay client not available for relay signing"))?;
        
        // Update state
        {
            let mut active = self.active_signings.write().await;
            if let Some(session) = active.get_mut(session_id) {
                session.state = MpcSigningState::Round1InProgress;
            }
        }
        
        // Register session with relay server
        // TODO: Get actual public key from loaded keyshare
        let temp_pubkey = format!("daemon-{}", session_id);
        relay_client.register_session(session_id, &temp_pubkey).await
            .map_err(|e| anyhow!("Failed to register session with relay: {}", e))?;
        
        info!("Relay signing session {} registered with server", session_id);
        Ok(())
    }

    /// Get signing session state
    pub async fn get_session_state(&self, session_id: &str) -> Option<MpcSigningState> {
        let active = self.active_signings.read().await;
        active.get(session_id).map(|s| s.state.clone())
    }

    /// Clean up completed signing sessions
    pub async fn cleanup_completed_sessions(&self) {
        let mut active = self.active_signings.write().await;
        active.retain(|_session_id, session| {
            !matches!(session.state, MpcSigningState::Completed | MpcSigningState::Failed(_))
        });
    }
}

/// Factory function to create MPC coordinator
pub fn create_mpc_coordinator(session_manager: Arc<SessionManager>) -> Arc<MpcCoordinator> {
    Arc::new(MpcCoordinator::new(session_manager))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::{SessionManager, SessionStatus};
    use crate::tss::{TssMessage, Signature};
    use std::sync::Arc;
    use tokio::time::{sleep, Duration};
    use tokio_test;
    use pretty_assertions::assert_eq;
    use assert_matches::assert_matches;
    use mockall::mock;

    // Mock implementations for testing
    mock! {
        RelayClient {
            pub async fn register_session(&self, session_id: &str, public_key: &str) -> Result<()>;
        }
    }

    fn create_test_ecdsa_keyshare() -> EcdsaKeyshareData {
        EcdsaKeyshareData {
            public_key: vec![0x02; 33], // Mock compressed secp256k1 key
            chain_code: vec![0x01; 32],
            share_data: vec![0x03; 32],
        }
    }

    fn create_test_eddsa_keyshare() -> EddsaKeyshareData {
        EddsaKeyshareData {
            public_key: vec![0x04; 32], // Mock ed25519 key
            chain_code: vec![0x05; 32],
            share_data: vec![0x06; 32],
        }
    }

    fn create_test_coordinator() -> Arc<MpcCoordinator> {
        let session_manager = Arc::new(SessionManager::new());
        create_mpc_coordinator(session_manager)
    }

    #[tokio::test]
    async fn test_mpc_coordinator_creation() {
        let session_manager = Arc::new(SessionManager::new());
        let coordinator = MpcCoordinator::new(session_manager.clone());
        
        // Verify initial state
        assert_eq!(coordinator.active_signings.read().await.len(), 0);
        assert!(Arc::ptr_eq(&coordinator.session_manager, &session_manager));
    }

    #[tokio::test]
    async fn test_factory_function() {
        let session_manager = Arc::new(SessionManager::new());
        let coordinator = create_mpc_coordinator(session_manager);
        
        assert_eq!(coordinator.active_signings.read().await.len(), 0);
    }

    #[tokio::test]
    async fn test_start_ecdsa_signing() {
        let coordinator = create_test_coordinator();
        let keyshare_data = create_test_ecdsa_keyshare();
        let message_hash = vec![0x07; 32];
        
        let result = coordinator.start_ecdsa_signing(
            "test-session".to_string(),
            "ethereum".to_string(),
            "send_transaction".to_string(),
            message_hash.clone(),
            keyshare_data,
            false, // use_relay
            None,  // relay_client
        ).await;
        
        assert!(result.is_ok());
        
        // Verify session was created
        let active_signings = coordinator.active_signings.read().await;
        assert_eq!(active_signings.len(), 1);
        
        let signing_session = active_signings.get("test-session").unwrap();
        assert_eq!(signing_session.session_id, "test-session");
        assert_eq!(signing_session.network, "ethereum");
        assert_eq!(signing_session.message_type, "send_transaction");
        assert_eq!(signing_session.message_hash, message_hash);
        assert_matches!(signing_session.state, MpcSigningState::WaitingForMobile);
    }

    #[tokio::test]
    async fn test_start_eddsa_signing() {
        let coordinator = create_test_coordinator();
        let keyshare_data = create_test_eddsa_keyshare();
        let message_hash = vec![0x08; 32];
        
        let result = coordinator.start_eddsa_signing(
            "test-eddsa-session".to_string(),
            "solana".to_string(),
            "send_transaction".to_string(),
            message_hash.clone(),
            keyshare_data,
            false, // use_relay
            None,  // relay_client
        ).await;
        
        assert!(result.is_ok());
        
        // Verify session was created
        let active_signings = coordinator.active_signings.read().await;
        assert_eq!(active_signings.len(), 1);
        
        let signing_session = active_signings.get("test-eddsa-session").unwrap();
        assert_eq!(signing_session.session_id, "test-eddsa-session");
        assert_eq!(signing_session.network, "solana");
        assert_eq!(signing_session.message_type, "send_transaction");
        assert_eq!(signing_session.message_hash, message_hash);
        assert_matches!(signing_session.state, MpcSigningState::WaitingForMobile);
    }

    #[tokio::test]
    async fn test_get_session_state() {
        let coordinator = create_test_coordinator();
        let keyshare_data = create_test_ecdsa_keyshare();
        
        // Start a signing session
        coordinator.start_ecdsa_signing(
            "state-test-session".to_string(),
            "bitcoin".to_string(),
            "send_transaction".to_string(),
            vec![0x09; 32],
            keyshare_data,
            false,
            None,
        ).await.unwrap();
        
        // Test getting session state
        let state = coordinator.get_session_state("state-test-session").await;
        assert!(state.is_some());
        assert_matches!(state.unwrap(), MpcSigningState::WaitingForMobile);
        
        // Test nonexistent session
        let nonexistent_state = coordinator.get_session_state("nonexistent").await;
        assert!(nonexistent_state.is_none());
    }

    #[tokio::test]
    async fn test_handle_mobile_setup_response() {
        let coordinator = create_test_coordinator();
        let keyshare_data = create_test_ecdsa_keyshare();
        
        // Start signing session
        coordinator.start_ecdsa_signing(
            "setup-test".to_string(),
            "ethereum".to_string(),
            "send_transaction".to_string(),
            vec![0x0A; 32],
            keyshare_data,
            false,
            None,
        ).await.unwrap();
        
        // Send setup response message
        let setup_message = TssMessage::SetupResponse {
            session_id: "setup-test".to_string(),
            public_keys: vec![vec![0x02; 33], vec![0x03; 33]],
            party_ids: vec!["mobile".to_string(), "daemon".to_string()],
        };
        
        let result = coordinator.handle_mobile_message("setup-test", setup_message).await;
        assert!(result.is_ok());
        
        // Verify state changed
        let state = coordinator.get_session_state("setup-test").await.unwrap();
        assert_matches!(state, MpcSigningState::Round1InProgress);
    }

    #[tokio::test]
    async fn test_handle_mobile_signing_complete() {
        let coordinator = create_test_coordinator();
        let keyshare_data = create_test_ecdsa_keyshare();
        
        // Start signing session
        coordinator.start_ecdsa_signing(
            "complete-test".to_string(),
            "bitcoin".to_string(),
            "send_transaction".to_string(),
            vec![0x0B; 32],
            keyshare_data,
            false,
            None,
        ).await.unwrap();
        
        // Send signing complete message
        let signature_bytes = vec![0x01, 0x02, 0x03, 0x04, 0x05];
        let complete_message = TssMessage::SigningComplete {
            signature: signature_bytes.clone(),
            recovery_id: Some(0),
        };
        
        let result = coordinator.handle_mobile_message("complete-test", complete_message).await;
        assert!(result.is_ok());
        
        // Verify state changed to completed
        let state = coordinator.get_session_state("complete-test").await.unwrap();
        assert_matches!(state, MpcSigningState::Completed);
        
        // Verify result was stored
        let signing_result = coordinator.session_manager.get_result("complete-test").await;
        assert!(signing_result.is_some());
        let result = signing_result.unwrap();
        assert!(result.success);
        assert_eq!(result.signature, signature_bytes);
    }

    #[tokio::test]
    async fn test_handle_mobile_signing_error() {
        let coordinator = create_test_coordinator();
        let keyshare_data = create_test_ecdsa_keyshare();
        
        // Start signing session
        coordinator.start_ecdsa_signing(
            "error-test".to_string(),
            "ethereum".to_string(),
            "send_transaction".to_string(),
            vec![0x0C; 32],
            keyshare_data,
            false,
            None,
        ).await.unwrap();
        
        // Send signing error message
        let error_message = TssMessage::SigningError {
            error: "Invalid signature share".to_string(),
        };
        
        let result = coordinator.handle_mobile_message("error-test", error_message).await;
        assert!(result.is_ok());
        
        // Verify state changed to failed
        let state = coordinator.get_session_state("error-test").await.unwrap();
        assert_matches!(state, MpcSigningState::Failed(ref error) if error == "Invalid signature share");
        
        // Verify error result was stored
        let signing_result = coordinator.session_manager.get_result("error-test").await;
        assert!(signing_result.is_some());
        let result = signing_result.unwrap();
        assert!(!result.success);
        assert_eq!(result.error_message, "Invalid signature share");
    }

    #[tokio::test]
    async fn test_handle_mobile_round_messages() {
        let coordinator = create_test_coordinator();
        let keyshare_data = create_test_ecdsa_keyshare();
        
        // Start signing session
        coordinator.start_ecdsa_signing(
            "rounds-test".to_string(),
            "thorchain".to_string(),
            "send_transaction".to_string(),
            vec![0x0D; 32],
            keyshare_data,
            false,
            None,
        ).await.unwrap();
        
        // Test Round 1 message
        let round1_message = TssMessage::EcdsaRound1 {
            sender: "mobile".to_string(),
            share_data: vec![0x01; 64],
        };
        
        let result = coordinator.handle_mobile_message("rounds-test", round1_message).await;
        assert!(result.is_ok());
        
        let state = coordinator.get_session_state("rounds-test").await.unwrap();
        assert_matches!(state, MpcSigningState::Round2InProgress);
        
        // Test Round 2 message
        let round2_message = TssMessage::EcdsaRound2 {
            sender: "mobile".to_string(),
            signature_share: vec![0x02; 32],
        };
        
        let result = coordinator.handle_mobile_message("rounds-test", round2_message).await;
        assert!(result.is_ok());
        
        let state = coordinator.get_session_state("rounds-test").await.unwrap();
        assert_matches!(state, MpcSigningState::Round3InProgress);
    }

    #[tokio::test]
    async fn test_handle_mobile_eddsa_round_messages() {
        let coordinator = create_test_coordinator();
        let keyshare_data = create_test_eddsa_keyshare();
        
        // Start EdDSA signing session
        coordinator.start_eddsa_signing(
            "eddsa-rounds-test".to_string(),
            "solana".to_string(),
            "send_transaction".to_string(),
            vec![0x0E; 32],
            keyshare_data,
            false,
            None,
        ).await.unwrap();
        
        // Test EdDSA Round 1 message
        let round1_message = TssMessage::EddsaRound1 {
            sender: "mobile".to_string(),
            commitment: vec![0x01; 32],
        };
        
        let result = coordinator.handle_mobile_message("eddsa-rounds-test", round1_message).await;
        assert!(result.is_ok());
        
        let state = coordinator.get_session_state("eddsa-rounds-test").await.unwrap();
        assert_matches!(state, MpcSigningState::Round2InProgress);
        
        // Test EdDSA Round 2 message
        let round2_message = TssMessage::EddsaRound2 {
            sender: "mobile".to_string(),
            signature_share: vec![0x02; 64],
        };
        
        let result = coordinator.handle_mobile_message("eddsa-rounds-test", round2_message).await;
        assert!(result.is_ok());
        
        let state = coordinator.get_session_state("eddsa-rounds-test").await.unwrap();
        assert_matches!(state, MpcSigningState::Round3InProgress);
    }

    #[tokio::test]
    async fn test_handle_message_for_nonexistent_session() {
        let coordinator = create_test_coordinator();
        
        let message = TssMessage::SetupResponse {
            session_id: "nonexistent".to_string(),
            public_keys: vec![],
            party_ids: vec![],
        };
        
        let result = coordinator.handle_mobile_message("nonexistent", message).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("No active signing session found"));
    }

    #[tokio::test]
    async fn test_cleanup_completed_sessions() {
        let coordinator = create_test_coordinator();
        let keyshare_data = create_test_ecdsa_keyshare();
        
        // Create multiple sessions
        coordinator.start_ecdsa_signing(
            "completed-session".to_string(),
            "ethereum".to_string(),
            "send_transaction".to_string(),
            vec![0x0F; 32],
            keyshare_data.clone(),
            false,
            None,
        ).await.unwrap();
        
        coordinator.start_ecdsa_signing(
            "failed-session".to_string(),
            "bitcoin".to_string(),
            "send_transaction".to_string(),
            vec![0x10; 32],
            keyshare_data.clone(),
            false,
            None,
        ).await.unwrap();
        
        coordinator.start_ecdsa_signing(
            "active-session".to_string(),
            "thorchain".to_string(),
            "send_transaction".to_string(),
            vec![0x11; 32],
            keyshare_data,
            false,
            None,
        ).await.unwrap();
        
        // Mark some sessions as completed/failed
        {
            let mut active = coordinator.active_signings.write().await;
            if let Some(session) = active.get_mut("completed-session") {
                session.state = MpcSigningState::Completed;
            }
            if let Some(session) = active.get_mut("failed-session") {
                session.state = MpcSigningState::Failed("Test error".to_string());
            }
        }
        
        // Verify all sessions exist
        assert_eq!(coordinator.active_signings.read().await.len(), 3);
        
        // Run cleanup
        coordinator.cleanup_completed_sessions().await;
        
        // Verify only active session remains
        let remaining = coordinator.active_signings.read().await;
        assert_eq!(remaining.len(), 1);
        assert!(remaining.contains_key("active-session"));
    }

    #[tokio::test]
    async fn test_concurrent_signing_sessions() {
        let coordinator = Arc::new(create_test_coordinator());
        let mut handles = Vec::new();
        
        // Start multiple signing sessions concurrently
        for i in 0..5 {
            let coordinator_clone = coordinator.clone();
            let handle = tokio::spawn(async move {
                let session_id = format!("concurrent-session-{}", i);
                let keyshare_data = create_test_ecdsa_keyshare();
                
                coordinator_clone.start_ecdsa_signing(
                    session_id.clone(),
                    "ethereum".to_string(),
                    "send_transaction".to_string(),
                    vec![i as u8; 32],
                    keyshare_data,
                    false,
                    None,
                ).await.unwrap();
                
                session_id
            });
            handles.push(handle);
        }
        
        // Wait for all sessions to be created
        let session_ids: Vec<String> = futures_util::future::join_all(handles).await
            .into_iter()
            .map(|result| result.unwrap())
            .collect();
        
        // Verify all sessions were created
        assert_eq!(coordinator.active_signings.read().await.len(), 5);
        
        // Verify each session exists and is in correct state
        for session_id in session_ids {
            let state = coordinator.get_session_state(&session_id).await;
            assert!(state.is_some());
            assert_matches!(state.unwrap(), MpcSigningState::WaitingForMobile);
        }
    }

    #[tokio::test]
    async fn test_mixed_ecdsa_eddsa_sessions() {
        let coordinator = create_test_coordinator();
        
        // Start ECDSA session
        coordinator.start_ecdsa_signing(
            "ecdsa-mixed".to_string(),
            "ethereum".to_string(),
            "send_transaction".to_string(),
            vec![0x12; 32],
            create_test_ecdsa_keyshare(),
            false,
            None,
        ).await.unwrap();
        
        // Start EdDSA session
        coordinator.start_eddsa_signing(
            "eddsa-mixed".to_string(),
            "solana".to_string(),
            "send_transaction".to_string(),
            vec![0x13; 32],
            create_test_eddsa_keyshare(),
            false,
            None,
        ).await.unwrap();
        
        // Verify both sessions exist
        assert_eq!(coordinator.active_signings.read().await.len(), 2);
        
        let ecdsa_state = coordinator.get_session_state("ecdsa-mixed").await.unwrap();
        let eddsa_state = coordinator.get_session_state("eddsa-mixed").await.unwrap();
        
        assert_matches!(ecdsa_state, MpcSigningState::WaitingForMobile);
        assert_matches!(eddsa_state, MpcSigningState::WaitingForMobile);
    }

    #[test]
    fn test_mpc_signing_state_debug_display() {
        let states = vec![
            MpcSigningState::WaitingForMobile,
            MpcSigningState::Round1InProgress,
            MpcSigningState::Round2InProgress,
            MpcSigningState::Round3InProgress,
            MpcSigningState::Completed,
            MpcSigningState::Failed("test error".to_string()),
        ];
        
        for state in states {
            let debug_str = format!("{:?}", state);
            assert!(!debug_str.is_empty());
        }
    }

    #[test]
    fn test_mpc_signing_session_debug_display() {
        let (tx, _rx) = mpsc::unbounded_channel();
        
        let session = MpcSigningSession {
            session_id: "test".to_string(),
            network: "ethereum".to_string(),
            message_type: "tx".to_string(),
            message_hash: vec![0x01, 0x02],
            mobile_tx: tx,
            state: MpcSigningState::WaitingForMobile,
        };
        
        let debug_str = format!("{:?}", session);
        assert!(debug_str.contains("test"));
        assert!(debug_str.contains("ethereum"));
        assert!(debug_str.contains("WaitingForMobile"));
    }

    // Note: The following test would require actual TSS engine integration
    // and is commented out for now since it depends on the TSS engines being
    // properly implemented and available in the test environment
    /*
    #[tokio::test] 
    async fn test_full_signing_flow_with_mock_tss() {
        // This would test the complete flow from session creation to signature
        // completion, but requires mock or stub implementations of the TSS engines
    }
    */
}

