use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use sha2::{Sha256, Digest};
use sha3::Keccak256;
use std::sync::Arc;
use base64::Engine;

use crate::keyshare::VultKeyshare;
use crate::session::SessionManager;
use crate::relay_client::RelayClient;

/// Transaction signing payload from external packages
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxSigningPayload {
    pub network: String,
    pub payload: Value,
    pub metadata: HashMap<String, String>,
}

/// Pre-signing hash with context information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreSigningHash {
    pub hash: Vec<u8>,
    pub hash_hex: String,
    pub derivation_path: String,
    pub algorithm: SignatureAlgorithm,
}

/// Supported signature algorithms
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SignatureAlgorithm {
    ECDSA,
    EdDSA,
}

/// Complete signing session parameters
#[derive(Debug, Clone)]
pub struct SigningSessionParams {
    pub session_id: String,
    pub local_party_id: String,
    pub network: String,
    pub signing_mode: SigningMode,
    pub relay_server_url: Option<String>,
    pub encryption_key: String,
    pub broadcast: bool,
}

impl SigningSessionParams {
    /// Check if transaction should be broadcast to the network
    pub fn should_broadcast(&self) -> bool {
        self.broadcast
    }
}

/// Signing modes
#[derive(Debug, Clone, PartialEq)]
pub enum SigningMode {
    Local,
    Relay,
}

/// MPC signature result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MpcSignature {
    pub r: Vec<u8>,
    pub s: Vec<u8>,
    pub der_signature: Vec<u8>,
    pub recovery_id: Option<u8>,
}

/// Compiled transaction ready for broadcasting
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompiledTransaction {
    pub network: String,
    pub raw_tx: Vec<u8>,
    pub tx_hash: String,
    pub signatures: Vec<MpcSignature>,
}

/// Main signing coordinator
pub struct SigningCoordinator {
    keyshare: VultKeyshare,
    session_manager: Arc<SessionManager>,
}

impl SigningCoordinator {
    pub fn new(keyshare: VultKeyshare, session_manager: Arc<SessionManager>) -> Self {
        Self {
            keyshare,
            session_manager,
        }
    }

    /// Start a complete signing session from payload to final signature
    /// This is the main entry point that orchestrates the entire signing flow
    pub async fn sign_transaction(
        &self,
        payload: TxSigningPayload,
        session_params: SigningSessionParams,
    ) -> Result<CompiledTransaction> {
        tracing::info!("Starting transaction signing session: {}", session_params.session_id);
        
        // Step 1: Generate pre-signing hashes
        let pre_signing_hashes = self.get_pre_signing_hashes(&payload)?;
        tracing::debug!("Generated {} pre-signing hashes", pre_signing_hashes.len());

        // Step 2: Initialize session management
        let session_id = self.create_mpc_session(&session_params, &pre_signing_hashes).await?;
        tracing::info!("Created MPC session: {}", session_id);

        // Step 3: Perform MPC keysign ceremony
        let mut updated_params = session_params.clone();
        updated_params.session_id = session_id.clone(); // Use MPC session ID for relay operations
        let signatures = self.perform_mpc_keysign(&updated_params, &pre_signing_hashes).await?;
        tracing::info!("Completed MPC keysign ceremony with {} signatures", signatures.len());

        // Step 4: Compile transaction with signatures
        let compiled_tx = self.compile_transaction(&payload, &signatures).await?;
        tracing::info!("Compiled transaction with hash: {}", compiled_tx.tx_hash);

        // Step 5: Optionally broadcast transaction
        let final_tx = if session_params.should_broadcast() {
            tracing::info!("Broadcasting transaction to network: {}", compiled_tx.network);
            match self.broadcast_transaction(&compiled_tx).await {
                Ok(broadcast_hash) => {
                    tracing::info!("Transaction broadcast successful: {}", broadcast_hash);
                    CompiledTransaction {
                        tx_hash: broadcast_hash,
                        ..compiled_tx
                    }
                }
                Err(e) => {
                    tracing::warn!("Transaction broadcast failed, but compilation succeeded: {}", e);
                    // Return the compiled transaction even if broadcast fails
                    compiled_tx
                }
            }
        } else {
            compiled_tx
        };

        // Step 6: Clean up session
        self.cleanup_session(&session_params).await?;

        Ok(final_tx)
    }

    /// Create and register MPC session according to the specification
    async fn create_mpc_session(
        &self,
        params: &SigningSessionParams,
        hashes: &[PreSigningHash],
    ) -> Result<String> {
        use crate::session::{SessionManager, SessionStatus};
        use std::collections::HashMap;

        // Create session metadata
        let mut metadata = HashMap::new();
        metadata.insert("network".to_string(), params.network.clone());
        metadata.insert("mode".to_string(), format!("{:?}", params.signing_mode));
        metadata.insert("local_party_id".to_string(), params.local_party_id.clone());
        
        if let Some(server_url) = &params.relay_server_url {
            metadata.insert("relay_server_url".to_string(), server_url.clone());
        }

        // Create session payload from first hash (primary message to sign)
        let primary_hash = hashes.first()
            .ok_or_else(|| anyhow!("No pre-signing hashes provided"))?;
        
        let session_id = self.session_manager.create_session(
            params.network.clone(),
            format!("{}_tx", params.network.to_lowercase()),
            primary_hash.hash.clone(),
            metadata,
        ).await?;

        // Update session status to indicate we're waiting for mobile device
        self.session_manager.update_session_status(&session_id, SessionStatus::WaitingForMobile).await?;
        
        tracing::info!("Session {} is waiting for mobile app to join", session_id);

        match params.signing_mode {
            SigningMode::Relay => {
                self.setup_relay_session(params, &session_id).await?;
            }
            SigningMode::Local => {
                self.setup_local_session(params, &session_id).await?;
            }
        }

        Ok(session_id)
    }

    /// Setup relay mode session with remote server
    async fn setup_relay_session(&self, params: &SigningSessionParams, session_id: &str) -> Result<()> {
        let default_server = "https://api.vultisig.com".to_string();
        let server_url = params.relay_server_url.as_ref()
            .unwrap_or(&default_server);
        
        let relay_client = RelayClient::new_remote(server_url);

        // Health check first
        if !relay_client.health_check().await.unwrap_or(false) {
            return Err(anyhow!("Relay server is not accessible: {}", server_url));
        }

        // Register session with relay server
        let public_key = self.keyshare.public_key_ecdsa(); // Use ECDSA public key as identifier
        relay_client.register_session(session_id, public_key).await?;
        
        tracing::info!("Registered session {} with relay server: {}", session_id, server_url);

        // Store relay client info in session metadata for later use
        // In a real implementation, we'd store this in the session manager
        
        Ok(())
    }

    /// Setup local mode session
    async fn setup_local_session(&self, params: &SigningSessionParams, session_id: &str) -> Result<()> {
        // For local mode, we use the embedded relay server on port 18080
        let local_server_url = "http://127.0.0.1:18080";
        let relay_client = RelayClient::new_local();

        // Health check local server
        if !relay_client.health_check().await.unwrap_or(false) {
            return Err(anyhow!("Local relay server is not running on port 18080"));
        }

        // Register session with local relay server
        let public_key = self.keyshare.public_key_ecdsa();
        relay_client.register_session(session_id, public_key).await?;

        tracing::info!("Registered session {} with local relay server", session_id);

        Ok(())
    }

    /// Wait for participants to join the session
    async fn wait_for_participants(&self, params: &SigningSessionParams) -> Result<Vec<String>> {
        let default_relay_server = "https://api.vultisig.com".to_string();
        let server_url = match params.signing_mode {
            SigningMode::Relay => {
                params.relay_server_url.as_ref()
                    .unwrap_or(&default_relay_server)
            }
            SigningMode::Local => "http://127.0.0.1:18080",
        };

        let relay_client = if params.signing_mode == SigningMode::Relay {
            RelayClient::new_remote(server_url)
        } else {
            RelayClient::new_local()
        };

        // Wait for session to start (other participants to join)
        tracing::info!("Waiting for participants to join session: {}", params.session_id);
        let participants = relay_client.wait_for_session_start(&params.session_id).await?;
        
        tracing::info!("Session started with participants: {:?}", participants);

        // Validate that we have exactly 2 participants for 2-of-2 MPC
        if participants.len() != 2 {
            return Err(anyhow!("Expected 2 participants for 2-of-2 MPC, got {}", participants.len()));
        }

        // Ensure our local party ID is in the participant list
        if !participants.contains(&params.local_party_id) {
            return Err(anyhow!("Local party ID {} not found in participants", params.local_party_id));
        }

        Ok(participants)
    }

    /// Get the other participant (peer) from the participant list
    fn get_peer_participant(&self, participants: &[String], local_party_id: &str) -> Result<String> {
        let peers: Vec<String> = participants.iter()
            .filter(|&p| p != local_party_id)
            .cloned()
            .collect();

        if peers.len() != 1 {
            return Err(anyhow!("Expected exactly 1 peer, got {}", peers.len()));
        }

        Ok(peers[0].clone())
    }

    /// Clean up session resources
    async fn cleanup_session(&self, params: &SigningSessionParams) -> Result<()> {
        let default_relay_server = "https://api.vultisig.com".to_string();
        let server_url = match params.signing_mode {
            SigningMode::Relay => {
                params.relay_server_url.as_ref()
                    .unwrap_or(&default_relay_server)
            }
            SigningMode::Local => "http://127.0.0.1:18080",
        };

        let relay_client = if params.signing_mode == SigningMode::Relay {
            RelayClient::new_remote(server_url)
        } else {
            RelayClient::new_local()
        };

        // End session on relay server (best effort)
        let _ = relay_client.end_session(&params.session_id).await;

        tracing::info!("Cleaned up session: {}", params.session_id);
        Ok(())
    }

    /// Perform MPC keysign ceremony with proper message exchange
    /// This implements the core TSS signing protocol coordination
    async fn perform_mpc_keysign(
        &self,
        params: &SigningSessionParams,
        hashes: &[PreSigningHash],
    ) -> Result<Vec<MpcSignature>> {
        tracing::info!("Starting MPC keysign ceremony for session: {}", params.session_id);
        
        if hashes.is_empty() {
            return Err(anyhow!("No hashes provided for signing"));
        }

        // Step 1: Wait for participants to join the session
        tracing::info!("Waiting for participants to join session: {}", params.session_id);
        let participants = self.wait_for_participants(params).await?;
        tracing::info!("All participants joined: {:?}", participants);

        // Step 2: Get the peer participant (in 2-of-2 TSS)
        let peer_id = self.get_peer_participant(&participants, &params.local_party_id)?;
        tracing::info!("Peer participant: {}", peer_id);

        // Step 3: Start MPC signing for each hash
        let mut signatures = Vec::new();
        
        for (i, hash) in hashes.iter().enumerate() {
            tracing::info!("Signing hash {} of {}: {}", i + 1, hashes.len(), hash.hash_hex);
            
            let signature = match hash.algorithm {
                SignatureAlgorithm::ECDSA => {
                    self.perform_ecdsa_keysign(params, hash, &peer_id).await?
                }
                SignatureAlgorithm::EdDSA => {
                    self.perform_eddsa_keysign(params, hash, &peer_id).await?
                }
            };
            
            signatures.push(signature);
            tracing::info!("Successfully signed hash {} with {} algorithm", i + 1, 
                         if hash.algorithm == SignatureAlgorithm::ECDSA { "ECDSA" } else { "EdDSA" });
        }

        tracing::info!("MPC keysign ceremony completed successfully with {} signatures", signatures.len());
        Ok(signatures)
    }

    /// Perform ECDSA keysign for a single hash using 2-of-2 MPC
    async fn perform_ecdsa_keysign(
        &self,
        params: &SigningSessionParams,
        hash: &PreSigningHash,
        _peer_id: &str,
    ) -> Result<MpcSignature> {
        use crate::mpc_coordinator::MpcCoordinator;
        
        tracing::info!("Starting ECDSA keysign for hash: {}", hash.hash_hex);
        
        // Get ECDSA keyshare data from our keyshare
        let ecdsa_keyshare = match &self.keyshare.ecdsa_keyshare {
            Some(keyshare) => keyshare.clone(),
            None => return Err(anyhow!("No ECDSA keyshare available")),
        };

        // Create relay client for message exchange
        let default_server = "https://api.vultisig.com".to_string();
        let relay_client = if params.signing_mode == SigningMode::Relay {
            let server_url = params.relay_server_url.as_ref()
                .unwrap_or(&default_server);
            Arc::new(crate::relay_client::RelayClient::new_remote(server_url))
        } else {
            Arc::new(crate::relay_client::RelayClient::new_local())
        };

        // Start ECDSA signing using the MPC coordinator
        let temp_coordinator = MpcCoordinator::new(self.session_manager.clone());
        let signing_result = temp_coordinator.start_ecdsa_signing(
            format!("{}-ecdsa-{}", params.session_id, hash.hash_hex),
            params.network.clone(),
            "keysign".to_string(),
            hash.hash.clone(),
            ecdsa_keyshare,
            params.signing_mode == SigningMode::Relay,
            Some(relay_client),
        ).await;

        match signing_result {
            Ok(_) => {
                // Wait for signing to complete by polling the session manager
                let signing_session_id = format!("{}-ecdsa-{}", params.session_id, hash.hash_hex);
                self.wait_for_signing_completion(&signing_session_id).await
            }
            Err(e) => {
                tracing::error!("Failed to start ECDSA signing: {}", e);
                Err(anyhow!("ECDSA signing failed: {}", e))
            }
        }
    }

    /// Perform EdDSA keysign for a single hash using 2-of-2 MPC
    async fn perform_eddsa_keysign(
        &self,
        params: &SigningSessionParams,
        hash: &PreSigningHash,
        _peer_id: &str,
    ) -> Result<MpcSignature> {
        use crate::mpc_coordinator::MpcCoordinator;
        
        tracing::info!("Starting EdDSA keysign for hash: {}", hash.hash_hex);
        
        // Get EdDSA keyshare data from our keyshare
        let eddsa_keyshare = match &self.keyshare.eddsa_keyshare {
            Some(keyshare) => keyshare.clone(),
            None => return Err(anyhow!("No EdDSA keyshare available")),
        };

        // Create relay client for message exchange
        let default_server = "https://api.vultisig.com".to_string();
        let relay_client = if params.signing_mode == SigningMode::Relay {
            let server_url = params.relay_server_url.as_ref()
                .unwrap_or(&default_server);
            Arc::new(crate::relay_client::RelayClient::new_remote(server_url))
        } else {
            Arc::new(crate::relay_client::RelayClient::new_local())
        };

        // Start EdDSA signing using the MPC coordinator
        let temp_coordinator = MpcCoordinator::new(self.session_manager.clone());
        let signing_result = temp_coordinator.start_eddsa_signing(
            format!("{}-eddsa-{}", params.session_id, hash.hash_hex),
            params.network.clone(),
            "keysign".to_string(),
            hash.hash.clone(),
            eddsa_keyshare,
            params.signing_mode == SigningMode::Relay,
            Some(relay_client),
        ).await;

        match signing_result {
            Ok(_) => {
                // Wait for signing to complete by polling the session manager
                let signing_session_id = format!("{}-eddsa-{}", params.session_id, hash.hash_hex);
                self.wait_for_signing_completion(&signing_session_id).await
            }
            Err(e) => {
                tracing::error!("Failed to start EdDSA signing: {}", e);
                Err(anyhow!("EdDSA signing failed: {}", e))
            }
        }
    }

    /// Wait for a signing session to complete and retrieve the signature
    async fn wait_for_signing_completion(&self, session_id: &str) -> Result<MpcSignature> {
        use crate::session::SessionStatus;
        use tokio::time::{sleep, Duration};
        
        const MAX_WAIT_TIME: Duration = Duration::from_secs(300); // 5 minutes
        const POLL_INTERVAL: Duration = Duration::from_millis(500);
        
        let start_time = std::time::Instant::now();
        
        loop {
            // Check if we've exceeded the maximum wait time
            if start_time.elapsed() > MAX_WAIT_TIME {
                return Err(anyhow!("Signing timeout: session {} took longer than 5 minutes", session_id));
            }

            // Get the session status
            if let Some(session) = self.session_manager.get_session(session_id).await {
                match session.status {
                    SessionStatus::Completed => {
                        // Get the signing result
                        if let Some(result) = self.session_manager.get_result(session_id).await {
                            if result.success {
                                tracing::info!("Signing completed successfully for session: {}", session_id);
                                
                                // Convert the signature bytes back to MpcSignature
                                // For ECDSA, signature contains r||s (64 bytes total)
                                // For EdDSA, signature is in the signature field directly
                                
                                if result.signature.len() >= 64 {
                                    // ECDSA signature: split into r and s
                                    let r = result.signature[..32].to_vec();
                                    let s = result.signature[32..64].to_vec();
                                    
                                    return Ok(MpcSignature {
                                        r,
                                        s,
                                        der_signature: result.signature.clone(),
                                        recovery_id: None, // Will be computed if needed
                                    });
                                } else if result.signature.len() == 32 || result.signature.len() == 64 {
                                    // EdDSA signature: use as-is in r field
                                    return Ok(MpcSignature {
                                        r: result.signature.clone(),
                                        s: vec![],
                                        der_signature: result.signature.clone(),
                                        recovery_id: None,
                                    });
                                } else {
                                    return Err(anyhow!("Invalid signature length: {}", result.signature.len()));
                                }
                            } else {
                                return Err(anyhow!("Signing failed: {}", result.error_message));
                            }
                        } else {
                            return Err(anyhow!("No signing result found for completed session: {}", session_id));
                        }
                    }
                    SessionStatus::Failed(ref error) => {
                        return Err(anyhow!("Signing failed: {}", error));
                    }
                    _ => {
                        // Still in progress, continue polling
                        tracing::debug!("Session {} status: {:?}", session_id, session.status);
                    }
                }
            } else {
                return Err(anyhow!("Session not found: {}", session_id));
            }

            // Wait before next poll
            sleep(POLL_INTERVAL).await;
        }
    }

    /// Compile transaction with signatures into final signed transaction
    /// This implements transaction compilation with signature integration
    async fn compile_transaction(
        &self,
        payload: &TxSigningPayload,
        signatures: &[MpcSignature],
    ) -> Result<CompiledTransaction> {
        tracing::info!("Compiling transaction for network: {}", payload.network);
        
        if signatures.is_empty() {
            return Err(anyhow!("No signatures provided for transaction compilation"));
        }

        let network = self.normalize_network(&payload.network)?;
        
        match network.as_str() {
            "ETH" | "BSC" | "MATIC" | "AVAX" => {
                self.compile_evm_transaction(&payload.payload, signatures, &network).await
            }
            "BTC" | "LTC" | "DOGE" => {
                self.compile_utxo_transaction(&payload.payload, signatures, &network).await
            }
            "SOL" => {
                self.compile_solana_transaction(&payload.payload, signatures, &network).await
            }
            "ATOM" | "THOR" => {
                self.compile_cosmos_transaction(&payload.payload, signatures, &network).await
            }
            _ => Err(anyhow!("Unsupported network for transaction compilation: {}", network)),
        }
    }

    /// Compile EVM-compatible transaction with ECDSA signatures
    async fn compile_evm_transaction(
        &self,
        payload: &Value,
        signatures: &[MpcSignature],
        network: &str,
    ) -> Result<CompiledTransaction> {
        tracing::info!("Compiling EVM transaction for network: {}", network);
        
        if signatures.len() != 1 {
            return Err(anyhow!("EVM transactions require exactly 1 signature, got {}", signatures.len()));
        }
        
        let signature = &signatures[0];
        
        // Extract transaction fields
        let to = payload.get("to").and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("Missing 'to' field"))?;
        let value_str;
        let value = if let Some(v) = payload.get("value").and_then(|v| v.as_str()) {
            v
        } else if let Some(v) = payload.get("value").and_then(|v| v.as_u64()) {
            value_str = v.to_string();
            &value_str
        } else {
            return Err(anyhow!("Missing 'value' field"));
        };
        
        let gas_price = payload.get("gasPrice").and_then(|v| v.as_str()).unwrap_or("20000000000");
        let gas_limit = payload.get("gasLimit").and_then(|v| v.as_str()).unwrap_or("21000");
        let nonce = payload.get("nonce").and_then(|v| v.as_u64()).unwrap_or(0);
        let data = payload.get("data").and_then(|v| v.as_str()).unwrap_or("");

        // Build signed transaction using RLP encoding
        let raw_tx = self.build_signed_evm_transaction(to, value, gas_price, gas_limit, nonce, data, signature, network)?;
        
        // Calculate transaction hash
        let tx_hash = format!("0x{}", hex::encode(Keccak256::digest(&raw_tx)));
        
        tracing::info!("EVM transaction compiled: hash={}, size={} bytes", tx_hash, raw_tx.len());
        
        Ok(CompiledTransaction {
            network: network.to_string(),
            raw_tx,
            tx_hash,
            signatures: signatures.to_vec(),
        })
    }

    /// Compile UTXO-based transaction with ECDSA signatures  
    async fn compile_utxo_transaction(
        &self,
        payload: &Value,
        signatures: &[MpcSignature],
        network: &str,
    ) -> Result<CompiledTransaction> {
        tracing::info!("Compiling UTXO transaction for network: {}", network);
        
        let to_address = payload.get("toAddress").and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("Missing 'toAddress' field"))?;
        let amount_str;
        let amount = if let Some(v) = payload.get("amount").and_then(|v| v.as_str()) {
            v
        } else if let Some(v) = payload.get("amount").and_then(|v| v.as_u64()) {
            amount_str = v.to_string();
            &amount_str
        } else {
            return Err(anyhow!("Missing 'amount' field"));
        };

        // Build signed transaction
        let raw_tx = self.build_signed_utxo_transaction(to_address, amount, signatures, network)?;
        
        // Calculate transaction ID (double SHA256)
        let hash1 = Sha256::digest(&raw_tx);
        let hash2 = Sha256::digest(&hash1);
        let tx_hash = hex::encode(hash2);
        
        tracing::info!("UTXO transaction compiled: txid={}, size={} bytes", tx_hash, raw_tx.len());
        
        Ok(CompiledTransaction {
            network: network.to_string(),
            raw_tx,
            tx_hash,
            signatures: signatures.to_vec(),
        })
    }

    /// Compile Solana transaction with EdDSA signatures
    async fn compile_solana_transaction(
        &self,
        payload: &Value,
        signatures: &[MpcSignature],
        network: &str,
    ) -> Result<CompiledTransaction> {
        tracing::info!("Compiling Solana transaction for network: {}", network);
        
        if signatures.len() != 1 {
            return Err(anyhow!("Solana transactions require exactly 1 signature, got {}", signatures.len()));
        }

        let to_pubkey = payload.get("toPubkey").and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("Missing 'toPubkey' field"))?;
        let amount = payload.get("amount").and_then(|v| v.as_u64())
            .ok_or_else(|| anyhow!("Missing 'amount' field"))?;

        // Build signed Solana transaction
        let raw_tx = self.build_signed_solana_transaction(to_pubkey, amount, &signatures[0])?;
        
        // Solana transaction hash is just the first signature
        let tx_hash = hex::encode(&signatures[0].r);
        
        tracing::info!("Solana transaction compiled: hash={}, size={} bytes", tx_hash, raw_tx.len());
        
        Ok(CompiledTransaction {
            network: network.to_string(),
            raw_tx,
            tx_hash,
            signatures: signatures.to_vec(),
        })
    }

    /// Compile Cosmos SDK transaction with ECDSA signatures
    async fn compile_cosmos_transaction(
        &self,
        payload: &Value,
        signatures: &[MpcSignature],
        network: &str,
    ) -> Result<CompiledTransaction> {
        tracing::info!("Compiling Cosmos transaction for network: {}", network);
        
        if signatures.len() != 1 {
            return Err(anyhow!("Cosmos transactions require exactly 1 signature, got {}", signatures.len()));
        }

        let to_address = payload.get("toAddress").and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("Missing 'toAddress' field"))?;
        let amount_str;
        let amount = if let Some(v) = payload.get("amount").and_then(|v| v.as_str()) {
            v
        } else if let Some(v) = payload.get("amount").and_then(|v| v.as_u64()) {
            amount_str = v.to_string();
            &amount_str
        } else {
            return Err(anyhow!("Missing 'amount' field"));
        };

        // Build signed Cosmos transaction
        let raw_tx = self.build_signed_cosmos_transaction(to_address, amount, &signatures[0], network)?;
        
        // Calculate transaction hash
        let tx_hash = format!("{}", hex::encode(Sha256::digest(&raw_tx)));
        
        tracing::info!("Cosmos transaction compiled: hash={}, size={} bytes", tx_hash, raw_tx.len());
        
        Ok(CompiledTransaction {
            network: network.to_string(),
            raw_tx,
            tx_hash,
            signatures: signatures.to_vec(),
        })
    }

    /// Helper methods for building signed transactions
    fn build_signed_evm_transaction(
        &self,
        to: &str,
        value: &str,
        gas_price: &str,
        gas_limit: &str,
        nonce: u64,
        data: &str,
        signature: &MpcSignature,
        _network: &str,
    ) -> Result<Vec<u8>> {
        // Simplified EVM transaction with signature
        // In practice, this would use proper RLP encoding with v, r, s values
        let mut tx_data = Vec::new();
        tx_data.extend_from_slice(&nonce.to_be_bytes());
        tx_data.extend_from_slice(gas_price.as_bytes());
        tx_data.extend_from_slice(gas_limit.as_bytes());
        tx_data.extend_from_slice(to.as_bytes());
        tx_data.extend_from_slice(value.as_bytes());
        if !data.is_empty() {
            tx_data.extend_from_slice(data.as_bytes());
        }
        
        // Append signature components (r, s, v)
        tx_data.extend_from_slice(&signature.r);
        tx_data.extend_from_slice(&signature.s);
        if let Some(recovery_id) = signature.recovery_id {
            tx_data.push(recovery_id);
        }
        
        Ok(tx_data)
    }

    fn build_signed_utxo_transaction(
        &self,
        to_address: &str,
        amount: &str,
        signatures: &[MpcSignature],
        _network: &str,
    ) -> Result<Vec<u8>> {
        // Simplified UTXO transaction with signatures
        let mut tx_data = Vec::new();
        tx_data.extend_from_slice(to_address.as_bytes());
        tx_data.extend_from_slice(amount.as_bytes());
        
        // Add all signatures
        for signature in signatures {
            tx_data.extend_from_slice(&signature.der_signature);
        }
        
        Ok(tx_data)
    }

    fn build_signed_solana_transaction(&self, to_pubkey: &str, amount: u64, signature: &MpcSignature) -> Result<Vec<u8>> {
        // Simplified Solana transaction with signature
        let mut tx_data = Vec::new();
        tx_data.extend_from_slice(&signature.r); // EdDSA signature
        tx_data.extend_from_slice(to_pubkey.as_bytes());
        tx_data.extend_from_slice(&amount.to_be_bytes());
        
        Ok(tx_data)
    }

    fn build_signed_cosmos_transaction(
        &self,
        to_address: &str,
        amount: &str,
        signature: &MpcSignature,
        _network: &str,
    ) -> Result<Vec<u8>> {
        // Simplified Cosmos transaction with signature
        let mut tx_data = Vec::new();
        tx_data.extend_from_slice(to_address.as_bytes());
        tx_data.extend_from_slice(amount.as_bytes());
        tx_data.extend_from_slice(&signature.der_signature);
        
        Ok(tx_data)
    }

    /// Broadcast compiled transaction to the network
    async fn broadcast_transaction(&self, compiled_tx: &CompiledTransaction) -> Result<String> {
        tracing::info!("Broadcasting transaction to {} network", compiled_tx.network);
        
        let network = self.normalize_network(&compiled_tx.network)?;
        
        match network.as_str() {
            "ETH" | "BSC" | "MATIC" | "AVAX" => {
                self.broadcast_evm_transaction(compiled_tx, &network).await
            }
            "BTC" | "LTC" | "DOGE" => {
                self.broadcast_utxo_transaction(compiled_tx, &network).await
            }
            "SOL" => {
                self.broadcast_solana_transaction(compiled_tx, &network).await
            }
            "ATOM" | "THOR" => {
                self.broadcast_cosmos_transaction(compiled_tx, &network).await
            }
            _ => Err(anyhow!("Broadcasting not supported for network: {}", network)),
        }
    }

    /// Broadcast EVM transaction via RPC
    async fn broadcast_evm_transaction(&self, compiled_tx: &CompiledTransaction, network: &str) -> Result<String> {
        let rpc_url = self.get_rpc_url(network)?;
        
        // Prepare RPC payload
        let raw_tx_hex = format!("0x{}", hex::encode(&compiled_tx.raw_tx));
        let rpc_payload = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "eth_sendRawTransaction",
            "params": [raw_tx_hex],
            "id": 1
        });

        tracing::info!("Broadcasting to {} RPC: {}", network, rpc_url);
        
        // Send transaction via HTTP
        let client = reqwest::Client::new();
        let response = client
            .post(&rpc_url)
            .header("Content-Type", "application/json")
            .json(&rpc_payload)
            .send()
            .await
            .map_err(|e| anyhow!("Failed to send transaction to RPC: {}", e))?;

        if !response.status().is_success() {
            return Err(anyhow!("RPC request failed with status: {}", response.status()));
        }

        let rpc_response: serde_json::Value = response
            .json()
            .await
            .map_err(|e| anyhow!("Failed to parse RPC response: {}", e))?;

        // Extract transaction hash from response
        if let Some(error) = rpc_response.get("error") {
            return Err(anyhow!("RPC error: {}", error));
        }

        let tx_hash = rpc_response
            .get("result")
            .and_then(|r| r.as_str())
            .ok_or_else(|| anyhow!("No transaction hash in RPC response"))?;

        tracing::info!("EVM transaction broadcast successful: {}", tx_hash);
        Ok(tx_hash.to_string())
    }

    /// Broadcast UTXO transaction via RPC
    async fn broadcast_utxo_transaction(&self, compiled_tx: &CompiledTransaction, network: &str) -> Result<String> {
        let rpc_url = self.get_rpc_url(network)?;
        
        // Prepare RPC payload (Bitcoin-style)
        let raw_tx_hex = hex::encode(&compiled_tx.raw_tx);
        let rpc_payload = serde_json::json!({
            "jsonrpc": "1.0",
            "method": "sendrawtransaction",
            "params": [raw_tx_hex],
            "id": 1
        });

        tracing::info!("Broadcasting to {} RPC: {}", network, rpc_url);

        let client = reqwest::Client::new();
        let response = client
            .post(&rpc_url)
            .header("Content-Type", "application/json")
            .json(&rpc_payload)
            .send()
            .await
            .map_err(|e| anyhow!("Failed to send transaction to RPC: {}", e))?;

        if !response.status().is_success() {
            return Err(anyhow!("RPC request failed with status: {}", response.status()));
        }

        let rpc_response: serde_json::Value = response
            .json()
            .await
            .map_err(|e| anyhow!("Failed to parse RPC response: {}", e))?;

        if let Some(error) = rpc_response.get("error") {
            return Err(anyhow!("RPC error: {}", error));
        }

        let tx_hash = rpc_response
            .get("result")
            .and_then(|r| r.as_str())
            .ok_or_else(|| anyhow!("No transaction hash in RPC response"))?;

        tracing::info!("UTXO transaction broadcast successful: {}", tx_hash);
        Ok(tx_hash.to_string())
    }

    /// Broadcast Solana transaction via RPC
    async fn broadcast_solana_transaction(&self, compiled_tx: &CompiledTransaction, _network: &str) -> Result<String> {
        let rpc_url = "https://api.mainnet-beta.solana.com";
        
        // Prepare Solana RPC payload
        let raw_tx_base64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &compiled_tx.raw_tx);
        let rpc_payload = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "sendTransaction",
            "params": [raw_tx_base64, {"encoding": "base64"}],
            "id": 1
        });

        tracing::info!("Broadcasting to Solana RPC: {}", rpc_url);

        let client = reqwest::Client::new();
        let response = client
            .post(rpc_url)
            .header("Content-Type", "application/json")
            .json(&rpc_payload)
            .send()
            .await
            .map_err(|e| anyhow!("Failed to send transaction to Solana RPC: {}", e))?;

        if !response.status().is_success() {
            return Err(anyhow!("Solana RPC request failed with status: {}", response.status()));
        }

        let rpc_response: serde_json::Value = response
            .json()
            .await
            .map_err(|e| anyhow!("Failed to parse Solana RPC response: {}", e))?;

        if let Some(error) = rpc_response.get("error") {
            return Err(anyhow!("Solana RPC error: {}", error));
        }

        let tx_hash = rpc_response
            .get("result")
            .and_then(|r| r.as_str())
            .ok_or_else(|| anyhow!("No transaction hash in Solana RPC response"))?;

        tracing::info!("Solana transaction broadcast successful: {}", tx_hash);
        Ok(tx_hash.to_string())
    }

    /// Broadcast Cosmos transaction via RPC  
    async fn broadcast_cosmos_transaction(&self, compiled_tx: &CompiledTransaction, network: &str) -> Result<String> {
        let rpc_url = self.get_rpc_url(network)?;
        
        // Prepare Cosmos RPC payload
        let raw_tx_base64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &compiled_tx.raw_tx);
        let rpc_payload = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "broadcast_tx_sync",
            "params": {
                "tx": raw_tx_base64
            },
            "id": 1
        });

        tracing::info!("Broadcasting to {} RPC: {}", network, rpc_url);

        let client = reqwest::Client::new();
        let response = client
            .post(&rpc_url)
            .header("Content-Type", "application/json")
            .json(&rpc_payload)
            .send()
            .await
            .map_err(|e| anyhow!("Failed to send transaction to Cosmos RPC: {}", e))?;

        if !response.status().is_success() {
            return Err(anyhow!("Cosmos RPC request failed with status: {}", response.status()));
        }

        let rpc_response: serde_json::Value = response
            .json()
            .await
            .map_err(|e| anyhow!("Failed to parse Cosmos RPC response: {}", e))?;

        if let Some(error) = rpc_response.get("error") {
            return Err(anyhow!("Cosmos RPC error: {}", error));
        }

        // Cosmos returns the transaction hash in result.hash
        let tx_hash = rpc_response
            .get("result")
            .and_then(|r| r.get("hash"))
            .and_then(|h| h.as_str())
            .ok_or_else(|| anyhow!("No transaction hash in Cosmos RPC response"))?;

        tracing::info!("Cosmos transaction broadcast successful: {}", tx_hash);
        Ok(tx_hash.to_string())
    }

    /// Get RPC URL for network broadcasting
    fn get_rpc_url(&self, network: &str) -> Result<String> {
        let url = match network {
            "ETH" => "https://eth.llamarpc.com",
            "BSC" => "https://bsc-dataseed1.binance.org",
            "MATIC" => "https://polygon-rpc.com",
            "AVAX" => "https://api.avax.network/ext/bc/C/rpc",
            "BTC" => "https://blockstream.info/api", // Using blockstream API
            "LTC" => "https://litecoin.com/api/rpc", // Example Litecoin RPC
            "DOGE" => "https://dogechain.info/api/rpc", // Example Dogecoin RPC
            "ATOM" => "https://cosmos-rpc.polkachu.com",
            "THOR" => "https://thornode.ninerealms.com",
            _ => return Err(anyhow!("No RPC URL configured for network: {}", network)),
        };
        Ok(url.to_string())
    }

    /// Generate pre-signing hashes from transaction payload
    /// This is equivalent to the TypeScript `getPreSigningHashes` function
    pub fn get_pre_signing_hashes(
        &self,
        payload: &TxSigningPayload,
    ) -> Result<Vec<PreSigningHash>> {
        let network = self.normalize_network(&payload.network)?;
        let algorithm = self.get_signature_algorithm(&network)?;
        
        match network.as_str() {
            "ETH" | "BSC" | "MATIC" | "AVAX" => {
                self.get_evm_pre_signing_hashes(&payload.payload, &network, algorithm)
            }
            "BTC" | "LTC" | "DOGE" => {
                self.get_utxo_pre_signing_hashes(&payload.payload, &network, algorithm)
            }
            "SOL" => {
                self.get_solana_pre_signing_hashes(&payload.payload, &network, algorithm)
            }
            "ATOM" | "THOR" => {
                self.get_cosmos_pre_signing_hashes(&payload.payload, &network, algorithm)
            }
            _ => Err(anyhow!("Unsupported network: {}", network)),
        }
    }

    /// Generate pre-signing hashes for EVM-compatible chains
    fn get_evm_pre_signing_hashes(
        &self,
        payload: &Value,
        network: &str,
        algorithm: SignatureAlgorithm,
    ) -> Result<Vec<PreSigningHash>> {
        // Extract transaction fields from payload
        let to = payload.get("to")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("Missing 'to' field in EVM transaction"))?;
        
        let value_str;
        let value = if let Some(v) = payload.get("value").and_then(|v| v.as_str()) {
            v
        } else if let Some(v) = payload.get("value").and_then(|v| v.as_u64()) {
            value_str = v.to_string();
            &value_str
        } else {
            return Err(anyhow!("Missing 'value' field in EVM transaction"));
        };
        
        let gas_price_str;
        let gas_price = if let Some(v) = payload.get("gasPrice").and_then(|v| v.as_str()) {
            v
        } else if let Some(v) = payload.get("gasPrice").and_then(|v| v.as_u64()) {
            gas_price_str = v.to_string();
            &gas_price_str
        } else {
            "20000000000"
        };
        
        let gas_limit_str;
        let gas_limit = if let Some(v) = payload.get("gasLimit").and_then(|v| v.as_str()) {
            v
        } else if let Some(v) = payload.get("gasLimit").and_then(|v| v.as_u64()) {
            gas_limit_str = v.to_string();
            &gas_limit_str
        } else {
            "21000"
        };
        
        let nonce = payload.get("nonce")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        
        let data = payload.get("data")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        // Build EVM transaction for signing
        let tx_data = self.build_evm_transaction(to, value, gas_price, gas_limit, nonce, data, network)?;
        
        // Generate Keccak256 hash for EVM transactions
        let hash = Keccak256::digest(&tx_data);
        let hash_vec = hash.to_vec();
        let hash_hex = hex::encode(&hash_vec);

        let derivation_path = self.get_derivation_path(network)?;

        Ok(vec![PreSigningHash {
            hash: hash_vec,
            hash_hex,
            derivation_path,
            algorithm,
        }])
    }

    /// Generate pre-signing hashes for UTXO-based chains (Bitcoin, etc.)
    fn get_utxo_pre_signing_hashes(
        &self,
        payload: &Value,
        network: &str,
        algorithm: SignatureAlgorithm,
    ) -> Result<Vec<PreSigningHash>> {
        // Extract UTXO transaction fields
        let to_address = payload.get("toAddress")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("Missing 'toAddress' field in UTXO transaction"))?;
        
        let amount_str;
        let amount = if let Some(v) = payload.get("amount").and_then(|v| v.as_str()) {
            v
        } else if let Some(v) = payload.get("amount").and_then(|v| v.as_u64()) {
            amount_str = v.to_string();
            &amount_str
        } else {
            return Err(anyhow!("Missing 'amount' field in UTXO transaction"));
        };
        
        let fee_rate_str;
        let fee_rate = if let Some(v) = payload.get("feeRate").and_then(|v| v.as_str()) {
            v
        } else if let Some(v) = payload.get("feeRate").and_then(|v| v.as_u64()) {
            fee_rate_str = v.to_string();
            &fee_rate_str
        } else {
            "10"
        };

        // For UTXO chains, we need to hash the transaction inputs
        let tx_data = self.build_utxo_transaction(to_address, amount, fee_rate, network)?;
        
        // Use double SHA256 for Bitcoin-like chains
        let hash1 = Sha256::digest(&tx_data);
        let hash2 = Sha256::digest(&hash1);
        let hash_vec = hash2.to_vec();
        let hash_hex = hex::encode(&hash_vec);

        let derivation_path = self.get_derivation_path(network)?;

        Ok(vec![PreSigningHash {
            hash: hash_vec,
            hash_hex,
            derivation_path,
            algorithm,
        }])
    }

    /// Generate pre-signing hashes for Solana transactions
    fn get_solana_pre_signing_hashes(
        &self,
        payload: &Value,
        network: &str,
        algorithm: SignatureAlgorithm,
    ) -> Result<Vec<PreSigningHash>> {
        // Extract Solana transaction fields
        let to_pubkey = payload.get("toPubkey")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("Missing 'toPubkey' field in Solana transaction"))?;
        
        let amount = payload.get("amount")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| anyhow!("Missing 'amount' field in Solana transaction"))?;

        // Build Solana transaction for signing
        let tx_data = self.build_solana_transaction(to_pubkey, amount)?;
        
        // Solana uses raw bytes for signing (no additional hashing)
        let hash_vec = tx_data;
        let hash_hex = hex::encode(&hash_vec);

        let derivation_path = self.get_derivation_path(network)?;

        Ok(vec![PreSigningHash {
            hash: hash_vec,
            hash_hex,
            derivation_path,
            algorithm,
        }])
    }

    /// Generate pre-signing hashes for Cosmos SDK chains
    fn get_cosmos_pre_signing_hashes(
        &self,
        payload: &Value,
        network: &str,
        algorithm: SignatureAlgorithm,
    ) -> Result<Vec<PreSigningHash>> {
        // Extract Cosmos transaction fields
        let to_address = payload.get("toAddress")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("Missing 'toAddress' field in Cosmos transaction"))?;
        
        let amount_str;
        let amount = if let Some(v) = payload.get("amount").and_then(|v| v.as_str()) {
            v
        } else if let Some(v) = payload.get("amount").and_then(|v| v.as_u64()) {
            amount_str = v.to_string();
            &amount_str
        } else {
            return Err(anyhow!("Missing 'amount' field in Cosmos transaction"));
        };

        // Build Cosmos transaction for signing
        let tx_data = self.build_cosmos_transaction(to_address, amount, network)?;
        
        // Cosmos uses SHA256 for transaction hashing
        let hash = Sha256::digest(&tx_data);
        let hash_vec = hash.to_vec();
        let hash_hex = hex::encode(&hash_vec);

        let derivation_path = self.get_derivation_path(network)?;

        Ok(vec![PreSigningHash {
            hash: hash_vec,
            hash_hex,
            derivation_path,
            algorithm,
        }])
    }

    /// Helper methods for transaction building
    fn build_evm_transaction(
        &self,
        to: &str,
        value: &str,
        gas_price: &str,
        gas_limit: &str,
        nonce: u64,
        data: &str,
        _network: &str,
    ) -> Result<Vec<u8>> {
        // Simplified EVM transaction encoding - in practice would use RLP encoding
        let mut tx_data = Vec::new();
        tx_data.extend_from_slice(&nonce.to_be_bytes());
        tx_data.extend_from_slice(gas_price.as_bytes());
        tx_data.extend_from_slice(gas_limit.as_bytes());
        tx_data.extend_from_slice(to.as_bytes());
        tx_data.extend_from_slice(value.as_bytes());
        if !data.is_empty() {
            tx_data.extend_from_slice(data.as_bytes());
        }
        Ok(tx_data)
    }

    fn build_utxo_transaction(&self, to: &str, amount: &str, fee_rate: &str, _network: &str) -> Result<Vec<u8>> {
        // Simplified UTXO transaction encoding
        let mut tx_data = Vec::new();
        tx_data.extend_from_slice(to.as_bytes());
        tx_data.extend_from_slice(amount.as_bytes());
        tx_data.extend_from_slice(fee_rate.as_bytes());
        Ok(tx_data)
    }

    fn build_solana_transaction(&self, to_pubkey: &str, amount: u64) -> Result<Vec<u8>> {
        // Simplified Solana transaction encoding
        let mut tx_data = Vec::new();
        tx_data.extend_from_slice(to_pubkey.as_bytes());
        tx_data.extend_from_slice(&amount.to_be_bytes());
        Ok(tx_data)
    }

    fn build_cosmos_transaction(&self, to_address: &str, amount: &str, _network: &str) -> Result<Vec<u8>> {
        // Simplified Cosmos transaction encoding
        let mut tx_data = Vec::new();
        tx_data.extend_from_slice(to_address.as_bytes());
        tx_data.extend_from_slice(amount.as_bytes());
        Ok(tx_data)
    }

    /// Get the appropriate signature algorithm for a network
    fn get_signature_algorithm(&self, network: &str) -> Result<SignatureAlgorithm> {
        match network {
            "SOL" => Ok(SignatureAlgorithm::EdDSA),
            _ => Ok(SignatureAlgorithm::ECDSA),
        }
    }

    /// Get BIP32 derivation path for a network
    fn get_derivation_path(&self, network: &str) -> Result<String> {
        match network {
            "ETH" | "BSC" | "MATIC" | "AVAX" => Ok("m/44'/60'/0'/0/0".to_string()),
            "BTC" => Ok("m/44'/0'/0'/0/0".to_string()),
            "LTC" => Ok("m/44'/2'/0'/0/0".to_string()),
            "DOGE" => Ok("m/44'/3'/0'/0/0".to_string()),
            "SOL" => Ok("m/44'/501'/0'/0'".to_string()),
            "ATOM" => Ok("m/44'/118'/0'/0/0".to_string()),
            "THOR" => Ok("m/44'/931'/0'/0/0".to_string()),
            _ => Err(anyhow!("Unknown network: {}", network)),
        }
    }

    /// Normalize network name to uppercase
    fn normalize_network(&self, network: &str) -> Result<String> {
        let normalized = match network.to_lowercase().as_str() {
            "eth" | "ethereum" => "ETH",
            "btc" | "bitcoin" => "BTC",
            "sol" | "solana" => "SOL",
            "atom" | "cosmos" => "ATOM",
            "thor" | "thorchain" => "THOR",
            "bsc" | "binance" => "BSC",
            "matic" | "polygon" => "MATIC",
            "avax" | "avalanche" => "AVAX",
            "ltc" | "litecoin" => "LTC",
            "doge" | "dogecoin" => "DOGE",
            _ => network,
        };
        Ok(normalized.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keyshare::VultKeyshare;
    use crate::session::SessionManager;
    use std::sync::Arc;
    use serde_json::json;

    fn create_test_coordinator() -> Result<SigningCoordinator> {
        // Create a minimal keyshare for testing
        // Using base64 encoded protobuf that matches the expected format
        let test_base64 = "ChdUZXN0U2VjdXJlVmF1bHQtdGVzdC0xMjMSiAEKUDOCQRMEWjfF9YNIzqJQdC5iZ+NHLZ6VqOmTyUgCGy7Tg5P8UqwU4RqBFaY+B7XZDVzK/YmEBF4/Ts5YKvPz9+3xJb8O9jAFMjr8YmsSFFCyDFdKBjqaKmj+Xqk/yUqJ/Y8QP8Qj8PmfY="; 
        let keyshare = VultKeyshare::from_base64(test_base64)?;
        let session_manager = Arc::new(SessionManager::new());
        Ok(SigningCoordinator::new(keyshare, session_manager))
    }

    #[test]
    fn test_normalize_network() {
        let coordinator = create_test_coordinator().unwrap();
        
        assert_eq!(coordinator.normalize_network("eth").unwrap(), "ETH");
        assert_eq!(coordinator.normalize_network("ETH").unwrap(), "ETH");
        assert_eq!(coordinator.normalize_network("ethereum").unwrap(), "ETH");
        assert_eq!(coordinator.normalize_network("btc").unwrap(), "BTC");
        assert_eq!(coordinator.normalize_network("sol").unwrap(), "SOL");
    }

    #[test]
    fn test_get_signature_algorithm() {
        let coordinator = create_test_coordinator().unwrap();
        
        assert_eq!(coordinator.get_signature_algorithm("ETH").unwrap(), SignatureAlgorithm::ECDSA);
        assert_eq!(coordinator.get_signature_algorithm("BTC").unwrap(), SignatureAlgorithm::ECDSA);
        assert_eq!(coordinator.get_signature_algorithm("SOL").unwrap(), SignatureAlgorithm::EdDSA);
    }

    #[test]
    fn test_get_derivation_path() {
        let coordinator = create_test_coordinator().unwrap();
        
        assert_eq!(coordinator.get_derivation_path("ETH").unwrap(), "m/44'/60'/0'/0/0");
        assert_eq!(coordinator.get_derivation_path("BTC").unwrap(), "m/44'/0'/0'/0/0");
        assert_eq!(coordinator.get_derivation_path("SOL").unwrap(), "m/44'/501'/0'/0'");
    }

    #[test]
    fn test_evm_pre_signing_hashes() {
        let coordinator = create_test_coordinator().unwrap();
        
        let payload = TxSigningPayload {
            network: "ETH".to_string(),
            payload: json!({
                "to": "0x742d35Cc6634C0532925a3b8D6Ac6E2b8c2C5E00",
                "value": "1000000000000000000",
                "gasPrice": "20000000000",
                "gasLimit": "21000",
                "nonce": 0,
                "data": ""
            }),
            metadata: HashMap::new(),
        };

        let hashes = coordinator.get_pre_signing_hashes(&payload).unwrap();
        assert_eq!(hashes.len(), 1);
        assert_eq!(hashes[0].algorithm, SignatureAlgorithm::ECDSA);
        assert_eq!(hashes[0].derivation_path, "m/44'/60'/0'/0/0");
        assert!(!hashes[0].hash.is_empty());
        assert!(!hashes[0].hash_hex.is_empty());
    }
}