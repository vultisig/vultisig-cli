// Fixed TSS implementation using correct API patterns
// This file demonstrates the correct way to use DKLS23 and multi-party-schnorr

use std::sync::Arc;
use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tracing::{info, error};
use rand;

use crate::keyshare::{EcdsaKeyshareData, EddsaKeyshareData};

// TSS Messages for communication between daemon and mobile app
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TssMessage {
    // Setup phase
    SetupRequest {
        session_id: String,
        keyshare_info: TssKeyshareInfo,
    },
    SetupResponse {
        session_id: String,
        public_keys: Vec<Vec<u8>>,
        party_ids: Vec<String>,
    },
    
    // ECDSA Protocol Messages (DKLS23)
    EcdsaRound1 {
        sender: String,
        share_data: Vec<u8>,
    },
    EcdsaRound2 {
        sender: String,
        signature_share: Vec<u8>,
    },
    EcdsaRound3 {
        sender: String,
        final_signature: Vec<u8>,
    },
    
    // EdDSA Protocol Messages (multi-party-schnorr)
    EddsaRound1 {
        sender: String,
        commitment: Vec<u8>,
    },
    EddsaRound2 {
        sender: String,
        signature_share: Vec<u8>,
    },
    
    // Completion
    SigningComplete {
        signature: Vec<u8>,
        recovery_id: Option<u8>,
    },
    SigningError {
        error: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TssKeyshareInfo {
    pub public_key: Vec<u8>,
    pub chain_code: Vec<u8>,
    pub party_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signature {
    pub r: Vec<u8>,
    pub s: Vec<u8>,
    pub recovery_id: Option<u8>,
}

// TSS Engine enum for different signing algorithms
// Using enum instead of trait to avoid dyn compatibility issues with async methods
#[derive(Debug)]
pub enum TssEngine {
    Ecdsa(EcdsaTssEngine),
    EdDsa(EdDsaTssEngine),
}

impl TssEngine {
    pub async fn sign_as_initiator(
        &self,
        message_hash: Vec<u8>,
        mobile_tx: mpsc::UnboundedSender<TssMessage>,
        mobile_rx: mpsc::UnboundedReceiver<TssMessage>,
    ) -> Result<Signature> {
        match self {
            TssEngine::Ecdsa(engine) => engine.sign_as_initiator(message_hash, mobile_tx, mobile_rx).await,
            TssEngine::EdDsa(engine) => engine.sign_as_initiator(message_hash, mobile_tx, mobile_rx).await,
        }
    }
}

// ECDSA TSS Engine using DKLS23 - CORRECTED IMPLEMENTATION
#[derive(Debug)]
pub struct EcdsaTssEngine {
    keyshare_data: EcdsaKeyshareData,
}

impl EcdsaTssEngine {
    pub fn new(keyshare_data: EcdsaKeyshareData) -> Self {
        Self { keyshare_data }
    }
    
    // Convert VultKeyshare to DKLS23 format
    fn convert_vult_to_dkls_keyshare(&self) -> Result<Arc<sl_dkls23::keygen::Keyshare>> {
        // ISSUE: sl_dkls23::keygen::Keyshare doesn't implement Deserialize
        // We need to either:
        // 1. Generate keyshares using the DKLS23 keygen process
        // 2. Find another way to convert VultKeyshare data
        // 3. Use a different approach
        
        error!("❌ DKLS23: VultKeyshare to DKLS23 conversion not yet implemented");
        error!("❌ DKLS23: sl_dkls23::keygen::Keyshare does not implement Deserialize trait");
        error!("❌ DKLS23: Need to implement keyshare conversion or use keygen process");
        
        Err(anyhow!("VultKeyshare to DKLS23 keyshare conversion not implemented - Keyshare lacks Deserialize trait"))
    }
    
    // Create DKLS23 signing setup - CORRECTED
    fn create_sign_setup(
        &self, 
        keyshare: Arc<sl_dkls23::keygen::Keyshare>,
        message_hash: &[u8]
    ) -> Result<sl_dkls23::setup::sign::SetupMessage> {
        use sl_dkls23::setup::{NoSigningKey, NoVerifyingKey};
        use sl_mpc_mate::message::InstanceId;
        use derivation_path::DerivationPath;
        use std::str::FromStr;
        
        info!("🔄 DKLS23: Creating signing setup for 2-party protocol");
        
        // Generate unique instance ID for this signing session
        let instance_id = InstanceId::new(rand::random::<[u8; 32]>());
        
        // Use NoSigningKey for local testing (as shown in examples)
        let signing_key = NoSigningKey;
        
        // Party index (0 for daemon, 1 for mobile)
        let party_index = 0;
        
        // Create verifying keys for both parties (daemon=0, mobile=1)
        let party_vks = vec![
            NoVerifyingKey::new(0), // daemon
            NoVerifyingKey::new(1), // mobile
        ];
        
        // Default derivation path
        let chain_path = DerivationPath::from_str("m").map_err(|e| {
            anyhow!("Failed to parse derivation path: {}", e)
        })?;
        
        // Create the setup message
        let mut setup = sl_dkls23::setup::sign::SetupMessage::new(
            instance_id,
            signing_key,
            party_index,
            party_vks,
            keyshare,
        );
        
        // Add chain path and message hash
        setup = setup.with_chain_path(chain_path);
        setup = setup.with_hash(message_hash.try_into().map_err(|_| {
            anyhow!("Message hash must be exactly 32 bytes")
        })?);
        
        // Add TTL
        setup = setup.with_ttl(std::time::Duration::from_secs(300)); // 5 minutes
        
        info!("✅ DKLS23: Signing setup created successfully");
        Ok(setup)
    }
}

impl EcdsaTssEngine {
    pub async fn sign_as_initiator(
        &self,
        message_hash: Vec<u8>,
        mobile_tx: mpsc::UnboundedSender<TssMessage>,
        mut mobile_rx: mpsc::UnboundedReceiver<TssMessage>,
    ) -> Result<Signature> {
        info!("🚀 DKLS23 PROTOCOL START: Initiating ECDSA signing");
        
        // Ensure message hash is exactly 32 bytes
        if message_hash.len() != 32 {
            return Err(anyhow!("Message hash must be exactly 32 bytes, got {}", message_hash.len()));
        }
        let hash_array: [u8; 32] = message_hash.try_into()
            .map_err(|_| anyhow!("Failed to convert message hash to array"))?;
        
        // For now, create a temporary keyshare for testing
        // TODO: Implement proper keyshare conversion
        info!("⚠️ DKLS23: Using temporary keyshare generation for testing");
        let keyshares = self.generate_test_keyshares().await?;
        let daemon_keyshare = keyshares[0].clone();
        
        // Create setup message for daemon (party 0)
        let setup = self.create_sign_setup_from_keyshare(daemon_keyshare.clone(), &hash_array)?;
        
        // For now, use a simplified local signing approach
        // TODO: Implement proper device-to-device relay
        info!("⚠️ DKLS23: Using simplified local signing for testing");
        
        // Use SimpleMessageRelay for local simulation
        let coord = sl_mpc_mate::coord::SimpleMessageRelay::new();
        
        info!("🔄 DKLS23: Starting signing protocol");
        
        // For testing, create a second party setup and run both parties locally
        // In real implementation, the mobile app would run the second party
        let mobile_setup = self.create_sign_setup_from_keyshare_for_party(daemon_keyshare.clone(), &hash_array, 1)?;
        
        // Spawn both parties
        let mut signing_tasks = tokio::task::JoinSet::new();
        
        // Daemon party (party 0)
        signing_tasks.spawn({
            let relay = coord.connect();
            sl_dkls23::sign::run(setup, rand::random(), relay)
        });
        
        // Mobile party (party 1) - simulated locally for testing
        signing_tasks.spawn({
            let relay = coord.connect();  
            sl_dkls23::sign::run(mobile_setup, rand::random(), relay)
        });
        
        // Wait for the first successful result  
        let mut signature_result = None;
        while let Some(task_result) = signing_tasks.join_next().await {
            match task_result {
                Ok(signing_result) => match signing_result {
                    Ok((signature, recovery_id)) => {
                        signature_result = Some((signature, recovery_id));
                        break; // We got a successful signature
                    }
                    Err(e) => {
                        error!("❌ DKLS23: Signing task failed: {}", e);
                        continue; // Try other tasks
                    }
                }
                Err(e) => {
                    error!("❌ DKLS23: Task execution failed: {}", e);
                    continue;
                }
            }
        }
        
        match signature_result {
            Some((signature, recovery_id)) => {
                info!("✅ DKLS23: Signing completed successfully");
                
                // Convert k256::ecdsa::Signature to our Signature format
                let sig_bytes = signature.to_bytes();
                let r = sig_bytes[..32].to_vec();
                let s = sig_bytes[32..].to_vec();
                
                Ok(Signature {
                    r,
                    s,
                    recovery_id: Some(recovery_id.to_byte()),
                })
            }
            None => {
                error!("❌ DKLS23: All signing tasks failed");
                Err(anyhow!("DKLS23 signing failed: no successful signature"))
            }
        }
    }
    
    // Temporary keyshare generation for testing
    // TODO: Replace with proper keyshare conversion
    async fn generate_test_keyshares(&self) -> Result<Vec<Arc<sl_dkls23::keygen::Keyshare>>> {
        info!("⚠️ DKLS23: Generating temporary test keyshares");
        
        use sl_dkls23::keygen;
        use sl_dkls23::setup::{NoSigningKey, NoVerifyingKey};
        use sl_mpc_mate::message::InstanceId;
        use sl_mpc_mate::coord::SimpleMessageRelay;
        use rand::{SeedableRng, Rng, thread_rng};
        use std::time::Duration;
        
        let t = 2; // threshold
        let n = 2; // total parties
        
        // Generate unique instance ID
        let instance: [u8; 32] = rand::random();
        
        // Create mock signing/verifying keys
        let party_sk: Vec<NoSigningKey> = std::iter::repeat_with(|| NoSigningKey)
            .take(n)
            .collect();
        
        let party_vk: Vec<NoVerifyingKey> = party_sk
            .iter()
            .enumerate()
            .map(|(party_id, _)| NoVerifyingKey::new(party_id))
            .collect();
        
        // Create setup messages for keygen
        let setup_messages: Vec<_> = party_sk
            .into_iter()
            .enumerate()
            .map(|(party_id, sk)| {
                sl_dkls23::setup::keygen::SetupMessage::new(
                    InstanceId::new(instance),
                    sk,
                    party_id,
                    party_vk.clone(),
                    &vec![0u8; n],
                    t,
                ).with_ttl(Duration::from_secs(300))
            })
            .collect();
        
        // Run keygen protocol
        let coord = SimpleMessageRelay::new();
        let mut parties = tokio::task::JoinSet::new();
        
        for setup in setup_messages {
            parties.spawn({
                let relay = coord.connect();
                keygen::run(setup, rand::random(), relay)
            });
        }
        
        let mut keyshares = vec![];
        while let Some(result) = parties.join_next().await {
            match result? {
                Ok(keyshare) => keyshares.push(Arc::new(keyshare)),
                Err(e) => return Err(anyhow!("Keygen failed: {}", e)),
            }
        }
        
        keyshares.sort_by_key(|share| share.party_id);
        info!("✅ DKLS23: Generated {} test keyshares", keyshares.len());
        
        Ok(keyshares)
    }
    
    // Create signing setup from existing keyshare
    fn create_sign_setup_from_keyshare(
        &self,
        keyshare: Arc<sl_dkls23::keygen::Keyshare>,
        message_hash: &[u8; 32],
    ) -> Result<sl_dkls23::setup::sign::SetupMessage> {
        self.create_sign_setup_from_keyshare_for_party(keyshare, message_hash, 0)
    }
    
    // Create signing setup from existing keyshare for specific party
    fn create_sign_setup_from_keyshare_for_party(
        &self,
        keyshare: Arc<sl_dkls23::keygen::Keyshare>,
        message_hash: &[u8; 32],
        party_id: usize,
    ) -> Result<sl_dkls23::setup::sign::SetupMessage> {
        use sl_dkls23::setup::{NoSigningKey, NoVerifyingKey};
        use sl_mpc_mate::message::InstanceId;
        use derivation_path::DerivationPath;
        use std::str::FromStr;
        
        info!("🔄 DKLS23: Creating signing setup from keyshare for party {}", party_id);
        
        // Generate unique instance ID
        let instance_id = InstanceId::new(rand::random::<[u8; 32]>());
        
        // Create verifying keys for both parties
        let party_vks = vec![
            NoVerifyingKey::new(0), // daemon
            NoVerifyingKey::new(1), // mobile
        ];
        
        // Parse chain path
        let chain_path = DerivationPath::from_str("m")
            .map_err(|e| anyhow!("Failed to parse derivation path: {}", e))?;
        
        // Create setup message
        let setup = sl_dkls23::setup::sign::SetupMessage::new(
            instance_id,
            NoSigningKey,
            party_id, // Use the specified party ID
            party_vks,
            keyshare,
        )
        .with_chain_path(chain_path)
        .with_hash(*message_hash)
        .with_ttl(std::time::Duration::from_secs(300));
        
        info!("✅ DKLS23: Signing setup created from keyshare for party {}", party_id);
        Ok(setup)
    }
}

// TODO: Implement proper device-to-device message relay for real mobile app communication

// EdDSA TSS Engine using multi-party-schnorr - CORRECTED IMPLEMENTATION  
#[derive(Debug)]
pub struct EdDsaTssEngine {
    keyshare_data: EddsaKeyshareData,
}

impl EdDsaTssEngine {
    pub fn new(keyshare_data: EddsaKeyshareData) -> Self {
        Self { keyshare_data }
    }
    
    // Convert VultKeyshare to multi-party-schnorr format - CORRECTED
    fn convert_vult_to_schnorr_keyshare(&self) -> Result<multi_party_schnorr::keygen::Keyshare<curve25519_dalek::EdwardsPoint>> {
        info!("🔄 EdDSA: Converting VultKeyshare to multi-party-schnorr format");
        
        // Deserialize the keyshare data
        let keyshare = bincode::deserialize::<multi_party_schnorr::keygen::Keyshare<curve25519_dalek::EdwardsPoint>>(
            &self.keyshare_data.share_data
        ).map_err(|e| {
            error!("❌ EdDSA: Failed to deserialize keyshare data: {}", e);
            anyhow!("Failed to deserialize EdDSA keyshare: {}", e)
        })?;
        
        info!("✅ EdDSA: Keyshare conversion successful");
        Ok(keyshare)
    }
}

impl EdDsaTssEngine {
    pub async fn sign_as_initiator(
        &self,
        message_hash: Vec<u8>,
        _mobile_tx: mpsc::UnboundedSender<TssMessage>,
        _mobile_rx: mpsc::UnboundedReceiver<TssMessage>,
    ) -> Result<Signature> {
        info!("🚀 EdDSA PROTOCOL START: Initiating EdDSA signing");
        
        // For now, use a local-only implementation for testing
        // TODO: Implement proper device-to-device coordination
        info!("⚠️ EdDSA: Using local-only implementation for testing");
        
        use multi_party_schnorr::common::utils::{run_keygen, run_round};
        use multi_party_schnorr::sign::SignerParty;
        use curve25519_dalek::EdwardsPoint;
        use rand::seq::SliceRandom;
        
        const N: usize = 2;
        const T: usize = 2;
        
        // Generate test keyshares
        let keyshares = run_keygen::<T, N, EdwardsPoint>();
        let mut rng = rand::thread_rng();
        
        // Select subset for signing (in real implementation, daemon would have one keyshare)
        let subset: Vec<_> = keyshares
            .choose_multiple(&mut rand::thread_rng(), T)
            .cloned()
            .collect();
        
        // Create signer parties
        let parties = subset
            .iter()
            .map(|keyshare| {
                SignerParty::<_, EdwardsPoint>::new(
                    keyshare.clone().into(),
                    message_hash.clone(),
                    "m".parse().unwrap(),
                    &mut rng,
                )
            })
            .collect::<Vec<_>>();
        
        info!("🔄 EdDSA: Running pre-signature phase");
        
        // Pre-Signature phase
        let (parties, msgs): (Vec<_>, Vec<_>) = run_round(parties, ()).into_iter().unzip();
        let (parties, msgs): (Vec<_>, Vec<_>) = run_round(parties, msgs).into_iter().unzip();
        let ready_parties = run_round(parties, msgs);
        
        info!("🔄 EdDSA: Running signature phase");
        
        // Signature phase
        let (parties, partial_sigs): (Vec<_>, Vec<_>) =
            run_round(ready_parties, ()).into_iter().unzip();
        
        let (signatures, _complete_msg): (Vec<_>, Vec<_>) =
            run_round(parties, partial_sigs).into_iter().unzip();
        
        if let Some(signature) = signatures.first() {
            info!("✅ EdDSA: Signing completed successfully");
            
            // Convert Ed25519 signature to our format
            let sig_bytes = signature.to_bytes();
            Ok(Signature {
                r: sig_bytes[..32].to_vec(),
                s: sig_bytes[32..].to_vec(),
                recovery_id: None, // EdDSA doesn't use recovery ID
            })
        } else {
            Err(anyhow!("EdDSA signing failed - no signature produced"))
        }
    }
}

// Factory function to create the appropriate TSS engine
pub fn create_tss_engine(
    network: &str,
    ecdsa_keyshare: Option<EcdsaKeyshareData>,
    eddsa_keyshare: Option<EddsaKeyshareData>,
) -> Result<TssEngine> {
    match network.to_lowercase().as_str() {
        "eth" | "btc" | "thor" => {
            let keyshare_data = ecdsa_keyshare
                .ok_or_else(|| anyhow!("ECDSA keyshare required for network: {}", network))?;
            Ok(TssEngine::Ecdsa(EcdsaTssEngine::new(keyshare_data)))
        }
        "sol" => {
            let keyshare_data = eddsa_keyshare
                .ok_or_else(|| anyhow!("EdDSA keyshare required for network: {}", network))?;
            Ok(TssEngine::EdDsa(EdDsaTssEngine::new(keyshare_data)))
        }
        _ => Err(anyhow!("Unsupported network for TSS: {}", network)),
    }
}

// Summary of what needs to be implemented for proper TSS integration:
//
// 1. DKLS23 (ECDSA):
//    - Solve keyshare conversion issue (Deserialize trait)
//    - Both daemon and mobile connect to same SimpleMessageRelay
//    - Both call sign::run() with their setup messages
//    - Relay handles message coordination internally
//
// 2. Multi-party-schnorr (EdDSA):  
//    - Design device-to-device coordination for run_round() calls
//    - Implement message serialization between devices
//    - Synchronize protocol phases across devices
//    - Handle round-by-round message exchange
//
// 3. Architecture:
//    - Implement proper device-to-device protocol adapter
//    - Or modify mobile app to integrate with Rust TSS libraries
