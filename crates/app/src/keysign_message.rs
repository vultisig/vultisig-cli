use anyhow::{anyhow, Result};
use base64::Engine;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// Keysign message structure for QR code generation
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct KeysignMessage {
    pub session_id: String,
    pub service_name: String,
    pub payload: Option<KeysignPayload>,
    pub custom_message_payload: Option<CustomMessagePayload>,
    pub encryption_key_hex: String,
    pub use_vultisig_relay: bool,  // Key field for local vs relay
    pub payload_id: String,
}

/// Transaction payload for signing
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct KeysignPayload {
    pub coin: Coin,
    pub to_address: String,
    pub to_amount: String,
    pub chain_specific: BlockChainSpecific,
    pub utxos: Vec<UtxoInfo>,
    pub memo: Option<String>,
    pub swap_payload: Option<SwapPayload>,
    pub approve_payload: Option<ApprovePayload>,
    pub vault_pub_key_ecdsa: String,
    pub vault_local_party_id: String,
    pub lib_type: String,
}

/// Custom message payload (for message signing)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CustomMessagePayload {
    pub message: String,
    pub method: String,
}

/// Coin information
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Coin {
    pub chain: String,
    pub ticker: String,
    pub address: String,
    pub decimals: u32,
    pub hex_public_key: String,
    pub is_native_token: bool,
    pub contract_address: Option<String>,
    pub price_provider_id: Option<String>,
}

/// Blockchain-specific transaction data
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BlockChainSpecific {
    // Ethereum specific
    pub max_fee_per_gas_wei: Option<String>,
    pub priority_fee_wei: Option<String>,
    pub nonce: Option<u64>,
    pub gas_limit: Option<u64>,
    
    // Bitcoin specific
    pub bytes_fee: Option<String>,
    
    // Solana specific
    pub recent_block_hash: Option<String>,
    pub priority_fee: Option<String>,
    
    // THORChain/Cosmos specific
    pub account_number: Option<String>,
    pub sequence: Option<String>,
    pub fee: Option<String>,
    pub gas: Option<String>,
    pub from_address: Option<String>,
    pub is_deposit: Option<bool>,
}

/// UTXO for Bitcoin transactions
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct UtxoInfo {
    pub hash: String,
    pub amount: String,
    pub index: u32,
}

/// Swap payload for DEX transactions
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SwapPayload {
    pub from_coin: Coin,
    pub to_coin: Coin,
    pub router_address: String,
    pub expected_amount_out: String,
}

/// Approve payload for token approvals
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ApprovePayload {
    pub spender: String,
    pub amount: String,
}

/// Keygen message structure for vault creation
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct KeygenMessage {
    pub session_id: String,
    pub hex_chain_code: String,
    pub service_name: String,
    pub encryption_key_hex: String,
    pub use_vultisig_relay: bool,
    pub vault_name: String,
    pub lib_type: LibType,
}

/// Reshare message structure for vault resharing
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ReshareMessage {
    pub session_id: String,
    pub hex_chain_code: String,
    pub service_name: String,
    pub pub_key_ecdsa: String,
    pub old_parties: Vec<String>,
    pub encryption_key_hex: String,
    pub use_vultisig_relay: bool,
    pub old_reshare_prefix: String,
    pub vault_name: String,
    pub lib_type: LibType,
}

/// Network mode enumeration
#[derive(Debug, Clone)]
pub enum NetworkMode {
    Local,
    Relay,
}

/// TSS type enumeration
#[derive(Debug, Clone)]
pub enum TssType {
    Keygen,
    Reshare,
}

impl TssType {
    pub fn as_str(&self) -> &'static str {
        match self {
            TssType::Keygen => "Keygen",
            TssType::Reshare => "Reshare",
        }
    }
}

/// Library type enumeration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum LibType {
    #[serde(rename = "GG20")]
    GG20,
    #[serde(rename = "DKLS")]
    DKLS,
}

/// Vultisig QR Generator
pub struct VultisigQRGenerator {
    pub vault_ecdsa_pubkey: String,
}

impl VultisigQRGenerator {
    /// Create a new QR generator with vault ECDSA public key
    pub fn new(vault_ecdsa_pubkey: String) -> Self {
        Self { vault_ecdsa_pubkey }
    }

    /// Generate QR code URL for transaction signing
    pub fn generate_keysign_qr(
        &self,
        payload: KeysignPayload,
        mode: NetworkMode,
        session_id: Option<String>,
        service_name: Option<String>,
    ) -> Result<String> {
        
        // Generate session ID if not provided
        let session_id = session_id.unwrap_or_else(|| Uuid::new_v4().to_string());
        
        // Generate service name if not provided
        let service_name = service_name.unwrap_or_else(|| {
            format!("Vultisig-{}", rand::random::<u16>() % 1000)
        });
        
        // Generate encryption key (32 bytes hex)
        let encryption_key = self.generate_encryption_key();
        
        // Create keysign message
        let message = KeysignMessage {
            session_id,
            service_name,
            payload: Some(payload),
            custom_message_payload: None,
            encryption_key_hex: encryption_key,
            use_vultisig_relay: matches!(mode, NetworkMode::Relay),
            payload_id: String::new(),
        };
        
        // Serialize to JSON and base64 encode
        let json_data = self.serialize_to_base64(&message)?;
        
        // Create the QR code URL
        let qr_url = format!(
            "vultisig://vultisig.com?type=SignTransaction&vault={}&jsonData={}",
            self.vault_ecdsa_pubkey,
            json_data
        );
        
        Ok(qr_url)
    }

    /// Generate QR code URL for custom message signing
    pub fn generate_message_sign_qr(
        &self,
        message: String,
        method: String,
        mode: NetworkMode,
        session_id: Option<String>,
        service_name: Option<String>,
    ) -> Result<String> {
        
        let session_id = session_id.unwrap_or_else(|| Uuid::new_v4().to_string());
        let service_name = service_name.unwrap_or_else(|| "Vultisig-CLI".to_string());
        let encryption_key = self.generate_encryption_key();
        
        let keysign_message = KeysignMessage {
            session_id,
            service_name,
            payload: None,
            custom_message_payload: Some(CustomMessagePayload { message, method }),
            encryption_key_hex: encryption_key,
            use_vultisig_relay: matches!(mode, NetworkMode::Relay),
            payload_id: String::new(),
        };
        
        let json_data = self.serialize_to_base64(&keysign_message)?;
        
        let qr_url = format!(
            "vultisig://vultisig.com?type=SignTransaction&vault={}&jsonData={}",
            self.vault_ecdsa_pubkey,
            json_data
        );
        
        Ok(qr_url)
    }
    
    // Note: Keygen QR generation removed - only focusing on signing functionality
    
    // Private helper methods
    fn generate_encryption_key(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(Uuid::new_v4().as_bytes());
        let result = hasher.finalize();
        hex::encode(result)
    }
    
    fn serialize_to_base64<T: Serialize>(&self, message: &T) -> Result<String> {
        let json = serde_json::to_string(message)
            .map_err(|e| anyhow!("Failed to serialize message: {}", e))?;
        Ok(base64::engine::general_purpose::STANDARD.encode(json.as_bytes()))
    }
}

/// Helper function to create Ethereum transaction payload
pub fn create_eth_transaction_payload(
    to_address: &str,
    value: &str,
    nonce: u64,
    gas_limit: u64,
    max_fee_per_gas: &str,
    max_priority_fee_per_gas: &str,
    vault_public_key: &str,
    vault_address: &str,
) -> KeysignPayload {
    KeysignPayload {
        coin: Coin {
            chain: "ETH".to_string(),
            ticker: "ETH".to_string(),
            address: vault_address.to_string(),
            decimals: 18,
            hex_public_key: vault_public_key.to_string(),
            is_native_token: true,
            contract_address: None,
            price_provider_id: Some("ethereum".to_string()),
        },
        to_address: to_address.to_string(),
        to_amount: value.to_string(),
        chain_specific: BlockChainSpecific {
            max_fee_per_gas_wei: Some(max_fee_per_gas.to_string()),
            priority_fee_wei: Some(max_priority_fee_per_gas.to_string()),
            nonce: Some(nonce),
            gas_limit: Some(gas_limit),
            bytes_fee: None,
            recent_block_hash: None,
            priority_fee: None,
            account_number: None,
            sequence: None,
            fee: None,
            gas: None,
            from_address: Some(vault_address.to_string()),
            is_deposit: Some(false),
        },
        utxos: vec![],
        memo: None,
        swap_payload: None,
        approve_payload: None,
        vault_pub_key_ecdsa: vault_public_key.to_string(),
        vault_local_party_id: "device-1".to_string(),
        lib_type: "GG20".to_string(),
    }
}

// Add rand dependency for random service names
// use rand::Rng;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keysign_qr_generation() {
        let vault_pubkey = "023e4b76861289ad4528b33c2fd21b3a5160cd37b3294234914e21efb6ed4a452b";
        let qr_gen = VultisigQRGenerator::new(vault_pubkey.to_string());
        
        let payload = create_eth_transaction_payload(
            "0x742d35Cc6634C0532925a3b8D45C0D2C0d0Db8f7",
            "1000000000000000000", // 1 ETH in wei
            1,
            21000,
            "25000000000", // 25 gwei
            "1000000000", // 1 gwei
            vault_pubkey,
            "0x1234567890123456789012345678901234567890",
        );
        
        // Test relay mode
        let relay_qr = qr_gen.generate_keysign_qr(
            payload.clone(),
            NetworkMode::Relay,
            Some("test-session-123".to_string()),
            Some("Vultisig-Test".to_string()),
        ).unwrap();
        
        assert!(relay_qr.starts_with("vultisig://vultisig.com?type=SignTransaction"));
        assert!(relay_qr.contains("vault=023e4b76861289ad4528b33c2fd21b3a5160cd37b3294234914e21efb6ed4a452b"));
        assert!(relay_qr.contains("jsonData="));
        
        // Test local mode
        let local_qr = qr_gen.generate_keysign_qr(
            payload,
            NetworkMode::Local,
            None,
            None,
        ).unwrap();
        
        assert!(local_qr.starts_with("vultisig://vultisig.com?type=SignTransaction"));
    }

    // Note: Keygen test removed since we only need signing functionality

    #[test]
    fn test_message_signing_qr() {
        let vault_pubkey = "023e4b76861289ad4528b33c2fd21b3a5160cd37b3294234914e21efb6ed4a452b";
        let qr_gen = VultisigQRGenerator::new(vault_pubkey.to_string());
        
        let message_qr = qr_gen.generate_message_sign_qr(
            "Hello, Vultisig!".to_string(),
            "personal_sign".to_string(),
            NetworkMode::Local,
            None,
            None,
        ).unwrap();
        
        assert!(message_qr.starts_with("vultisig://vultisig.com?type=SignTransaction"));
        assert!(message_qr.contains("vault=023e4b76861289ad4528b33c2fd21b3a5160cd37b3294234914e21efb6ed4a452b"));
    }
}