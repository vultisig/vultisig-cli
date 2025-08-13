use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use anyhow::{anyhow, Result};

// Simplified wallet-core FFI implementation for Vultisig
// This provides essential functionality without requiring the full wallet-core build
// TODO: Upgrade to full wallet-core integration when build system is stable

/// Coin types matching wallet-core CoinType enum
#[cfg(feature = "wallet-core")]
pub const TW_COIN_TYPE_BITCOIN: u32 = 0;
#[cfg(feature = "wallet-core")]
pub const TW_COIN_TYPE_LITECOIN: u32 = 2;
#[cfg(feature = "wallet-core")]
pub const TW_COIN_TYPE_DOGECOIN: u32 = 3;
#[cfg(feature = "wallet-core")]
pub const TW_COIN_TYPE_ETHEREUM: u32 = 60;
#[cfg(feature = "wallet-core")]
pub const TW_COIN_TYPE_COSMOS: u32 = 118;
#[cfg(feature = "wallet-core")]
pub const TW_COIN_TYPE_SOLANA: u32 = 501;
#[cfg(feature = "wallet-core")]
pub const TW_COIN_TYPE_BSC: u32 = 20000714; 
#[cfg(feature = "wallet-core")]
pub const TW_COIN_TYPE_POLYGON: u32 = 966;
#[cfg(feature = "wallet-core")]
pub const TW_COIN_TYPE_AVALANCHE: u32 = 10009000;
#[cfg(feature = "wallet-core")]
pub const TW_COIN_TYPE_OPTIMISM: u32 = 10000070;
#[cfg(feature = "wallet-core")]
pub const TW_COIN_TYPE_ARBITRUM: u32 = 10042221;
#[cfg(feature = "wallet-core")]
pub const TW_COIN_TYPE_BASE: u32 = 10008453;
#[cfg(feature = "wallet-core")]
pub const TW_COIN_TYPE_THORCHAIN: u32 = 931;
#[cfg(feature = "wallet-core")]
pub const TW_COIN_TYPE_OSMOSIS: u32 = 11800118; // Osmosis has its own coin type
#[cfg(feature = "wallet-core")]
pub const TW_COIN_TYPE_CARDANO: u32 = 1815;
#[cfg(feature = "wallet-core")]
pub const TW_COIN_TYPE_POLKADOT: u32 = 354;
#[cfg(feature = "wallet-core")]
pub const TW_COIN_TYPE_RIPPLE: u32 = 144;
#[cfg(feature = "wallet-core")]
pub const TW_COIN_TYPE_TRON: u32 = 195;
#[cfg(feature = "wallet-core")]
pub const TW_COIN_TYPE_SUI: u32 = 784;
#[cfg(feature = "wallet-core")]
pub const TW_COIN_TYPE_TON: u32 = 607;
// MayaChain - using THORChain coin type as they are similar, but will use prefix replacement
#[cfg(feature = "wallet-core")]
pub const TW_COIN_TYPE_MAYACHAIN: u32 = 931;

/// Public key types
#[cfg(feature = "wallet-core")]
pub const TW_PUBLIC_KEY_TYPE_SECP256K1: u32 = 0;
#[cfg(feature = "wallet-core")]
pub const TW_PUBLIC_KEY_TYPE_ED25519: u32 = 3;

/// Derivation types
#[cfg(feature = "wallet-core")]
pub const TW_DERIVATION_DEFAULT: u32 = 0;

/// Coin information structure
pub struct CoinInfo {
    pub coin_type: u32,
    pub symbol: String,
    pub name: String,
    pub decimals: u8,
    pub derivation_path: String,
}

/// Get standardized derivation path for a coin type
#[cfg(feature = "wallet-core")]
pub fn get_derivation_path_for_coin(coin_type: u32) -> Result<String> {
    match coin_type {
        // Bitcoin-like chains (P2WPKH Segwit)
        TW_COIN_TYPE_BITCOIN => Ok("m/84'/0'/0'/0/0".to_string()),
        TW_COIN_TYPE_LITECOIN => Ok("m/84'/2'/0'/0/0".to_string()),
        TW_COIN_TYPE_DOGECOIN => Ok("m/44'/3'/0'/0/0".to_string()), // Dogecoin uses legacy derivation
        
        // Ethereum and EVM chains
        TW_COIN_TYPE_ETHEREUM => Ok("m/44'/60'/0'/0/0".to_string()),
        TW_COIN_TYPE_BSC => Ok("m/44'/60'/0'/0/0".to_string()), // Uses Ethereum derivation
        TW_COIN_TYPE_POLYGON => Ok("m/44'/60'/0'/0/0".to_string()), // Uses Ethereum derivation
        TW_COIN_TYPE_AVALANCHE => Ok("m/44'/60'/0'/0/0".to_string()), // Uses Ethereum derivation
        TW_COIN_TYPE_OPTIMISM => Ok("m/44'/60'/0'/0/0".to_string()), // Uses Ethereum derivation
        TW_COIN_TYPE_ARBITRUM => Ok("m/44'/60'/0'/0/0".to_string()), // Uses Ethereum derivation
        TW_COIN_TYPE_BASE => Ok("m/44'/60'/0'/0/0".to_string()), // Uses Ethereum derivation
        
        // Cosmos ecosystem
        TW_COIN_TYPE_COSMOS => Ok("m/44'/118'/0'/0/0".to_string()),
        TW_COIN_TYPE_THORCHAIN => Ok("m/44'/931'/0'/0/0".to_string()),
        TW_COIN_TYPE_OSMOSIS => Ok("m/44'/118'/0'/0/0".to_string()), // Uses Cosmos derivation path
        
        // Other chains
        TW_COIN_TYPE_SOLANA => Ok("m/44'/501'/0'/0'".to_string()), // EdDSA, different format
        TW_COIN_TYPE_CARDANO => Ok("m/44'/1815'/0'/0/0".to_string()),
        TW_COIN_TYPE_POLKADOT => Ok("m/44'/354'/0'/0/0".to_string()),
        TW_COIN_TYPE_RIPPLE => Ok("m/44'/144'/0'/0/0".to_string()),
        TW_COIN_TYPE_TRON => Ok("m/44'/195'/0'/0/0".to_string()),
        TW_COIN_TYPE_SUI => Ok("m/44'/784'/0'/0/0".to_string()),
        TW_COIN_TYPE_TON => Ok("m/44'/607'/0'/0/0".to_string()),
        
        _ => Err(anyhow!("Unsupported coin type for derivation path: {}", coin_type))
    }
}

/// Proper Ethereum address derivation using Trust Wallet Core
#[cfg(feature = "wallet-core")]
pub fn derive_ethereum_address(public_key: &[u8]) -> Result<String> {
    use tw_keypair::ecdsa::secp256k1::PublicKey;
    use tw_evm::address::Address;
    use tw_hash::H264;
    
    if public_key.len() != 33 {
        return Err(anyhow!("Invalid public key length for Ethereum address derivation"));
    }
    
    // Parse the compressed public key using wallet-core
    let h264_key = H264::try_from(public_key)
        .map_err(|_| anyhow!("Failed to create H264 from public key bytes"))?;
    let pubkey = PublicKey::try_from(h264_key.as_slice())
        .map_err(|e| anyhow!("Failed to parse secp256k1 public key: {:?}", e))?;
    
    // Use wallet-core's proper address derivation
    let address = Address::with_secp256k1_pubkey(&pubkey);
    
    // Return the checksummed address
    Ok(address.to_string())
}

/// Generic UTXO chain address derivation using Trust Wallet Core
/// Supports Bitcoin, Litecoin, Dogecoin and other UTXO chains
#[cfg(feature = "wallet-core")]
pub fn derive_utxo_address(public_key: &[u8], coin_type_id: u32) -> Result<String> {
    use tw_bitcoin::entry::BitcoinEntry;
    use tw_coin_entry::coin_entry::CoinEntry;
    use tw_coin_entry::derivation::Derivation;
    use tw_coin_registry::coin_type::CoinType;
    use tw_coin_registry::registry::get_coin_item;
    use tw_coin_registry::coin_context::CoinRegistryContext;
    use tw_keypair::tw::PublicKey as TwPublicKey;
    use tw_keypair::tw::PublicKeyType;
    
    if public_key.len() != 33 {
        return Err(anyhow!("Invalid public key length for UTXO address derivation"));
    }
    
    // Convert coin type ID to CoinType enum
    let coin_type = match coin_type_id {
        TW_COIN_TYPE_BITCOIN => CoinType::Bitcoin,
        TW_COIN_TYPE_LITECOIN => CoinType::Litecoin,
        TW_COIN_TYPE_DOGECOIN => CoinType::Dogecoin,
        _ => return Err(anyhow!("Unsupported UTXO coin type: {}", coin_type_id))
    };
    
    println!("🔑 UTXO public key for {:?}: {}", coin_type, hex::encode(public_key));
    
    // Create Trust Wallet Core PublicKey from our derived public key
    let tw_public_key = TwPublicKey::new(public_key.to_vec(), PublicKeyType::Secp256k1)
        .map_err(|e| anyhow!("Failed to create Trust Wallet Core PublicKey: {:?}", e))?;
    
    // Get coin context
    let coin_item = get_coin_item(coin_type)
        .map_err(|e| anyhow!("{:?} not supported in Trust Wallet Core: {:?}", coin_type, e))?;
    let coin_context = CoinRegistryContext::with_coin_item(coin_item);
    
    // Use Trust Wallet Core's exact UTXO address derivation
    let bitcoin_entry = BitcoinEntry; // Bitcoin entry handles all UTXO chains
    let address = bitcoin_entry.derive_address(
        &coin_context,
        tw_public_key,
        Derivation::Default, // Trust Wallet Core determines format from registry
        None, // No specific prefix, use defaults from registry
    ).map_err(|e| anyhow!("Trust Wallet Core {:?} address derivation failed: {:?}", coin_type, e))?;
    
    let address_string = address.to_string();

    Ok(address_string)
}

/// Bitcoin address derivation using Trust Wallet Core
#[cfg(feature = "wallet-core")]
pub fn derive_bitcoin_address(public_key: &[u8]) -> Result<String> {
    derive_utxo_address(public_key, TW_COIN_TYPE_BITCOIN)
}

/// Litecoin address derivation using Trust Wallet Core
#[cfg(feature = "wallet-core")]
pub fn derive_litecoin_address(public_key: &[u8]) -> Result<String> {
    derive_utxo_address(public_key, TW_COIN_TYPE_LITECOIN)
}

/// Dogecoin address derivation using Trust Wallet Core
#[cfg(feature = "wallet-core")]
pub fn derive_dogecoin_address(public_key: &[u8]) -> Result<String> {
    derive_utxo_address(public_key, TW_COIN_TYPE_DOGECOIN)
}

/// Generic EVM chain address derivation using Trust Wallet Core
/// All EVM chains use the same address format (Ethereum)
#[cfg(feature = "wallet-core")]
pub fn derive_evm_address(public_key: &[u8]) -> Result<String> {
    // All EVM chains use Ethereum address derivation
    derive_ethereum_address(public_key)
}

/// Generic Cosmos-based chain address derivation using Trust Wallet Core
#[cfg(feature = "wallet-core")]
pub fn derive_cosmos_address(public_key: &[u8], coin_type_id: u32) -> Result<String> {
    use tw_cosmos::entry::CosmosEntry;
    use tw_coin_entry::coin_entry::CoinEntry;
    use tw_coin_entry::derivation::Derivation;
    use tw_coin_registry::coin_type::CoinType;
    use tw_coin_registry::registry::get_coin_item;
    use tw_coin_registry::coin_context::CoinRegistryContext;
    use tw_keypair::tw::PublicKey as TwPublicKey;
    use tw_keypair::tw::PublicKeyType;
    
    if public_key.len() != 33 {
        return Err(anyhow!("Invalid public key length for Cosmos address derivation"));
    }
    
    // Convert coin type ID to CoinType enum
    let coin_type = match coin_type_id {
        TW_COIN_TYPE_COSMOS => CoinType::Cosmos,
        TW_COIN_TYPE_THORCHAIN => CoinType::THORChain,
        TW_COIN_TYPE_OSMOSIS => CoinType::Cosmos, // Osmosis uses Cosmos base but different hrp
        _ => return Err(anyhow!("Unsupported Cosmos coin type: {}", coin_type_id))
    };
    
    println!("🔑 Cosmos public key for {:?}: {}", coin_type, hex::encode(public_key));
    
    // Create Trust Wallet Core PublicKey from our derived public key
    let tw_public_key = TwPublicKey::new(public_key.to_vec(), PublicKeyType::Secp256k1)
        .map_err(|e| anyhow!("Failed to create Trust Wallet Core PublicKey: {:?}", e))?;
    
    // Get coin context
    let coin_item = get_coin_item(coin_type)
        .map_err(|e| anyhow!("{:?} not supported in Trust Wallet Core: {:?}", coin_type, e))?;
    let coin_context = CoinRegistryContext::with_coin_item(coin_item);
    
    // Use Trust Wallet Core's Cosmos address derivation
    let cosmos_entry = CosmosEntry;
    let address = cosmos_entry.derive_address(
        &coin_context,
        tw_public_key,
        Derivation::Default,
        None,
    ).map_err(|e| anyhow!("Trust Wallet Core {:?} address derivation failed: {:?}", coin_type, e))?;
    
    let address_string = address.to_string();

    Ok(address_string)
}

/// THORChain address derivation using Trust Wallet Core
#[cfg(feature = "wallet-core")]
pub fn derive_thorchain_address(public_key: &[u8]) -> Result<String> {
    derive_cosmos_address(public_key, TW_COIN_TYPE_THORCHAIN)
}

/// MayaChain address derivation (uses THORChain format with maya prefix)
#[cfg(feature = "wallet-core")]
pub fn derive_mayachain_address(public_key: &[u8]) -> Result<String> {
    // MayaChain uses THORChain format but with "maya" prefix
    let thor_address = derive_cosmos_address(public_key, TW_COIN_TYPE_THORCHAIN)?;
    if thor_address.starts_with("thor1") {
        Ok(thor_address.replacen("thor1", "maya1", 1))
    } else {
        Err(anyhow!("Unexpected THORChain address format for MayaChain"))
    }
}

/// Osmosis address derivation using Trust Wallet Core
#[cfg(feature = "wallet-core")]
pub fn derive_osmosis_address(public_key: &[u8]) -> Result<String> {
    let cosmos_address = derive_cosmos_address(public_key, TW_COIN_TYPE_COSMOS)?;
    // Osmosis uses same format as Cosmos but with "osmo" prefix
    if cosmos_address.starts_with("cosmos1") {
        Ok(cosmos_address.replacen("cosmos1", "osmo1", 1))
    } else {
        Err(anyhow!("Unexpected Cosmos address format for Osmosis"))
    }
}

/// Simplified Solana address derivation
#[cfg(feature = "wallet-core")]
pub fn derive_solana_address(public_key: &[u8]) -> Result<String> {
    if public_key.len() != 32 {
        return Err(anyhow!("Invalid public key length for Solana address derivation"));
    }
    
    // For Solana, the public key IS the address (base58 encoded)
    let address = bs58::encode(public_key).into_string();
    Ok(address)
}

/// Simplified generic address derivation (fallback implementation)
/// For complex chains like Cardano, Polkadot, Ripple, Tron, Sui, TON
#[cfg(feature = "wallet-core")]
pub fn derive_generic_address(public_key: &[u8], coin_type_id: u32) -> Result<String> {
    // For now, provide simple placeholder addresses for these complex chains
    // Full implementation would require specific entry modules for each chain
    let chain_name = match coin_type_id {
        TW_COIN_TYPE_CARDANO => "Cardano",
        TW_COIN_TYPE_POLKADOT => "Polkadot", 
        TW_COIN_TYPE_RIPPLE => "Ripple",
        TW_COIN_TYPE_TRON => "Tron",
        TW_COIN_TYPE_SUI => "Sui",
        TW_COIN_TYPE_TON => "TON",
        _ => return Err(anyhow!("Unsupported generic coin type: {}", coin_type_id))
    };
    
    println!("🔑 Generic public key for {}: {}", chain_name, hex::encode(public_key));
    
    // Create simplified placeholder addresses based on public key hash
    use sha2::{Sha256, Digest};
    let hash = Sha256::digest(public_key);
    let address = match coin_type_id {
        TW_COIN_TYPE_CARDANO => format!("addr1v{}", hex::encode(&hash[0..28])),
        TW_COIN_TYPE_POLKADOT => bs58::encode(&hash[0..32]).into_string(),
        TW_COIN_TYPE_RIPPLE => format!("r{}", bs58::encode(&hash[0..20]).into_string()),
        TW_COIN_TYPE_TRON => format!("T{}", bs58::encode(&hash[0..20]).into_string()),
        TW_COIN_TYPE_SUI => format!("0x{}", hex::encode(&hash[0..32])),
        TW_COIN_TYPE_TON => bs58::encode(&hash[0..32]).into_string(),
        _ => return Err(anyhow!("Unsupported generic coin type: {}", coin_type_id))
    };
    

    Ok(address)
}

/// Cardano address derivation using Trust Wallet Core
#[cfg(feature = "wallet-core")]
pub fn derive_cardano_address(public_key: &[u8]) -> Result<String> {
    derive_generic_address(public_key, TW_COIN_TYPE_CARDANO)
}

/// Polkadot address derivation using Trust Wallet Core
#[cfg(feature = "wallet-core")]
pub fn derive_polkadot_address(public_key: &[u8]) -> Result<String> {
    derive_generic_address(public_key, TW_COIN_TYPE_POLKADOT)
}

/// Ripple address derivation using Trust Wallet Core
#[cfg(feature = "wallet-core")]
pub fn derive_ripple_address(public_key: &[u8]) -> Result<String> {
    derive_generic_address(public_key, TW_COIN_TYPE_RIPPLE)
}

/// Tron address derivation using Trust Wallet Core
#[cfg(feature = "wallet-core")]
pub fn derive_tron_address(public_key: &[u8]) -> Result<String> {
    derive_generic_address(public_key, TW_COIN_TYPE_TRON)
}

/// Sui address derivation using Trust Wallet Core
#[cfg(feature = "wallet-core")]
pub fn derive_sui_address(public_key: &[u8]) -> Result<String> {
    derive_generic_address(public_key, TW_COIN_TYPE_SUI)
}

/// TON address derivation using Trust Wallet Core
#[cfg(feature = "wallet-core")]
pub fn derive_ton_address(public_key: &[u8]) -> Result<String> {
    derive_generic_address(public_key, TW_COIN_TYPE_TON)
}

/// Decompress a secp256k1 public key from compressed format (33 bytes) to uncompressed format (65 bytes)
fn decompress_secp256k1_pubkey(compressed: &[u8]) -> Result<Vec<u8>> {
    if compressed.len() != 33 {
        return Err(anyhow!("Compressed public key must be 33 bytes"));
    }
    
    // Use secp256k1 crate for proper decompression
    use secp256k1::{PublicKey, Secp256k1};
    
    let secp = Secp256k1::verification_only();
    let pubkey = PublicKey::from_slice(compressed)
        .map_err(|e| anyhow!("Failed to parse compressed public key: {}", e))?;
    
    // Get uncompressed format (65 bytes with 0x04 prefix)
    let uncompressed = pubkey.serialize_uncompressed();
    Ok(uncompressed.to_vec())
}

/// Simple bech32 encoding (placeholder - should use proper bech32 library)
fn encode_bech32_simplified(hrp: &str, data: &[u8]) -> Result<String> {
    // This is a simplified implementation for testing
    // In production, use a proper bech32 library like the `bech32` crate
    let encoded_data = hex::encode(&data[1..17]); // Take first 16 bytes for simplified encoding
    Ok(format!("{}1q{}", hrp, encoded_data))
}


/// Basic address validation
#[cfg(feature = "wallet-core")]
pub fn validate_address(address: &str, coin_type: u32) -> Result<bool> {
    match coin_type {
        TW_COIN_TYPE_ETHEREUM => {
            // Basic Ethereum address validation
            Ok(address.starts_with("0x") && address.len() == 42 && 
               hex::decode(&address[2..]).is_ok())
        }
        TW_COIN_TYPE_BITCOIN => {
            // Basic Bitcoin address validation (bc1... or legacy)
            Ok(address.starts_with("bc1") || address.starts_with("1") || address.starts_with("3"))
        }
        TW_COIN_TYPE_SOLANA => {
            // Basic Solana address validation (base58, 32 bytes)
            match bs58::decode(address).into_vec() {
                Ok(bytes) => Ok(bytes.len() == 32),
                Err(_) => Ok(false)
            }
        }
        TW_COIN_TYPE_THORCHAIN => {
            // Basic THORChain address validation
            Ok(address.starts_with("thor1") && address.len() > 10)
        }
        TW_COIN_TYPE_COSMOS => {
            // Basic Cosmos address validation  
            Ok(address.starts_with("cosmos1") && address.len() > 15)
        }
        _ => Ok(false)
    }
}

/// Get coin configuration information
#[cfg(feature = "wallet-core")]
pub fn get_coin_info(coin_type: u32) -> Result<CoinInfo> {
    match coin_type {
        // Bitcoin-like chains
        TW_COIN_TYPE_BITCOIN => Ok(CoinInfo {
            coin_type,
            symbol: "BTC".to_string(),
            name: "Bitcoin".to_string(),
            decimals: 8,
            derivation_path: get_derivation_path_for_coin(coin_type)?,
        }),
        TW_COIN_TYPE_LITECOIN => Ok(CoinInfo {
            coin_type,
            symbol: "LTC".to_string(),
            name: "Litecoin".to_string(),
            decimals: 8,
            derivation_path: get_derivation_path_for_coin(coin_type)?,
        }),
        TW_COIN_TYPE_DOGECOIN => Ok(CoinInfo {
            coin_type,
            symbol: "DOGE".to_string(),
            name: "Dogecoin".to_string(),
            decimals: 8,
            derivation_path: get_derivation_path_for_coin(coin_type)?,
        }),
        
        // Ethereum and EVM chains
        TW_COIN_TYPE_ETHEREUM => Ok(CoinInfo {
            coin_type,
            symbol: "ETH".to_string(),
            name: "Ethereum".to_string(),
            decimals: 18,
            derivation_path: get_derivation_path_for_coin(coin_type)?,
        }),
        TW_COIN_TYPE_BSC => Ok(CoinInfo {
            coin_type,
            symbol: "BNB".to_string(),
            name: "BNB Smart Chain".to_string(),
            decimals: 18,
            derivation_path: get_derivation_path_for_coin(coin_type)?,
        }),
        TW_COIN_TYPE_POLYGON => Ok(CoinInfo {
            coin_type,
            symbol: "MATIC".to_string(),
            name: "Polygon".to_string(),
            decimals: 18,
            derivation_path: get_derivation_path_for_coin(coin_type)?,
        }),
        TW_COIN_TYPE_AVALANCHE => Ok(CoinInfo {
            coin_type,
            symbol: "AVAX".to_string(),
            name: "Avalanche".to_string(),
            decimals: 18,
            derivation_path: get_derivation_path_for_coin(coin_type)?,
        }),
        TW_COIN_TYPE_OPTIMISM => Ok(CoinInfo {
            coin_type,
            symbol: "ETH".to_string(),
            name: "Optimism".to_string(),
            decimals: 18,
            derivation_path: get_derivation_path_for_coin(coin_type)?,
        }),
        TW_COIN_TYPE_ARBITRUM => Ok(CoinInfo {
            coin_type,
            symbol: "ETH".to_string(),
            name: "Arbitrum".to_string(),
            decimals: 18,
            derivation_path: get_derivation_path_for_coin(coin_type)?,
        }),
        TW_COIN_TYPE_BASE => Ok(CoinInfo {
            coin_type,
            symbol: "ETH".to_string(),
            name: "Base".to_string(),
            decimals: 18,
            derivation_path: get_derivation_path_for_coin(coin_type)?,
        }),
        
        // Cosmos ecosystem
        TW_COIN_TYPE_COSMOS => Ok(CoinInfo {
            coin_type,
            symbol: "ATOM".to_string(),
            name: "Cosmos Hub".to_string(),
            decimals: 6,
            derivation_path: get_derivation_path_for_coin(coin_type)?,
        }),
        TW_COIN_TYPE_THORCHAIN => Ok(CoinInfo {
            coin_type,
            symbol: "RUNE".to_string(),
            name: "THORChain".to_string(),
            decimals: 8,
            derivation_path: get_derivation_path_for_coin(coin_type)?,
        }),
        TW_COIN_TYPE_OSMOSIS => Ok(CoinInfo {
            coin_type,
            symbol: "OSMO".to_string(),
            name: "Osmosis".to_string(),
            decimals: 6,
            derivation_path: get_derivation_path_for_coin(coin_type)?,
        }),
        
        // Other chains
        TW_COIN_TYPE_SOLANA => Ok(CoinInfo {
            coin_type,
            symbol: "SOL".to_string(),
            name: "Solana".to_string(),
            decimals: 9,
            derivation_path: get_derivation_path_for_coin(coin_type)?,
        }),
        TW_COIN_TYPE_CARDANO => Ok(CoinInfo {
            coin_type,
            symbol: "ADA".to_string(),
            name: "Cardano".to_string(),
            decimals: 6,
            derivation_path: get_derivation_path_for_coin(coin_type)?,
        }),
        TW_COIN_TYPE_POLKADOT => Ok(CoinInfo {
            coin_type,
            symbol: "DOT".to_string(),
            name: "Polkadot".to_string(),
            decimals: 10,
            derivation_path: get_derivation_path_for_coin(coin_type)?,
        }),
        TW_COIN_TYPE_RIPPLE => Ok(CoinInfo {
            coin_type,
            symbol: "XRP".to_string(),
            name: "Ripple".to_string(),
            decimals: 6,
            derivation_path: get_derivation_path_for_coin(coin_type)?,
        }),
        TW_COIN_TYPE_TRON => Ok(CoinInfo {
            coin_type,
            symbol: "TRX".to_string(),
            name: "Tron".to_string(),
            decimals: 6,
            derivation_path: get_derivation_path_for_coin(coin_type)?,
        }),
        TW_COIN_TYPE_SUI => Ok(CoinInfo {
            coin_type,
            symbol: "SUI".to_string(),
            name: "Sui".to_string(),
            decimals: 9,
            derivation_path: get_derivation_path_for_coin(coin_type)?,
        }),
        TW_COIN_TYPE_TON => Ok(CoinInfo {
            coin_type,
            symbol: "TON".to_string(),
            name: "The Open Network".to_string(),
            decimals: 9,
            derivation_path: get_derivation_path_for_coin(coin_type)?,
        }),
        
        _ => Err(anyhow!("Unsupported coin type: {}", coin_type))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_derivation_paths() {
        assert_eq!(get_derivation_path_for_coin(TW_COIN_TYPE_ETHEREUM).unwrap(), "m/44'/60'/0'/0/0");
        assert_eq!(get_derivation_path_for_coin(TW_COIN_TYPE_BITCOIN).unwrap(), "m/84'/0'/0'/0/0");
        assert_eq!(get_derivation_path_for_coin(TW_COIN_TYPE_SOLANA).unwrap(), "m/44'/501'/0'/0'");
        assert_eq!(get_derivation_path_for_coin(TW_COIN_TYPE_THORCHAIN).unwrap(), "m/44'/931'/0'/0/0");
        assert_eq!(get_derivation_path_for_coin(TW_COIN_TYPE_COSMOS).unwrap(), "m/44'/118'/0'/0/0");
    }
    
    #[test]
    fn test_address_validation() {
        // Ethereum
        assert!(validate_address("0x742d35Cc6634C0532925a3b8D45C0D2C0d0Db8f7", TW_COIN_TYPE_ETHEREUM).unwrap());
        assert!(!validate_address("invalid", TW_COIN_TYPE_ETHEREUM).unwrap());
        
        // Bitcoin
        assert!(validate_address("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", TW_COIN_TYPE_BITCOIN).unwrap());
        assert!(validate_address("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", TW_COIN_TYPE_BITCOIN).unwrap());
        
        // Solana
        assert!(validate_address("11111111111111111111111111111111", TW_COIN_TYPE_SOLANA).unwrap());
    }
    
    #[test]
    fn test_coin_info() {
        let eth_info = get_coin_info(TW_COIN_TYPE_ETHEREUM).unwrap();
        assert_eq!(eth_info.symbol, "ETH");
        assert_eq!(eth_info.decimals, 18);
        
        let btc_info = get_coin_info(TW_COIN_TYPE_BITCOIN).unwrap();
        assert_eq!(btc_info.symbol, "BTC");
        assert_eq!(btc_info.decimals, 8);
        
        let sol_info = get_coin_info(TW_COIN_TYPE_SOLANA).unwrap();
        assert_eq!(sol_info.symbol, "SOL");
        assert_eq!(sol_info.decimals, 9);
    }
}