use anyhow::{anyhow, Result};
use std::collections::HashMap;
use std::ffi::{CString, CStr};
use std::os::raw::c_char;

/// Wallet-Core integration module for Vultisig
/// This module provides a standardized interface to TrustWallet's wallet-core library
/// for address derivation, transaction building, and signing across multiple blockchains

// Constants for supported coins matching wallet-core CoinType
pub const COIN_TYPE_ETHEREUM: u32 = 60;
pub const COIN_TYPE_BITCOIN: u32 = 0;  
pub const COIN_TYPE_SOLANA: u32 = 501;
pub const COIN_TYPE_THORCHAIN: u32 = 931;
pub const COIN_TYPE_COSMOS: u32 = 118;
pub const COIN_TYPE_BINANCE: u32 = 714;

/// Supported blockchain networks with wallet-core integration
#[derive(Debug, Clone, PartialEq)]
pub enum SupportedChain {
    Ethereum,
    Bitcoin,
    Solana,
    THORChain,
    Cosmos,
    BinanceSmartChain,
}

impl SupportedChain {
    pub fn coin_type(&self) -> u32 {
        match self {
            SupportedChain::Ethereum => COIN_TYPE_ETHEREUM,
            SupportedChain::Bitcoin => COIN_TYPE_BITCOIN,
            SupportedChain::Solana => COIN_TYPE_SOLANA,
            SupportedChain::THORChain => COIN_TYPE_THORCHAIN,
            SupportedChain::Cosmos => COIN_TYPE_COSMOS,
            SupportedChain::BinanceSmartChain => COIN_TYPE_ETHEREUM, // BSC uses ETH-compatible addresses
        }
    }
    
    pub fn derivation_path(&self) -> Result<String> {
        crate::wallet_core_ffi::get_derivation_path_for_coin(self.coin_type())
    }
    
    pub fn hrp(&self) -> Option<&'static str> {
        match self {
            SupportedChain::Bitcoin => Some("bc"),
            SupportedChain::THORChain => Some("thor"),
            SupportedChain::Cosmos => Some("cosmos"),
            _ => None,
        }
    }
    
    pub fn to_symbol(&self) -> String {
        match self {
            SupportedChain::Ethereum => "ETH".to_string(),
            SupportedChain::Bitcoin => "BTC".to_string(),
            SupportedChain::Solana => "SOL".to_string(),
            SupportedChain::THORChain => "RUNE".to_string(),
            SupportedChain::Cosmos => "ATOM".to_string(),
            SupportedChain::BinanceSmartChain => "BNB".to_string(),
        }
    }
    
    pub fn from_symbol(symbol: &str) -> Option<Self> {
        match symbol.to_uppercase().as_str() {
            "ETH" | "ETHEREUM" => Some(SupportedChain::Ethereum),
            "BTC" | "BITCOIN" => Some(SupportedChain::Bitcoin),
            "SOL" | "SOLANA" => Some(SupportedChain::Solana),
            "THOR" | "THORCHAIN" | "RUNE" => Some(SupportedChain::THORChain),
            "ATOM" | "COSMOS" => Some(SupportedChain::Cosmos),
            "BNB" | "BSC" => Some(SupportedChain::BinanceSmartChain),
            _ => None,
        }
    }
}

/// Wallet-Core integration wrapper
pub struct WalletCore {
    supported_chains: HashMap<u32, SupportedChain>,
}

impl WalletCore {
    pub fn new() -> Self {
        let mut supported_chains = HashMap::new();
        
        // Initialize supported chains
        let chains = vec![
            SupportedChain::Ethereum,
            SupportedChain::Bitcoin, 
            SupportedChain::Solana,
            SupportedChain::THORChain,
            SupportedChain::Cosmos,
            SupportedChain::BinanceSmartChain,
        ];
        
        for chain in chains {
            supported_chains.insert(chain.coin_type(), chain);
        }
        
        Self { supported_chains }
    }
    
    /// Get all supported chains
    pub fn get_supported_chains(&self) -> Vec<&SupportedChain> {
        self.supported_chains.values().collect()
    }
    
    /// Check if a chain is supported
    pub fn is_chain_supported(&self, chain: &SupportedChain) -> bool {
        self.supported_chains.contains_key(&chain.coin_type())
    }
    
    /// Derive address from public key using wallet-core standards
    pub fn derive_address_from_public_key(
        &self,
        chain: &SupportedChain,
        public_key: &[u8],
    ) -> Result<String> {
        match chain {
            SupportedChain::Ethereum | SupportedChain::BinanceSmartChain => {
                self.derive_ethereum_address(public_key)
            }
            SupportedChain::Bitcoin => {
                self.derive_bitcoin_address(public_key)
            }
            SupportedChain::Solana => {
                self.derive_solana_address(public_key)
            }
            SupportedChain::THORChain => {
                self.derive_thorchain_address(public_key)
            }
            SupportedChain::Cosmos => {
                self.derive_cosmos_address(public_key)
            }
        }
    }
    
    /// Derive Ethereum-compatible address (ETH, BSC) using wallet-core
    fn derive_ethereum_address(&self, public_key: &[u8]) -> Result<String> {
        crate::wallet_core_ffi::derive_ethereum_address(public_key)
    }
    
    /// Derive Bitcoin P2WPKH address using wallet-core
    fn derive_bitcoin_address(&self, public_key: &[u8]) -> Result<String> {
        crate::wallet_core_ffi::derive_bitcoin_address(public_key)
    }
    
    /// Derive Solana address using wallet-core
    fn derive_solana_address(&self, public_key: &[u8]) -> Result<String> {
        crate::wallet_core_ffi::derive_solana_address(public_key)
    }
    
    /// Derive THORChain address using wallet-core
    fn derive_thorchain_address(&self, public_key: &[u8]) -> Result<String> {
        crate::wallet_core_ffi::derive_thorchain_address(public_key)
    }
    
    /// Derive Cosmos address using wallet-core
    fn derive_cosmos_address(&self, public_key: &[u8]) -> Result<String> {
        crate::wallet_core_ffi::derive_cosmos_address(public_key, crate::wallet_core_ffi::TW_COIN_TYPE_COSMOS)
    }
    
    /// Validate an address for a given chain
    pub fn validate_address(&self, chain: &SupportedChain, address: &str) -> bool {
        match chain {
            SupportedChain::Ethereum | SupportedChain::BinanceSmartChain => {
                self.validate_ethereum_address(address)
            }
            SupportedChain::Bitcoin => {
                self.validate_bitcoin_address(address)
            }
            SupportedChain::Solana => {
                self.validate_solana_address(address)
            }
            SupportedChain::THORChain => {
                self.validate_thorchain_address(address)
            }
            SupportedChain::Cosmos => {
                self.validate_cosmos_address(address)
            }
        }
    }
    
    fn validate_ethereum_address(&self, address: &str) -> bool {
        crate::wallet_core_ffi::validate_address(address, crate::wallet_core_ffi::TW_COIN_TYPE_ETHEREUM)
            .unwrap_or(false)
    }
    
    fn validate_bitcoin_address(&self, address: &str) -> bool {
        crate::wallet_core_ffi::validate_address(address, crate::wallet_core_ffi::TW_COIN_TYPE_BITCOIN)
            .unwrap_or(false)
    }
    
    fn validate_solana_address(&self, address: &str) -> bool {
        crate::wallet_core_ffi::validate_address(address, crate::wallet_core_ffi::TW_COIN_TYPE_SOLANA)
            .unwrap_or(false)
    }
    
    fn validate_thorchain_address(&self, address: &str) -> bool {
        crate::wallet_core_ffi::validate_address(address, crate::wallet_core_ffi::TW_COIN_TYPE_THORCHAIN)
            .unwrap_or(false)
    }
    
    fn validate_cosmos_address(&self, address: &str) -> bool {
        crate::wallet_core_ffi::validate_address(address, crate::wallet_core_ffi::TW_COIN_TYPE_COSMOS)
            .unwrap_or(false)
    }
}

impl Default for WalletCore {
    fn default() -> Self {
        Self::new()
    }
}

/// Address derivation utilities using wallet-core standards
pub mod address_utils {
    use super::*;
    
    /// Derive all supported addresses from public keys
    pub fn derive_all_addresses(
        ecdsa_pubkey: Option<&[u8]>, 
        eddsa_pubkey: Option<&[u8]>
    ) -> Result<HashMap<String, String>> {
        let wallet_core = WalletCore::new();
        let mut addresses = HashMap::new();
        
        // ECDSA-based chains
        if let Some(pubkey) = ecdsa_pubkey {
            let ecdsa_chains = vec![
                SupportedChain::Ethereum,
                SupportedChain::Bitcoin,
                SupportedChain::THORChain,
                SupportedChain::Cosmos,
                SupportedChain::BinanceSmartChain,
            ];
            
            for chain in ecdsa_chains {
                match wallet_core.derive_address_from_public_key(&chain, pubkey) {
                    Ok(address) => {
                        addresses.insert(format!("{:?}", chain), address);
                    }
                    Err(e) => {
                        eprintln!("Failed to derive {:?} address: {}", chain, e);
                    }
                }
            }
        }
        
        // EdDSA-based chains (Solana)
        if let Some(pubkey) = eddsa_pubkey {
            let eddsa_chains = vec![SupportedChain::Solana];
            
            for chain in eddsa_chains {
                match wallet_core.derive_address_from_public_key(&chain, pubkey) {
                    Ok(address) => {
                        addresses.insert(format!("{:?}", chain), address);
                    }
                    Err(e) => {
                        eprintln!("Failed to derive {:?} address: {}", chain, e);
                    }
                }
            }
        }
        
        Ok(addresses)
    }
    
    /// Get derivation path for a given chain
    pub fn get_derivation_path(chain_symbol: &str) -> Result<String> {
        let chain = SupportedChain::from_symbol(chain_symbol)
            .ok_or_else(|| anyhow!("Unsupported chain symbol: {}", chain_symbol))?;
        chain.derivation_path()
    }
    
    /// Get coin type for a given chain
    pub fn get_coin_type(chain_symbol: &str) -> Option<u32> {
        SupportedChain::from_symbol(chain_symbol)
            .map(|chain| chain.coin_type())
    }
}

/// Integration helper for TSS keyshare and wallet-core standards
pub mod tss_integration {
    use super::*;
    
    /// Derive addresses using TSS keyshare and wallet-core compatible paths
    pub fn derive_addresses_from_keyshare(
        keyshare: &crate::keyshare::VultKeyshare
    ) -> Result<HashMap<String, String>> {
        let wallet_core = WalletCore::new();
        let mut addresses = HashMap::new();
        
        // ECDSA-based chains
        if let Some(ecdsa_data) = &keyshare.ecdsa_keyshare {
            // Derive addresses for each supported ECDSA chain
            for chain in [
                SupportedChain::Ethereum,
                SupportedChain::Bitcoin,
                SupportedChain::THORChain,
                SupportedChain::Cosmos,
                SupportedChain::BinanceSmartChain,
            ] {
                match derive_chain_address_from_keyshare(keyshare, &chain) {
                    Ok(address) => {
                        addresses.insert(chain.to_symbol(), address);
                    }
                    Err(e) => {
                        eprintln!("Failed to derive {:?} address from keyshare: {}", chain, e);
                    }
                }
            }
        }
        
        // EdDSA-based chains
        if let Some(_eddsa_data) = &keyshare.eddsa_keyshare {
            match derive_chain_address_from_keyshare(keyshare, &SupportedChain::Solana) {
                Ok(address) => {
                    addresses.insert(SupportedChain::Solana.to_symbol(), address);
                }
                Err(e) => {
                    eprintln!("Failed to derive Solana address from keyshare: {}", e);
                }
            }
        }
        
        Ok(addresses)
    }
    
    /// Derive address for a specific chain from TSS keyshare
    pub fn derive_chain_address_from_keyshare(
        keyshare: &crate::keyshare::VultKeyshare,
        chain: &SupportedChain,
    ) -> Result<String> {
        match chain {
            SupportedChain::Ethereum | SupportedChain::BinanceSmartChain => {
                keyshare.derive_eth_address()
            }
            SupportedChain::Bitcoin => {
                keyshare.derive_btc_address()
            }
            SupportedChain::Solana => {
                keyshare.derive_sol_address()
            }
            SupportedChain::THORChain => {
                keyshare.derive_thor_address()
            }
            SupportedChain::Cosmos => {
                // Use existing keyshare derivation but with cosmos prefix
                let derivation_path = chain.derivation_path()?;
                let derived_pubkey = keyshare.derive_ecdsa_public_key(&derivation_path)?;
                let wallet_core = WalletCore::new();
                wallet_core.derive_cosmos_address(&derived_pubkey)
            }
        }
    }
    
    /// Get all supported chains with their metadata
    pub fn get_chain_metadata() -> Vec<ChainMetadata> {
        vec![
            ChainMetadata {
                chain: SupportedChain::Ethereum,
                symbol: "ETH",
                name: "Ethereum",
                decimals: 18,
                is_mainnet: true,
                rpc_urls: vec!["https://mainnet.infura.io/v3/YOUR_PROJECT_ID".to_string()],
            },
            ChainMetadata {
                chain: SupportedChain::Bitcoin,
                symbol: "BTC", 
                name: "Bitcoin",
                decimals: 8,
                is_mainnet: true,
                rpc_urls: vec!["https://blockstream.info/api".to_string()],
            },
            ChainMetadata {
                chain: SupportedChain::Solana,
                symbol: "SOL",
                name: "Solana", 
                decimals: 9,
                is_mainnet: true,
                rpc_urls: vec!["https://api.mainnet-beta.solana.com".to_string()],
            },
            ChainMetadata {
                chain: SupportedChain::THORChain,
                symbol: "RUNE",
                name: "THORChain",
                decimals: 8,
                is_mainnet: true,
                rpc_urls: vec!["https://daemon.thorchain.info".to_string()],
            },
            ChainMetadata {
                chain: SupportedChain::Cosmos,
                symbol: "ATOM",
                name: "Cosmos Hub",
                decimals: 6,
                is_mainnet: true,
                rpc_urls: vec!["https://lcd-cosmoshub.blockapsis.com".to_string()],
            },
            ChainMetadata {
                chain: SupportedChain::BinanceSmartChain,
                symbol: "BNB",
                name: "BNB Smart Chain",
                decimals: 18,
                is_mainnet: true,
                rpc_urls: vec!["https://bsc-dataseed.binance.org".to_string()],
            },
        ]
    }
}

/// Chain metadata for comprehensive blockchain support
#[derive(Debug, Clone)]
pub struct ChainMetadata {
    pub chain: SupportedChain,
    pub symbol: &'static str,
    pub name: &'static str,
    pub decimals: u8,
    pub is_mainnet: bool,
    pub rpc_urls: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_supported_chain_creation() {
        let wallet_core = WalletCore::new();
        assert_eq!(wallet_core.supported_chains.len(), 6);
        
        assert!(wallet_core.is_chain_supported(&SupportedChain::Ethereum));
        assert!(wallet_core.is_chain_supported(&SupportedChain::Bitcoin));
        assert!(wallet_core.is_chain_supported(&SupportedChain::Solana));
        assert!(wallet_core.is_chain_supported(&SupportedChain::THORChain));
    }
    
    #[test]
    fn test_chain_from_symbol() {
        assert_eq!(SupportedChain::from_symbol("ETH"), Some(SupportedChain::Ethereum));
        assert_eq!(SupportedChain::from_symbol("btc"), Some(SupportedChain::Bitcoin));
        assert_eq!(SupportedChain::from_symbol("SOLANA"), Some(SupportedChain::Solana));
        assert_eq!(SupportedChain::from_symbol("THOR"), Some(SupportedChain::THORChain));
        assert_eq!(SupportedChain::from_symbol("INVALID"), None);
    }
    
    #[test]
    fn test_derivation_paths() {
        assert_eq!(SupportedChain::Ethereum.derivation_path().unwrap(), "m/44'/60'/0'/0/0");
        assert_eq!(SupportedChain::Bitcoin.derivation_path().unwrap(), "m/84'/0'/0'/0/0");
        assert_eq!(SupportedChain::Solana.derivation_path().unwrap(), "m/44'/501'/0'/0'");
        assert_eq!(SupportedChain::THORChain.derivation_path().unwrap(), "m/44'/931'/0'/0/0");
    }
    
    #[test]
    fn test_coin_types() {
        assert_eq!(SupportedChain::Ethereum.coin_type(), 60);
        assert_eq!(SupportedChain::Bitcoin.coin_type(), 0);
        assert_eq!(SupportedChain::Solana.coin_type(), 501);
        assert_eq!(SupportedChain::THORChain.coin_type(), 931);
    }
    
    #[test]
    fn test_address_validation() {
        let wallet_core = WalletCore::new();
        
        // Ethereum addresses
        assert!(wallet_core.validate_address(&SupportedChain::Ethereum, "0x742d35Cc6634C0532925a3b8D45C0D2C0d0Db8f7"));
        assert!(!wallet_core.validate_address(&SupportedChain::Ethereum, "invalid"));
        
        // Bitcoin addresses
        assert!(wallet_core.validate_bitcoin_address("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"));
        assert!(!wallet_core.validate_bitcoin_address("invalid"));
        
        // Solana addresses  
        assert!(wallet_core.validate_solana_address("11111111111111111111111111111111"));
        assert!(!wallet_core.validate_solana_address("invalid"));
    }
}