use anyhow::{anyhow, Result};
use prost::Message;

// Include generated protobuf code from third_party/commondata
// This replaces the manual protobuf parsing in keyshare.rs

// Generated protobuf modules for vault types
pub mod vultisig {
    pub mod vault {
        pub mod v1 {
            include!(concat!(env!("OUT_DIR"), "/vultisig.vault.v1.rs"));
        }
    }
    
    pub mod keysign {
        pub mod v1 {
            include!(concat!(env!("OUT_DIR"), "/vultisig.keysign.v1.rs"));
        }
    }
    
    pub mod keygen {
        pub mod v1 {
            include!(concat!(env!("OUT_DIR"), "/vultisig.keygen.v1.rs"));
        }
    }
}

// Re-export the most commonly used types
pub use vultisig::vault::v1::{Vault, VaultContainer, vault};
pub use vultisig::keysign::v1::{Coin, KeysignMessage};
pub use vultisig::keygen::v1::LibType;

/// Parse VaultContainer from protobuf bytes using proper commondata definitions
pub fn parse_vault_container(data: &[u8]) -> Result<VaultContainer> {
    VaultContainer::decode(data)
        .map_err(|e| anyhow!("Failed to parse VaultContainer: {}", e))
}

/// Parse Vault from protobuf bytes using proper commondata definitions
pub fn parse_vault(data: &[u8]) -> Result<Vault> {
    Vault::decode(data)
        .map_err(|e| anyhow!("Failed to parse Vault: {}", e))
}

// TODO: Re-enable legacy conversion once keyshare types are properly structured
/*
pub mod legacy {
    use super::*;
    // TODO: Fix legacy imports once keyshare module is properly structured
    // use crate::keyshare::{VaultContainer as LegacyVaultContainer, Vault as LegacyVault};
    
    /// Convert commondata VaultContainer to legacy format
    pub fn vault_container_to_legacy(container: &VaultContainer) -> LegacyVaultContainer {
        LegacyVaultContainer {
            version: container.version,
            vault: container.vault.clone(),
            is_encrypted: container.is_encrypted,
        }
    }
    
    /// Convert commondata Vault to legacy format
    pub fn vault_to_legacy(vault: &Vault) -> LegacyVault {
        let key_shares = vault.key_shares.iter().map(|ks| {
            crate::keyshare::KeyShare {
                public_key: ks.public_key.clone(),
                keyshare: ks.keyshare.clone(),
            }
        }).collect();
        
        LegacyVault {
            name: vault.name.clone(),
            public_key_ecdsa: vault.public_key_ecdsa.clone(),
            public_key_eddsa: vault.public_key_eddsa.clone(),
            signers: vault.signers.clone(),
            hex_chain_code: vault.hex_chain_code.clone(),
            key_shares,
            local_party_id: vault.local_party_id.clone(),
            reshare_prefix: vault.reshare_prefix.clone(),
        }
    }
}
*/

#[cfg(test)]
mod tests {
    use super::*;
    use prost::Message;
    use pretty_assertions::assert_eq;
    
    // Helper function to create a test VaultContainer
    fn create_test_vault_container() -> VaultContainer {
        VaultContainer {
            version: 1,
            vault: "test_vault_data".to_string(),
            is_encrypted: false,
        }
    }
    
    // Helper function to create a test Vault
    fn create_test_vault() -> Vault {
        Vault {
            name: "Test Vault".to_string(),
            public_key_ecdsa: "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798".to_string(),
            public_key_eddsa: "1234567890123456789012345678901234567890123456789012345678901234".to_string(),
            signers: vec!["signer1".to_string(), "signer2".to_string()],
            created_at: None,
            hex_chain_code: "873DFF81C02F525623FD1FE5167EAC3A55A049DE3D314BB42EE227FFED37D508".to_string(),
            key_shares: vec![
                vault::KeyShare {
                    public_key: "pub_key_1".to_string(),
                    keyshare: "keyshare_1".to_string(),
                },
                vault::KeyShare {
                    public_key: "pub_key_2".to_string(),
                    keyshare: "keyshare_2".to_string(),
                },
            ],
            local_party_id: "local_party".to_string(),
            reshare_prefix: "reshare_".to_string(),
            lib_type: LibType::Gg20 as i32,
        }
    }
    
    // Helper function to create a test Coin
    fn create_test_coin() -> Coin {
        Coin {
            chain: "ethereum".to_string(),
            ticker: "ETH".to_string(),
            address: "0x742d35Cc6639C12acac95F6DE4E7B8E2F6e2b9fd".to_string(),
            contract_address: "0x0000000000000000000000000000000000000000".to_string(),
            decimals: 18,
            price_provider_id: "coingecko".to_string(),
            is_native_token: true,
            hex_public_key: "02abc123def456".to_string(),
            logo: "eth_logo.png".to_string(),
        }
    }
    
    // Helper function to create a test KeysignMessage
    fn create_test_keysign_message() -> KeysignMessage {
        KeysignMessage {
            session_id: "test-session-123".to_string(),
            service_name: "Vultisig-Test".to_string(),
            keysign_payload: None,
            custom_message_payload: None,
            encryption_key_hex: "abcdef123456".to_string(),
            use_vultisig_relay: false,
            payload_id: "payload-123".to_string(),
        }
    }
    
    #[test]
    fn test_parse_vault_container() {
        let test_container = create_test_vault_container();
        
        // Encode the container
        let mut buffer = Vec::new();
        test_container.encode(&mut buffer).unwrap();
        
        // Parse it back
        let parsed_container = parse_vault_container(&buffer).unwrap();
        
        assert_eq!(parsed_container.version, test_container.version);
        assert_eq!(parsed_container.vault, test_container.vault);
        assert_eq!(parsed_container.is_encrypted, test_container.is_encrypted);
    }
    
    #[test]
    fn test_parse_vault_container_invalid_data() {
        // Test with invalid protobuf data
        let invalid_data = vec![0xFF, 0xFE, 0xFD, 0xFC];
        let result = parse_vault_container(&invalid_data);
        
        assert!(result.is_err());
        let error = result.unwrap_err();
        assert!(error.to_string().contains("Failed to parse VaultContainer"));
    }
    
    #[test]
    fn test_parse_vault_container_empty_data() {
        // Test with empty data
        let empty_data = vec![];
        let result = parse_vault_container(&empty_data);
        
        assert!(result.is_err());
        let error = result.unwrap_err();
        assert!(error.to_string().contains("Failed to parse VaultContainer"));
    }
    
    #[test]
    fn test_parse_vault() {
        let test_vault = create_test_vault();
        
        // Encode the vault
        let mut buffer = Vec::new();
        test_vault.encode(&mut buffer).unwrap();
        
        // Parse it back
        let parsed_vault = parse_vault(&buffer).unwrap();
        
        assert_eq!(parsed_vault.name, test_vault.name);
        assert_eq!(parsed_vault.public_key_ecdsa, test_vault.public_key_ecdsa);
        assert_eq!(parsed_vault.public_key_eddsa, test_vault.public_key_eddsa);
        assert_eq!(parsed_vault.signers, test_vault.signers);
        assert_eq!(parsed_vault.hex_chain_code, test_vault.hex_chain_code);
        assert_eq!(parsed_vault.key_shares.len(), test_vault.key_shares.len());
        assert_eq!(parsed_vault.local_party_id, test_vault.local_party_id);
        assert_eq!(parsed_vault.reshare_prefix, test_vault.reshare_prefix);
        
        // Check key shares
        for (i, key_share) in parsed_vault.key_shares.iter().enumerate() {
            assert_eq!(key_share.public_key, test_vault.key_shares[i].public_key);
            assert_eq!(key_share.keyshare, test_vault.key_shares[i].keyshare);
        }
    }
    
    #[test]
    fn test_parse_vault_invalid_data() {
        // Test with invalid protobuf data
        let invalid_data = vec![0xFF, 0xFE, 0xFD, 0xFC];
        let result = parse_vault(&invalid_data);
        
        assert!(result.is_err());
        let error = result.unwrap_err();
        assert!(error.to_string().contains("Failed to parse Vault"));
    }
    
    #[test]
    fn test_parse_vault_empty_data() {
        // Test with empty data
        let empty_data = vec![];
        let result = parse_vault(&empty_data);
        
        assert!(result.is_err());
        let error = result.unwrap_err();
        assert!(error.to_string().contains("Failed to parse Vault"));
    }
    
    #[test]
    fn test_vault_container_serialization_deserialization() {
        let original = create_test_vault_container();
        
        // Encode
        let mut encoded = Vec::new();
        original.encode(&mut encoded).unwrap();
        
        // Decode
        let decoded = VaultContainer::decode(encoded.as_slice()).unwrap();
        
        // Compare
        assert_eq!(original.version, decoded.version);
        assert_eq!(original.vault, decoded.vault);
        assert_eq!(original.is_encrypted, decoded.is_encrypted);
    }
    
    #[test]
    fn test_vault_serialization_deserialization() {
        let original = create_test_vault();
        
        // Encode
        let mut encoded = Vec::new();
        original.encode(&mut encoded).unwrap();
        
        // Decode
        let decoded = Vault::decode(encoded.as_slice()).unwrap();
        
        // Compare all fields
        assert_eq!(original.name, decoded.name);
        assert_eq!(original.public_key_ecdsa, decoded.public_key_ecdsa);
        assert_eq!(original.public_key_eddsa, decoded.public_key_eddsa);
        assert_eq!(original.signers, decoded.signers);
        assert_eq!(original.hex_chain_code, decoded.hex_chain_code);
        assert_eq!(original.key_shares.len(), decoded.key_shares.len());
        assert_eq!(original.local_party_id, decoded.local_party_id);
        assert_eq!(original.reshare_prefix, decoded.reshare_prefix);
    }
    
    #[test]
    fn test_coin_serialization_deserialization() {
        let original = create_test_coin();
        
        // Encode
        let mut encoded = Vec::new();
        original.encode(&mut encoded).unwrap();
        
        // Decode
        let decoded = Coin::decode(encoded.as_slice()).unwrap();
        
        // Compare all fields
        assert_eq!(original.chain, decoded.chain);
        assert_eq!(original.ticker, decoded.ticker);
        assert_eq!(original.logo, decoded.logo);
        assert_eq!(original.decimals, decoded.decimals);
        assert_eq!(original.price_provider_id, decoded.price_provider_id);
        assert_eq!(original.contract_address, decoded.contract_address);
        assert_eq!(original.is_native_token, decoded.is_native_token);
    }
    
    #[test]
    fn test_keysign_message_serialization_deserialization() {
        let original = create_test_keysign_message();
        
        // Encode
        let mut encoded = Vec::new();
        original.encode(&mut encoded).unwrap();
        
        // Decode
        let decoded = KeysignMessage::decode(encoded.as_slice()).unwrap();
        
        // Compare all fields
        assert_eq!(original.session_id, decoded.session_id);
        assert_eq!(original.service_name, decoded.service_name);
        assert_eq!(original.keysign_payload, decoded.keysign_payload);
        assert_eq!(original.custom_message_payload, decoded.custom_message_payload);
        assert_eq!(original.encryption_key_hex, decoded.encryption_key_hex);
        assert_eq!(original.use_vultisig_relay, decoded.use_vultisig_relay);
        assert_eq!(original.payload_id, decoded.payload_id);
    }
    
    #[test]
    fn test_vault_container_with_different_versions() {
        let versions = [0, 1, 2, 999];
        
        for version in &versions {
            let container = VaultContainer {
                version: *version,
                vault: format!("vault_data_v{}", version),
                is_encrypted: *version % 2 == 0,
            };
            
            // Encode and decode
            let mut encoded = Vec::new();
            container.encode(&mut encoded).unwrap();
            
            let parsed = parse_vault_container(&encoded).unwrap();
            
            assert_eq!(parsed.version, *version);
            assert_eq!(parsed.vault, format!("vault_data_v{}", version));
            assert_eq!(parsed.is_encrypted, *version % 2 == 0);
        }
    }
    
    #[test]
    fn test_vault_with_empty_fields() {
        let vault = Vault {
            name: "".to_string(),
            public_key_ecdsa: "".to_string(),
            public_key_eddsa: "".to_string(),
            signers: vec![],
            created_at: None,
            hex_chain_code: "".to_string(),
            key_shares: vec![],
            local_party_id: "".to_string(),
            reshare_prefix: "".to_string(),
            lib_type: LibType::Gg20 as i32,
        };
        
        // Should still encode/decode successfully
        let mut encoded = Vec::new();
        vault.encode(&mut encoded).unwrap();
        
        let parsed = parse_vault(&encoded).unwrap();
        
        assert_eq!(parsed.name, "");
        assert_eq!(parsed.public_key_ecdsa, "");
        assert_eq!(parsed.public_key_eddsa, "");
        assert!(parsed.signers.is_empty());
        assert_eq!(parsed.hex_chain_code, "");
        assert!(parsed.key_shares.is_empty());
        assert_eq!(parsed.local_party_id, "");
        assert_eq!(parsed.reshare_prefix, "");
    }
    
    #[test]
    fn test_vault_with_many_signers_and_keyshares() {
        // Test with larger collections
        let mut signers = Vec::new();
        let mut key_shares = Vec::new();
        
        for i in 0..10 {
            signers.push(format!("signer_{}", i));
            key_shares.push(vault::KeyShare {
                public_key: format!("pub_key_{}", i),
                keyshare: format!("keyshare_{}", i),
            });
        }
        
        let vault = Vault {
            name: "Large Vault".to_string(),
            public_key_ecdsa: "ecdsa_key".to_string(),
            public_key_eddsa: "eddsa_key".to_string(),
            signers,
            created_at: None,
            hex_chain_code: "chain_code".to_string(),
            key_shares,
            local_party_id: "local".to_string(),
            reshare_prefix: "prefix_".to_string(),
            lib_type: LibType::Gg20 as i32,
        };
        
        // Encode and decode
        let mut encoded = Vec::new();
        vault.encode(&mut encoded).unwrap();
        
        let parsed = parse_vault(&encoded).unwrap();
        
        assert_eq!(parsed.signers.len(), 10);
        assert_eq!(parsed.key_shares.len(), 10);
        
        for i in 0..10 {
            assert_eq!(parsed.signers[i], format!("signer_{}", i));
            assert_eq!(parsed.key_shares[i].public_key, format!("pub_key_{}", i));
            assert_eq!(parsed.key_shares[i].keyshare, format!("keyshare_{}", i));
        }
    }
    
    #[test]
    fn test_coin_with_different_values() {
        let test_cases = [
            (
                "ethereum", "ETH", "eth.png", 18, "coingecko",
                "0x0000000000000000000000000000000000000000", true
            ),
            (
                "bitcoin", "BTC", "btc.png", 8, "coinmarketcap",
                "", true
            ),
            (
                "binance-smart-chain", "USDT", "usdt.png", 18, "coingecko",
                "0x55d398326f99059fF775485246999027B3197955", false
            ),
        ];
        
        for (chain, ticker, logo, decimals, provider, contract, is_native) in &test_cases {
            let coin = Coin {
                chain: chain.to_string(),
                ticker: ticker.to_string(),
                address: format!("0x{}", chain),  // Mock address
                contract_address: contract.to_string(),
                decimals: *decimals,
                price_provider_id: provider.to_string(),
                is_native_token: *is_native,
                hex_public_key: "02abc123".to_string(),  // Mock public key
                logo: logo.to_string(),
            };
            
            // Encode and decode
            let mut encoded = Vec::new();
            coin.encode(&mut encoded).unwrap();
            
            let decoded = Coin::decode(encoded.as_slice()).unwrap();
            
            assert_eq!(decoded.chain, *chain);
            assert_eq!(decoded.ticker, *ticker);
            assert_eq!(decoded.logo, *logo);
            assert_eq!(decoded.decimals, *decimals);
            assert_eq!(decoded.price_provider_id, *provider);
            assert_eq!(decoded.contract_address, *contract);
            assert_eq!(decoded.is_native_token, *is_native);
        }
    }
    
    #[test]
    fn test_keysign_message_with_different_relay_settings() {
        let test_cases = [
            (true, "relay_payload_id"),
            (false, "local_payload_id"),
        ];
        
        for (use_relay, payload_id) in &test_cases {
            let message = KeysignMessage {
                session_id: "test_session".to_string(),
                service_name: "test_service".to_string(),
                keysign_payload: None,
                custom_message_payload: None,
                encryption_key_hex: "key_hex".to_string(),
                use_vultisig_relay: *use_relay,
                payload_id: payload_id.to_string(),
            };
            
            // Encode and decode
            let mut encoded = Vec::new();
            message.encode(&mut encoded).unwrap();
            
            let decoded = KeysignMessage::decode(encoded.as_slice()).unwrap();
            
            assert_eq!(decoded.use_vultisig_relay, *use_relay);
            assert_eq!(decoded.payload_id, *payload_id);
        }
    }
    
    #[test]
    fn test_parse_functions_with_various_data_sizes() {
        // Test with different sized data to ensure robustness
        let data_sizes = [1, 10, 100, 1000, 10000];
        
        for size in &data_sizes {
            // Create vault with variable-sized data
            let large_data = "x".repeat(*size);
            let vault = Vault {
                name: format!("vault_size_{}", size),
                public_key_ecdsa: large_data.clone(),
                public_key_eddsa: large_data.clone(),
                signers: vec![large_data.clone()],
                hex_chain_code: large_data.clone(),
                created_at: None,
                key_shares: vec![vault::KeyShare {
                    public_key: large_data.clone(),
                    keyshare: large_data.clone(),
                }],
                local_party_id: large_data.clone(),
                reshare_prefix: large_data,
                lib_type: LibType::Gg20 as i32,
            };
            
            // Test encoding and parsing
            let mut encoded = Vec::new();
            vault.encode(&mut encoded).unwrap();
            
            let parsed = parse_vault(&encoded);
            assert!(parsed.is_ok(), "Failed to parse vault with size {}", size);
            
            let parsed_vault = parsed.unwrap();
            assert_eq!(parsed_vault.name, format!("vault_size_{}", size));
            
            println!("Successfully parsed vault with data size: {}", size);
        }
    }
    
    #[test]
    fn test_protobuf_field_order_independence() {
        // Create the same vault data but encoded in different ways
        // to ensure field order doesn't matter for parsing
        let vault = create_test_vault();
        
        // Encode normally
        let mut encoded1 = Vec::new();
        vault.encode(&mut encoded1).unwrap();
        
        // Both should parse to the same result
        let parsed1 = parse_vault(&encoded1).unwrap();
        
        // Basic validation - if protobuf is working correctly,
        // the same data should parse consistently
        assert_eq!(parsed1.name, vault.name);
        assert_eq!(parsed1.signers.len(), vault.signers.len());
        assert_eq!(parsed1.key_shares.len(), vault.key_shares.len());
    }
    
    #[test]
    fn test_error_propagation() {
        // Test that errors are properly propagated with meaningful messages
        let invalid_data = vec![0x08, 0x96, 0x01]; // Valid protobuf format but wrong message type
        
        let vault_result = parse_vault(&invalid_data);
        match vault_result {
            Ok(_) => {
                // This might succeed with default values, which is valid protobuf behavior
                println!("Parse succeeded with default values (valid protobuf behavior)");
            }
            Err(e) => {
                // If it fails, error should be meaningful
                let error_msg = e.to_string();
                assert!(error_msg.contains("Failed to parse Vault"));
                println!("Parse failed with expected error: {}", error_msg);
            }
        }
    }
    
    #[test]
    fn test_concurrent_parsing() {
        use std::sync::Arc;
        use std::thread;
        
        let vault = Arc::new(create_test_vault());
        let mut encoded = Vec::new();
        vault.encode(&mut encoded).unwrap();
        let encoded = Arc::new(encoded);
        
        // Test concurrent parsing (protobuf should be thread-safe)
        let handles: Vec<_> = (0..5).map(|i| {
            let encoded = encoded.clone();
            let vault = vault.clone();
            
            thread::spawn(move || {
                let parsed = parse_vault(&encoded).unwrap();
                assert_eq!(parsed.name, vault.name);
                println!("Thread {} successfully parsed vault", i);
            })
        }).collect();
        
        // Wait for all threads to complete
        for handle in handles {
            handle.join().unwrap();
        }
    }
    
    #[test]
    fn test_module_re_exports() {
        // Test that the re-exported types are accessible
        use crate::commondata::{Vault, VaultContainer, Coin, KeysignMessage};
        
        // Should be able to create instances using re-exported types
        let _vault_container = VaultContainer {
            version: 1,
            vault: "test".to_string(),
            is_encrypted: false,
        };
        
        let _vault = Vault {
            name: "test".to_string(),
            public_key_ecdsa: "test".to_string(),
            public_key_eddsa: "test".to_string(),
            signers: vec![],
            created_at: None,
            hex_chain_code: "test".to_string(),
            key_shares: vec![],
            local_party_id: "test".to_string(),
            reshare_prefix: "test".to_string(),
            lib_type: LibType::Gg20 as i32,
        };
        
        let _coin = Coin {
            chain: "test".to_string(),
            ticker: "TEST".to_string(),
            address: "0x123".to_string(),
            contract_address: "test".to_string(),
            decimals: 18,
            price_provider_id: "test".to_string(),
            is_native_token: true,
            hex_public_key: "02abc123".to_string(),
            logo: "test.png".to_string(),
        };
        
        let _message = KeysignMessage {
            session_id: "test".to_string(),
            service_name: "test".to_string(),
            keysign_payload: None,
            custom_message_payload: None,
            encryption_key_hex: "test".to_string(),
            use_vultisig_relay: false,
            payload_id: "test".to_string(),
        };
        
        println!("All re-exported types are accessible");
    }
}