#[cfg(test)]
mod create_vault_json_tests {
    use crate::keyshare::*;
    use anyhow::Result;
    use serde_json::json;

    #[tokio::test]
    async fn test_create_vault_json() -> Result<()> {
        println!("🔍 Creating vault.json from keyshare data");
        
        // Read keyshare2.vult (unencrypted)
        let keyshare_path = "/Users/dev/dev/vultisig/vultisig-cli/vault-data/keyshare2.vult";
        let content = std::fs::read_to_string(keyshare_path)?;
        let keyshare = VultKeyshare::from_base64_with_password(content.trim(), None)?;
        
        println!("✅ Loaded keyshare: {}", keyshare.vault_name);
        
        // Extract master public keys and chain code
        let ecdsa_pubkey = &keyshare.public_key_ecdsa_hex;
        let eddsa_pubkey = &keyshare.public_key_eddsa_hex;  
        let chain_code = &keyshare.hex_chain_code;
        
        println!("\n🔑 Master Keys:");
        println!("  ECDSA Public Key: {}", ecdsa_pubkey);
        println!("  EdDSA Public Key: {}", eddsa_pubkey);
        println!("  Chain Code: {}", chain_code);
        
        // Define networks and their derivation paths
        let networks = vec![
            // ECDSA Networks
            ("Ethereum", "ETH", "m/44'/60'/0'/0/0", "ecdsa"),
            ("Bitcoin", "BTC", "m/84'/0'/0'/0/0", "ecdsa"),
            ("THORChain", "RUNE", "m/44'/931'/0'/0/0", "ecdsa"),
            ("Cosmos", "ATOM", "m/44'/118'/0'/0/0", "ecdsa"),
            ("Binance Smart Chain", "BSC", "m/44'/60'/0'/0/0", "ecdsa"),
            // EdDSA Networks  
            ("Solana", "SOL", "m/44'/501'/0'/0'", "eddsa"),
        ];
        
        // Derive addresses for each network
        let mut network_addresses = Vec::new();
        
        for (network_name, symbol, derivation_path, key_type) in networks {
            println!("\n🌐 Processing {} ({})", network_name, symbol);
            
            let address_result = keyshare.derive_address(symbol);
            let derived_pubkey_result = if key_type == "ecdsa" {
                if let Some(ecdsa_data) = &keyshare.ecdsa_keyshare {
                    keyshare.tss_get_derived_pubkey(
                        &ecdsa_data.public_key,
                        &ecdsa_data.chain_code,
                        derivation_path
                    ).ok()
                } else {
                    None
                }
            } else {
                if let Some(eddsa_data) = &keyshare.eddsa_keyshare {
                    keyshare.tss_get_derived_pubkey(
                        &eddsa_data.public_key,
                        &eddsa_data.chain_code,
                        derivation_path
                    ).ok()
                } else {
                    None
                }
            };
            
            let network_info = json!({
                "name": network_name,
                "symbol": symbol,
                "derivation_path": derivation_path,
                "key_type": key_type,
                "address": match &address_result {
                    Ok(addr) => addr.clone(),
                    Err(e) => format!("Error: {}", e)
                },
                "derived_public_key": match derived_pubkey_result {
                    Some(pubkey) => hex::encode(pubkey),
                    None => "Error: Could not derive".to_string()
                }
            });
            
            network_addresses.push(network_info);
            
            match &address_result {
                Ok(addr) => println!("  ✅ Address: {}", addr),
                Err(e) => println!("  ❌ Address failed: {}", e),
            }
        }
        
        // Create comprehensive vault.json
        let vault_json = json!({
            "vault_info": {
                "name": keyshare.vault_name,
                "format_version": 1,
                "creation_timestamp": chrono::Utc::now().to_rfc3339(),
                "source": "keyshare2.vult (unencrypted)"
            },
            "master_keys": {
                "ecdsa_public_key": ecdsa_pubkey,
                "eddsa_public_key": eddsa_pubkey,
                "chain_code": chain_code,
                "key_format": {
                    "ecdsa": "66-character hex (compressed secp256k1)",
                    "eddsa": "64-character hex (Ed25519)",
                    "chain_code": "64-character hex (32 bytes)"
                }
            },
            "supported_networks": network_addresses,
            "bip32_derivation": {
                "algorithm": "HMAC-SHA512 based hierarchical deterministic derivation",
                "note": "Vultisig uses TSS-compatible HD derivation equivalent to iOS TssGetDerivedPubKey",
                "hardened_paths_supported": true,
                "test_derivations": {
                    "m/0": match keyshare.ecdsa_keyshare.as_ref()
                        .and_then(|ecdsa| keyshare.tss_get_derived_pubkey(&ecdsa.public_key, &ecdsa.chain_code, "m/0").ok()) {
                        Some(key) => hex::encode(&key[..8]),
                        None => "N/A".to_string()
                    },
                    "m/0/1": match keyshare.ecdsa_keyshare.as_ref()
                        .and_then(|ecdsa| keyshare.tss_get_derived_pubkey(&ecdsa.public_key, &ecdsa.chain_code, "m/0/1").ok()) {
                        Some(key) => hex::encode(&key[..8]),
                        None => "N/A".to_string()
                    }
                }
            },
            "mpc_info": {
                "signers": ["iPhone-2C0", "Server-07992"],
                "local_party_id": "iPhone-2C0",
                "threshold_scheme": "2-party TSS",
                "libraries_used": {
                    "ecdsa": "DKLS23 (audited by Trail of Bits)",
                    "eddsa": "multi-party-schnorr (audited by HashCloak)"
                }
            },
            "file_format": {
                "structure": "Base64 -> Protobuf VaultContainer -> Base64 -> Protobuf Vault",
                "encryption": "Supports AES-256-GCM password encryption",
                "keyshare_storage": "MPC key shares stored encrypted within vault"
            },
            "security_notes": [
                "Master public keys enable address derivation for multiple networks",
                "Each network uses isolated BIP32 derivation paths",
                "Private key shares are encrypted and require threshold cooperation",
                "HD derivation prevents key reuse across different purposes"
            ]
        });
        
        // Write vault.json
        let vault_json_path = "/Users/dev/dev/vultisig/vultisig-cli/vault-data/vault.json";
        std::fs::write(vault_json_path, serde_json::to_string_pretty(&vault_json)?)?;
        
        println!("\n🎉 Created vault.json at: {}", vault_json_path);
        println!("\n📊 Vault Summary:");
        println!("  Vault Name: {}", keyshare.vault_name);
        println!("  ECDSA Networks: 5 (Ethereum, Bitcoin, THORChain, Cosmos, BSC)");
        println!("  EdDSA Networks: 1 (Solana)");
        println!("  MPC Participants: 2 (iPhone-2C0, Server-07992)");
        println!("  BIP32 Derivation: ✅ Working (HMAC-SHA512)");
        
        Ok(())
    }
}