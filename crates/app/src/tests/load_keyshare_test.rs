#[cfg(test)]
mod load_keyshare_tests {
    use crate::keyshare::*;
    use anyhow::Result;

    #[tokio::test]
    async fn test_load_keyshare1_vult() -> Result<()> {
        println!("🔍 Loading keyshare1.vult file");
        
        // Read the keyshare1.vult file from the repo root
        let keyshare_path = "/Users/dev/dev/vultisig/vultisig-cli/keyshare1.vult";
        let content = std::fs::read_to_string(keyshare_path)?;
        
        println!("📄 File size: {} characters", content.len());
        
        // Load the keyshare (no password mentioned)
        let keyshare = VultKeyshare::from_base64_with_password(content.trim(), None)?;
        
        println!("✅ Successfully loaded keyshare!");
        println!("🏛️  Vault name: {}", keyshare.vault_name);
        
        // Print public keys
        println!("\n🔑 Public Keys:");
        println!("  ECDSA (hex): {}", keyshare.public_key_ecdsa_hex);
        println!("  EdDSA (hex): {}", keyshare.public_key_eddsa_hex);
        
        // Print chain code
        println!("\n⛓️  Chain Code (hex): {}", keyshare.hex_chain_code);
        
        // Print keyshare details
        if let Some(ecdsa_data) = &keyshare.ecdsa_keyshare {
            println!("\n📈 ECDSA Keyshare Details:");
            println!("  Public key: {} bytes", ecdsa_data.public_key.len());
            println!("  Chain code: {} bytes", ecdsa_data.chain_code.len()); 
            println!("  Share data: {} bytes", ecdsa_data.share_data.len());
        }
        
        if let Some(eddsa_data) = &keyshare.eddsa_keyshare {
            println!("\n📊 EdDSA Keyshare Details:");
            println!("  Public key: {} bytes", eddsa_data.public_key.len());
            println!("  Chain code: {} bytes", eddsa_data.chain_code.len());
            println!("  Share data: {} bytes", eddsa_data.share_data.len());
        }
        
        // Test address derivation for major networks
        println!("\n🏦 Address Derivation:");
        
        // ETH address
        match keyshare.derive_address("ETH") {
            Ok(addr) => println!("  ✅ ETH Address: {}", addr),
            Err(e) => println!("  ❌ ETH Address failed: {}", e),
        }
        
        // BTC address  
        match keyshare.derive_address("BTC") {
            Ok(addr) => println!("  ✅ BTC Address: {}", addr),
            Err(e) => println!("  ❌ BTC Address failed: {}", e),
        }
        
        // SOL address
        match keyshare.derive_address("SOL") {
            Ok(addr) => println!("  ✅ SOL Address: {}", addr),
            Err(e) => println!("  ❌ SOL Address failed: {}", e),
        }
        
        // THOR address
        match keyshare.derive_address("THOR") {
            Ok(addr) => println!("  ✅ THOR Address: {}", addr),
            Err(e) => println!("  ❌ THOR Address failed: {}", e),
        }
        
        // Test BIP32 key derivation for different paths
        println!("\n🗝️  BIP32 Key Derivation Test:");
        
        if let Some(ecdsa_data) = &keyshare.ecdsa_keyshare {
            let test_paths = vec![
                "m/0",                    // Simple non-hardened path
                "m/0/1",                  // Two-level path  
                "m/44'/60'/0'/0/0",      // Standard Ethereum path (hardened)
                "m/84'/0'/0'/0/0",       // Standard Bitcoin native segwit path
            ];
            
            for path in test_paths {
                match keyshare.tss_get_derived_pubkey(
                    &ecdsa_data.public_key, 
                    &ecdsa_data.chain_code, 
                    path
                ) {
                    Ok(derived_key) => {
                        println!("  ✅ Path {}: {} (33 bytes)", 
                            path, 
                            hex::encode(&derived_key[..8]) // Show first 8 bytes
                        );
                    },
                    Err(e) => {
                        println!("  ❌ Path {} failed: {}", path, e);
                    }
                }
            }
        }
        
        println!("\n🎉 Keyshare analysis complete!");
        Ok(())
    }
}