#!/usr/bin/env cargo run --bin inspect_keyshare
//! Keyshare Inspector - A tool to inspect and analyze .vult keyshare files
//! 
//! This script reads, decrypts (if needed), and analyzes the structure of 
//! Vultisig keyshare files (.vult) to help developers understand the format.

use anyhow::{anyhow, Result};
use base64::Engine;
use serde_json::Value;
use std::env;
use std::fs;
use std::path::Path;

// Import vultisigd types
use vultisig::keyshare::VultKeyshare;
use vultisig::commondata::{VaultContainer, Vault};

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    
    if args.len() < 2 {
        println!("Usage: {} <keyshare_file.vult> [password]", args[0]);
        println!("       {} --help", args[0]);
        return Ok(());
    }
    
    if args[1] == "--help" {
        print_help();
        return Ok(());
    }
    
    let keyshare_path = &args[1];
    let password = args.get(2).map(|s| s.as_str());
    
    println!("🔍 Vultisig Keyshare Inspector");
    println!("================================");
    println!("File: {}", keyshare_path);
    
    if !Path::new(keyshare_path).exists() {
        return Err(anyhow!("Keyshare file not found: {}", keyshare_path));
    }
    
    // Read the file
    let content = fs::read_to_string(keyshare_path)?;
    println!("📄 File size: {} bytes", content.len());
    
    // Analyze the raw content
    analyze_raw_content(&content)?;
    
    // Try to parse as keyshare
    match VultKeyshare::from_base64_with_password(&content.trim(), password) {
        Ok(keyshare) => {
            println!("\n✅ Successfully parsed keyshare!");
            analyze_keyshare_structure(&keyshare)?;
        }
        Err(e) => {
            println!("\n❌ Failed to parse keyshare: {}", e);
            if password.is_none() && content.trim().len() > 100 {
                println!("💡 This might be an encrypted keyshare. Try providing a password.");
            }
        }
    }
    
    // Try to decode just the container first
    if let Ok(decoded) = base64::engine::general_purpose::STANDARD
        .decode(content.trim().replace('\n', "").replace('\r', "")) 
    {
        analyze_container_structure(&decoded)?;
    }
    
    Ok(())
}

fn print_help() {
    println!("Vultisig Keyshare Inspector");
    println!("===========================");
    println!();
    println!("This tool inspects .vult keyshare files and explains their structure.");
    println!();
    println!("USAGE:");
    println!("  inspect_keyshare <file.vult>           # Inspect unencrypted keyshare");
    println!("  inspect_keyshare <file.vult> password  # Inspect encrypted keyshare");
    println!();
    println!("EXAMPLES:");
    println!("  inspect_keyshare ~/.vultisig/keyshares/my_vault.vult");
    println!("  inspect_keyshare encrypted.vult mypassword123");
    println!();
    println!("OUTPUT:");
    println!("  - File format analysis");
    println!("  - Keyshare structure breakdown");
    println!("  - Public key information");
    println!("  - Supported blockchain networks");
    println!("  - JSON schema documentation");
}

fn analyze_raw_content(content: &str) -> Result<()> {
    println!("\n📋 Raw Content Analysis:");
    println!("  Content length: {} characters", content.len());
    
    let trimmed = content.trim();
    println!("  Trimmed length: {} characters", trimmed.len());
    
    // Check if it looks like base64
    let base64_chars = trimmed.chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '+' || *c == '/' || *c == '=')
        .count();
    let base64_ratio = base64_chars as f64 / trimmed.len() as f64;
    
    println!("  Base64 character ratio: {:.2}%", base64_ratio * 100.0);
    
    if base64_ratio > 0.9 {
        println!("  ✅ Appears to be base64 encoded");
        
        // Try to decode
        match base64::engine::general_purpose::STANDARD
            .decode(trimmed.replace('\n', "").replace('\r', ""))
        {
            Ok(decoded) => {
                println!("  ✅ Valid base64, decoded to {} bytes", decoded.len());
                
                // Check if decoded data looks like protobuf
                if decoded.len() > 0 && decoded[0] < 32 {
                    println!("  💡 Decoded data appears to be binary (likely protobuf)");
                } else {
                    println!("  💡 Decoded data appears to be text/JSON");
                }
            }
            Err(e) => {
                println!("  ❌ Invalid base64: {}", e);
            }
        }
    } else {
        println!("  ❌ Does not appear to be base64 encoded");
    }
    
    Ok(())
}

fn analyze_container_structure(decoded_data: &[u8]) -> Result<()> {
    println!("\n📦 Container Structure Analysis:");
    
    // Try to parse as VaultContainer
    match vultisig::commondata::parse_vault_container(decoded_data) {
        Ok(container) => {
            println!("  ✅ Valid VaultContainer protobuf");
            println!("  📊 Container Details:");
            println!("    Version: {}", container.version);
            println!("    Is Encrypted: {}", container.is_encrypted);
            println!("    Vault Data Length: {} characters", container.vault.len());
            
            if container.is_encrypted {
                println!("    🔒 Vault data is encrypted (requires password)");
            } else {
                println!("    🔓 Vault data is unencrypted (base64 encoded)");
                
                // Try to decode the inner vault
                if let Ok(vault_data) = base64::Engine::decode(
                    &base64::engine::general_purpose::STANDARD, 
                    &container.vault
                ) {
                    println!("    📄 Inner vault decoded to {} bytes", vault_data.len());
                    
                    // Try to parse inner vault
                    if let Ok(vault) = vultisig::commondata::parse_vault(&vault_data) {
                        analyze_vault_details(&vault)?;
                    }
                }
            }
        }
        Err(e) => {
            println!("  ❌ Failed to parse as VaultContainer: {}", e);
            println!("  💡 Data might be encrypted or in a different format");
        }
    }
    
    Ok(())
}

fn analyze_keyshare_structure(keyshare: &VultKeyshare) -> Result<()> {
    println!("\n🔑 Keyshare Structure Analysis:");
    
    if let Some(ecdsa) = &keyshare.ecdsa_keyshare {
        println!("  📈 ECDSA Keyshare Present:");
        println!("    Public Key: {} bytes ({})", 
                 ecdsa.public_key.len(),
                 hex::encode(&ecdsa.public_key[..std::cmp::min(8, ecdsa.public_key.len())]));
        println!("    Chain Code: {} bytes ({})", 
                 ecdsa.chain_code.len(),
                 hex::encode(&ecdsa.chain_code[..std::cmp::min(8, ecdsa.chain_code.len())]));
        println!("    Share Data: {} bytes", ecdsa.share_data.len());
        
        println!("    🌐 Supported Networks (ECDSA):");
        println!("      • Ethereum (ETH) - m/44'/60'/0'/0/0");
        println!("      • Bitcoin (BTC) - m/84'/0'/0'/0/0");  
        println!("      • THORChain (RUNE) - m/44'/931'/0'/0/0");
        println!("      • Cosmos (ATOM) - m/44'/118'/0'/0/0");
        println!("      • Binance Smart Chain (BSC)");
    } else {
        println!("  ❌ No ECDSA keyshare found");
    }
    
    if let Some(eddsa) = &keyshare.eddsa_keyshare {
        println!("  📊 EdDSA Keyshare Present:");
        println!("    Public Key: {} bytes ({})", 
                 eddsa.public_key.len(),
                 hex::encode(&eddsa.public_key[..std::cmp::min(8, eddsa.public_key.len())]));
        println!("    Chain Code: {} bytes ({})", 
                 eddsa.chain_code.len(),
                 hex::encode(&eddsa.chain_code[..std::cmp::min(8, eddsa.chain_code.len())]));
        println!("    Share Data: {} bytes", eddsa.share_data.len());
        
        println!("    🌐 Supported Networks (EdDSA):");
        println!("      • Solana (SOL) - m/44'/501'/0'/0'");
    } else {
        println!("  ❌ No EdDSA keyshare found");
    }
    
    // Try to derive addresses (if not encrypted)
    println!("\n🏦 Address Derivation Test:");
    test_address_derivation(keyshare);
    
    Ok(())
}

fn analyze_vault_details(vault: &Vault) -> Result<()> {
    println!("    🏛️  Vault Details:");
    println!("      Name: '{}'", vault.name);
    println!("      ECDSA Public Key: {} chars", vault.public_key_ecdsa.len());
    if !vault.public_key_ecdsa.is_empty() {
        println!("        Value: {}", vault.public_key_ecdsa);
    }
    
    println!("      EdDSA Public Key: {} chars", vault.public_key_eddsa.len());
    if !vault.public_key_eddsa.is_empty() {
        println!("        Value: {}", vault.public_key_eddsa);
    }
    
    println!("      Chain Code: {} chars", vault.hex_chain_code.len());
    if !vault.hex_chain_code.is_empty() {
        println!("        Value: {}", vault.hex_chain_code);
    }
    
    println!("      Signers: {} participants", vault.signers.len());
    for (i, signer) in vault.signers.iter().enumerate() {
        println!("        {}: {}", i + 1, signer);
    }
    
    println!("      Key Shares: {} shares", vault.key_shares.len());
    for (i, share) in vault.key_shares.iter().enumerate() {
        println!("        Share {}: pubkey={}, keyshare={} chars", 
                 i + 1, 
                 share.public_key.chars().take(16).collect::<String>(),
                 share.keyshare.len());
    }
    
    println!("      Local Party ID: '{}'", vault.local_party_id);
    println!("      Reshare Prefix: '{}'", vault.reshare_prefix);
    println!("      Library Type: {}", vault.lib_type);
    
    Ok(())
}

fn test_address_derivation(keyshare: &VultKeyshare) {
    // Test ECDSA address derivation
    if keyshare.ecdsa_keyshare.is_some() {
        match keyshare.derive_eth_address() {
            Ok(addr) => println!("  ✅ ETH Address: {}", addr),
            Err(e) => println!("  ❌ ETH Address: {}", e),
        }
        
        match keyshare.derive_btc_address() {
            Ok(addr) => println!("  ✅ BTC Address: {}", addr),
            Err(e) => println!("  ❌ BTC Address: {}", e),
        }
        
        match keyshare.derive_thor_address() {
            Ok(addr) => println!("  ✅ THOR Address: {}", addr),
            Err(e) => println!("  ❌ THOR Address: {}", e),
        }
    }
    
    // Test EdDSA address derivation
    if keyshare.eddsa_keyshare.is_some() {
        match keyshare.derive_sol_address() {
            Ok(addr) => println!("  ✅ SOL Address: {}", addr),
            Err(e) => println!("  ❌ SOL Address: {}", e),
        }
    }
}

/// Generate JSON schema documentation for the keyshare structure
fn generate_json_schema() -> Value {
    serde_json::json!({
        "VaultContainer": {
            "description": "Top-level container for a Vultisig keyshare file",
            "type": "object",
            "properties": {
                "version": {
                    "type": "integer",
                    "description": "Data format version"
                },
                "vault": {
                    "type": "string", 
                    "description": "Base64-encoded vault data (encrypted or plain)"
                },
                "is_encrypted": {
                    "type": "boolean",
                    "description": "Whether the vault data is encrypted with a password"
                }
            }
        },
        "Vault": {
            "description": "Inner vault containing keyshare and metadata",
            "type": "object",
            "properties": {
                "name": {
                    "type": "string",
                    "description": "Human-readable name for this vault"
                },
                "public_key_ecdsa": {
                    "type": "string",
                    "description": "Hex-encoded ECDSA public key (33 bytes compressed secp256k1)"
                },
                "public_key_eddsa": {
                    "type": "string", 
                    "description": "Hex-encoded EdDSA public key (32 bytes Ed25519)"
                },
                "signers": {
                    "type": "array",
                    "items": { "type": "string" },
                    "description": "List of participant IDs in the MPC group"
                },
                "hex_chain_code": {
                    "type": "string",
                    "description": "Hex-encoded BIP32 chain code for HD key derivation"
                },
                "key_shares": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "public_key": {
                                "type": "string",
                                "description": "Public key for this share"
                            },
                            "keyshare": {
                                "type": "string", 
                                "description": "The actual MPC key share (encrypted)"
                            }
                        }
                    },
                    "description": "MPC key shares for threshold signing"
                },
                "local_party_id": {
                    "type": "string",
                    "description": "ID of the local party in MPC protocol"
                },
                "reshare_prefix": {
                    "type": "string",
                    "description": "Prefix for key resharing operations"
                },
                "lib_type": {
                    "type": "integer",
                    "description": "MPC library type (e.g., GG20)"
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_schema_generation() {
        let schema = generate_json_schema();
        assert!(schema.get("VaultContainer").is_some());
        assert!(schema.get("Vault").is_some());
    }
}
