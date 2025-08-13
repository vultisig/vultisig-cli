use vultisig::{qr, keysign_message};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Testing Vultisig QR Code Generation");
    println!("===================================");
    
    let vault_public_key = "023e4b76861289ad4528b33c2fd21b3a5160cd37b3294234914e21efb6ed4a452b";
    let vault_address = "0x1234567890123456789012345678901234567890";
    
    // Initialize QR generator
    let qr_gen = keysign_message::VultisigQRGenerator::new(vault_public_key.to_string());
    
    // Create a sample Ethereum transaction payload
    let eth_payload = keysign_message::create_eth_transaction_payload(
        "0x742d35Cc6634C0532925a3b8D45C0D2C0d0Db8f7", // to
        "1000000000000000000", // 1 ETH in wei
        1, // nonce
        21000, // gas limit
        "25000000000", // max fee per gas (25 gwei)
        "1000000000", // max priority fee per gas (1 gwei)
        vault_public_key,
        vault_address,
    );
    
    // Test RELAY mode (Internet)
    let relay_qr = qr_gen.generate_keysign_qr(
        eth_payload.clone(),
        keysign_message::NetworkMode::Relay,
        Some("f2583792-92cf-4efa-87aa-2cbbe939d19f".to_string()),
        Some("Vultisig-CLI".to_string()),
    )?;
    println!("\nRelay QR: {}", relay_qr);
    
    // Test LOCAL mode (Same Network)
    let local_qr = qr_gen.generate_keysign_qr(
        eth_payload,
        keysign_message::NetworkMode::Local,
        Some("f2583792-92cf-4efa-87aa-2cbbe939d19f".to_string()),
        Some("Vultisig-CLI".to_string()),
    )?;
    println!("\nLocal QR: {}", local_qr);
    
    // Test keygen QR for vault creation
    let keygen_qr = qr_gen.generate_keygen_qr(
        "My Test Vault".to_string(),
        "c9b189a8232b872b8d9ccd867d0db316dd10f56e729c310fe072adf5fd204ae7".to_string(),
        keysign_message::NetworkMode::Relay,
        keysign_message::TssType::Keygen,
    )?;
    println!("\nKeygen QR: {}", keygen_qr);
    
    // Test message signing QR
    let message_qr = qr_gen.generate_message_sign_qr(
        "Hello, Vultisig!".to_string(),
        "personal_sign".to_string(),
        keysign_message::NetworkMode::Local,
        Some("f2583792-92cf-4efa-87aa-2cbbe939d19f".to_string()),
        Some("Vultisig-CLI".to_string()),
    )?;
    println!("\nMessage QR: {}", message_qr);
    
    // Display QR code with instructions (using local mode)
    match qr::display_qr_with_instructions(
        "f2583792-92cf-4efa-87aa-2cbbe939d19f", 
        &local_qr, 
        "ETH", 
        "local"
    ) {
        Ok(_) => println!("\n✅ QR code generated and displayed successfully!"),
        Err(e) => println!("\n❌ Error displaying QR code: {}", e),
    }
    
    Ok(())
}
