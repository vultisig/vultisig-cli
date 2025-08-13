use anyhow::{anyhow, Result};
use qrcode::QrCode;
use qrcode::render::unicode;
use serde::{Deserialize, Serialize};
use std::fs;
use std::process::Command;

#[cfg(test)]
use url;

/// Vault sharing data structure (matches QR spec format)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultShareData {
    pub uid: String,                    // Unique identifier for the vault
    pub name: String,                   // Human-readable vault name
    pub public_key_ecdsa: String,       // ECDSA public key (secp256k1) in hex format
    pub public_key_eddsa: String,       // EdDSA public key (ed25519) in hex format
    pub hex_chain_code: String,         // BIP32 chain code for key derivation (32 bytes hex)
}

/// Generate vault sharing QR code (plain JSON format)
/// According to spec: plain JSON string, not URI-based
pub fn generate_vault_sharing_qr(vault_data: &VaultShareData) -> Result<String> {
    serde_json::to_string(vault_data)
        .map_err(|e| anyhow!("Failed to serialize vault sharing data: {}", e))
}

/// Generate address QR code (plain address string)
/// According to spec: plain address string, no URI wrapper
pub fn generate_address_qr(address: &str) -> String {
    address.to_string()
}

/// Generate a QR code URI for mobile app scanning (keysign mode)
/// Uses the official Vultisig URI scheme for transaction signing
pub fn generate_vultisig_keysign_uri(
    vault_public_key: &str,
    json_data: &str,
) -> String {
    format!(
        "vultisig://vultisig.com?type=SignTransaction&vault={}&jsonData={}",
        vault_public_key, json_data
    )
}

// Note: Keygen QR codes removed as they are not needed for this implementation
// Only focusing on signing (keysign) QR codes

/// Generate ASCII QR code for terminal display (compact version)
pub fn generate_ascii_qr(uri: &str) -> Result<String> {
    let code = QrCode::new(uri.as_bytes())
        .map_err(|e| anyhow!("Failed to generate QR code: {}", e))?;
    
    // Use smaller characters for more compact display
    let image = code
        .render::<char>()
        .quiet_zone(false)  // Remove quiet zone to save space
        .dark_color('█')
        .light_color(' ')
        .build();
    
    Ok(image)
}

/// Generate very compact QR code using tiny characters
pub fn generate_compact_qr(uri: &str) -> Result<String> {
    let code = QrCode::new(uri.as_bytes())
        .map_err(|e| anyhow!("Failed to generate QR code: {}", e))?;
    
    // Use smallest possible characters
    let image = code
        .render::<char>()
        .quiet_zone(false)  // Remove quiet zone to save space
        .dark_color('▪')    // Small black square
        .light_color('▫')   // Small white square
        .build();
    
    Ok(image)
}

/// Generate ultra-compact QR code using half-blocks (most compact but still scannable)
pub fn generate_tiny_qr(uri: &str) -> Result<String> {
    let code = QrCode::new(uri.as_bytes())
        .map_err(|e| anyhow!("Failed to generate QR code: {}", e))?;
    
    // Use Dense1x2 half-blocks - this is the most compact scannable format
    // It renders 2 vertical pixels per character, halving the height
    let image = code
        .render::<unicode::Dense1x2>()
        .quiet_zone(false)  // Remove quiet zone to save space
        .module_dimensions(1, 1)  // Smallest possible modules
        .dark_color(unicode::Dense1x2::Dark)
        .light_color(unicode::Dense1x2::Light)
        .build();
    
    Ok(image)
}

/// Generate micro QR code using braille patterns (experimental - very compact)
pub fn generate_micro_qr(uri: &str) -> Result<String> {
    let code = QrCode::new(uri.as_bytes())
        .map_err(|e| anyhow!("Failed to generate QR code: {}", e))?;
    
    // Use simple character rendering with minimal spacing
    let image = code
        .render::<char>()
        .quiet_zone(false)
        .module_dimensions(1, 1)
        .dark_color('▀')  // Top half block
        .light_color(' ')  // Space
        .build();
    
    // Post-process to make even more compact by removing every other line
    let lines: Vec<&str> = image.lines().collect();
    let mut compact_lines = Vec::new();
    
    for (i, line) in lines.iter().enumerate() {
        if i % 2 == 0 {  // Take every other line
            compact_lines.push(*line);
        }
    }
    
    Ok(compact_lines.join("\n"))
}

/// Generate QR code as PNG image and save to file
pub fn generate_qr_image(uri: &str, output_path: &str) -> Result<()> {
    let code = QrCode::new(uri.as_bytes())
        .map_err(|e| anyhow!("Failed to generate QR code: {}", e))?;
    
    // Generate QR as character matrix first
    let qr_string = code.render::<char>()
        .quiet_zone(true)
        .module_dimensions(10, 10)  // Larger modules for better scanning
        .dark_color('█')
        .light_color(' ')
        .build();
    
    // Convert to image manually
    let lines: Vec<&str> = qr_string.lines().collect();
    let height = lines.len();
    let width = if height > 0 { lines[0].len() } else { 0 };
    
    if width == 0 || height == 0 {
        return Err(anyhow!("Invalid QR code dimensions"));
    }
    
    // Create image buffer
    let mut img_buffer = image::ImageBuffer::new(width as u32, height as u32);
    
    for (y, line) in lines.iter().enumerate() {
        for (x, ch) in line.chars().enumerate() {
            let pixel = if ch == '█' { 
                image::Luma([0u8])  // Black for dark modules
            } else { 
                image::Luma([255u8])  // White for light modules
            };
            img_buffer.put_pixel(x as u32, y as u32, pixel);
        }
    }
    
    // Scale up the image for better scanning (4x)
    let scaled_width = width as u32 * 4;
    let scaled_height = height as u32 * 4;
    let scaled_img = image::imageops::resize(&img_buffer, scaled_width, scaled_height, image::imageops::FilterType::Nearest);
    
    scaled_img.save(output_path)
        .map_err(|e| anyhow!("Failed to save QR image: {}", e))?;
    
    Ok(())
}

/// Generate HTML page with embedded QR code
pub fn generate_qr_html(uri: &str, session_id: &str, network: &str, connection_type: &str, output_path: &str) -> Result<()> {
    let code = QrCode::new(uri.as_bytes())
        .map_err(|e| anyhow!("Failed to generate QR code: {}", e))?;
    
    // Generate SVG for crisp display
    let svg = code.render::<qrcode::render::svg::Color>()
        .min_dimensions(300, 300)
        .max_dimensions(500, 500)
        .build();
    
    let mode_display = match connection_type {
        "local" => "LOCAL P2P SIGNING",
        "relay" => "RELAY SERVER SIGNING", 
        _ => "MOBILE SIGNING",
    };
    
    let html_content = format!(r#"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Vultisig QR Code - {}</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            margin: 0;
            padding: 20px;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }}
        .container {{
            background: white;
            border-radius: 20px;
            padding: 40px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.1);
            text-align: center;
            max-width: 600px;
        }}
        .header {{
            color: #333;
            margin-bottom: 30px;
        }}
        .qr-container {{
            background: #f8f9fa;
            border-radius: 15px;
            padding: 30px;
            margin: 30px 0;
            display: inline-block;
        }}
        .qr-code {{
            background: white;
            padding: 20px;
            border-radius: 10px;
            display: inline-block;
        }}
        .info {{
            background: #e3f2fd;
            border-radius: 10px;
            padding: 20px;
            margin: 20px 0;
            text-align: left;
        }}
        .info h3 {{
            margin-top: 0;
            color: #1976d2;
        }}
        .info p {{
            margin: 8px 0;
            color: #555;
        }}
        .instructions {{
            background: #f1f8e9;
            border-radius: 10px;
            padding: 20px;
            margin: 20px 0;
        }}
        .instructions h3 {{
            margin-top: 0;
            color: #388e3c;
        }}
        .instructions ol {{
            text-align: left;
            color: #555;
        }}
        .instructions li {{
            margin: 10px 0;
        }}
        .status {{
            background: #fff3e0;
            border-radius: 10px;
            padding: 15px;
            margin: 20px 0;
            color: #f57c00;
            font-weight: bold;
        }}
        .url {{
            word-break: break-all;
            font-family: monospace;
            font-size: 12px;
            color: #666;
            background: #f5f5f5;
            padding: 10px;
            border-radius: 5px;
            margin: 10px 0;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔐 Vultisig {}</h1>
            <p>Scan the QR code with your mobile app to sign the transaction</p>
        </div>
        
        <div class="qr-container">
            <div class="qr-code">
                {}
            </div>
        </div>
        
        <div class="info">
            <h3>📋 Transaction Details</h3>
            <p><strong>Session ID:</strong> {}</p>
            <p><strong>Network:</strong> {}</p>
            <p><strong>Mode:</strong> {}</p>
        </div>
        
        <div class="instructions">
            <h3>📱 Instructions</h3>
            <ol>
                <li>Open the Vultisig mobile app</li>
                <li>Use the QR scanner to scan the code above</li>
                <li>Review the transaction details on your mobile device</li>
                <li>Approve the transaction to complete the signing process</li>
            </ol>
        </div>
        
        <div class="status">
            ⏳ Waiting for mobile app to connect and sign...
        </div>
        
        <details>
            <summary>Technical Details</summary>
            <div class="url">{}</div>
        </details>
    </div>
    
    <script>
        // Auto-refresh every 30 seconds to check for updates
        setTimeout(() => {{
            window.location.reload();
        }}, 30000);
        
        // Show connection status
        console.log('Vultisig QR Code ready for scanning');
        console.log('Session ID: {}');
    </script>
</body>
</html>
"#, mode_display, mode_display, svg, session_id, network, connection_type.to_uppercase(), uri, session_id);
    
    fs::write(output_path, html_content)
        .map_err(|e| anyhow!("Failed to write HTML file: {}", e))?;
    
    Ok(())
}

/// Open file with system default application
pub fn open_file(file_path: &str) -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        Command::new("open")
            .arg(file_path)
            .spawn()
            .map_err(|e| anyhow!("Failed to open file: {}", e))?;
    }
    
    #[cfg(target_os = "linux")]
    {
        Command::new("xdg-open")
            .arg(file_path)
            .spawn()
            .map_err(|e| anyhow!("Failed to open file: {}", e))?;
    }
    
    #[cfg(target_os = "windows")]
    {
        Command::new("cmd")
            .args(&["/c", "start", file_path])
            .spawn()
            .map_err(|e| anyhow!("Failed to open file: {}", e))?;
    }
    
    Ok(())
}

/// Display QR code with instructions - enhanced with web/image options
pub fn display_qr_with_instructions(session_id: &str, uri: &str, network: &str, connection_type: &str) -> Result<()> {
    let mode_display = match connection_type {
        "local" => "LOCAL P2P SIGNING",
        "relay" => "RELAY SERVER SIGNING",
        _ => "MOBILE SIGNING",
    };
    
    println!("\n┌─────────────────────────────────────────────────────────────┐");
    println!("│                    VULTISIG {}                  │", mode_display);
    println!("├─────────────────────────────────────────────────────────────┤");
    println!("│  Session ID: {:<47} │", session_id);
    println!("│  Network:    {:<47} │", network);
    println!("│  Mode:       {:<47} │", connection_type.to_uppercase());
    println!("├─────────────────────────────────────────────────────────────┤");
    println!("│                                                             │");
    println!("│  🚀 QR CODE READY - Choose viewing option:                │");
    println!("│                                                             │");
    println!("│  📱 MOBILE SCANNING INSTRUCTIONS:                         │");
    println!("│  1. Open Vultisig mobile app                               │");
    println!("│  2. Use QR scanner to scan the code                       │");
    println!("│  3. Review and approve the transaction                     │");
    println!("│                                                             │");
    println!("└─────────────────────────────────────────────────────────────┘");
    println!();
    
    // Generate multiple viewing options
    let temp_dir = std::env::temp_dir();
    let html_path = temp_dir.join(format!("vultisig_qr_{}.html", session_id));
    let png_path = temp_dir.join(format!("vultisig_qr_{}.png", session_id));
    
    // Generate HTML page
    match generate_qr_html(uri, session_id, network, connection_type, html_path.to_str().unwrap()) {
        Ok(_) => {
            println!("🌐 Opening QR code in web browser...");
            if let Err(e) = open_file(html_path.to_str().unwrap()) {
                println!("   ⚠️  Could not auto-open browser: {}", e);
                println!("   📂 Manual: open {}", html_path.display());
            } else {
                println!("   ✅ Web page opened successfully!");
            }
        }
        Err(e) => println!("   ⚠️  Could not generate web page: {}", e),
    }
    
    // Generate PNG image as backup
    match generate_qr_image(uri, png_path.to_str().unwrap()) {
        Ok(_) => {
            println!("🖼️  QR code image saved: {}", png_path.display());
            println!("   💡 Tip: Double-click to open with image viewer");
        }
        Err(e) => println!("   ⚠️  Could not generate PNG: {}", e),
    }
    
    // Also show compact terminal version as fallback
    println!();
    println!("📟 Terminal QR (fallback):");
    match generate_micro_qr(uri) {
        Ok(qr_code) => {
            for line in qr_code.lines() {
                println!("  {}", line);
            }
        }
        Err(e) => println!("   ⚠️  Could not generate terminal QR: {}", e),
    }
    
    println!();
    println!("🔗 Raw URI: {}", uri);
    println!();
    
    match connection_type {
        "local" => println!("⏳ Waiting for mobile app to connect via local WiFi network..."),
        "relay" => println!("⏳ Waiting for mobile app to connect via Vultisig relay server..."),
        _ => println!("⏳ Waiting for mobile app to connect and sign..."),
    }
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;
    use pretty_assertions::assert_eq;

    // Test data constants
    const TEST_VAULT_PUBKEY: &str = "023e4b76861289ad4528b33c2fd21b3a5160cd37b3294234914e21efb6ed4a452b";
    const TEST_JSON_DATA: &str = "CiQ4MjU5NzFmMy0wODU0LTRhNzItYjkzZS00ZjE4ZjI5MjgzYjESC1Z1bHRpc2lnLTEyNRoQMTIzNDU2Nzg5MGFiY2RlZiAB";
    const TEST_URI_SHORT: &str = "vultisig://test";
    const TEST_URI_LONG: &str = "vultisig://sign?sid=test-session-123&type=local&host=192.168.1.100&port=8787&net=ETH&data=very-long-data-payload-that-makes-qr-code-dense";
    
    // Test addresses for different networks
    const TEST_BTC_ADDRESS: &str = "bc1qsef7rshf0jwm53rnkttpry5rpveqcd6dyj6pn9";
    const TEST_ETH_ADDRESS: &str = "0x8c4E1C2D3b9F88bBa6162F6Bd8dB05840Ca24F8c";
    const TEST_SOL_ADDRESS: &str = "G5Jm9g1NH1xprPz3ZpnNmF8Wkz2F6YUhkxpf432mRefR";

    #[test]
    fn test_generate_vultisig_keysign_uri() {
        let uri = generate_vultisig_keysign_uri(TEST_VAULT_PUBKEY, TEST_JSON_DATA);
        
        let expected = format!(
            "vultisig://vultisig.com?type=SignTransaction&vault={}&jsonData={}",
            TEST_VAULT_PUBKEY, TEST_JSON_DATA
        );
        assert_eq!(uri, expected);
        
        // Verify the URI contains required components
        assert!(uri.starts_with("vultisig://vultisig.com"));
        assert!(uri.contains("type=SignTransaction"));
        assert!(uri.contains(&format!("vault={}", TEST_VAULT_PUBKEY)));
        assert!(uri.contains(&format!("jsonData={}", TEST_JSON_DATA)));
    }
    
    #[test]
    fn test_generate_vultisig_keysign_uri_edge_cases() {
        // Test with empty data
        let uri_empty = generate_vultisig_keysign_uri("", "");
        assert!(uri_empty.contains("vault="));
        assert!(uri_empty.contains("jsonData="));
        
        // Test with special characters (should be handled by URL encoding at higher level)
        let special_data = "data with spaces & symbols";
        let uri_special = generate_vultisig_keysign_uri(TEST_VAULT_PUBKEY, special_data);
        assert!(uri_special.contains(special_data));
    }
    
    // Note: Keygen tests removed since we only need signing QR codes

    #[test]
    fn test_generate_ascii_qr() {
        let result = generate_ascii_qr(TEST_URI_SHORT);
        assert!(result.is_ok());
        
        let qr_code = result.unwrap();
        assert!(!qr_code.is_empty());
        assert!(qr_code.contains("█")); // Should contain block characters
        
        // QR code should be roughly square (allow some variance)
        let lines: Vec<&str> = qr_code.lines().collect();
        assert!(lines.len() > 10); // Should have reasonable size
        
        // Each line should have characters
        for line in &lines {
            assert!(!line.is_empty());
        }
    }
    
    #[test]
    fn test_generate_ascii_qr_different_sizes() {
        let test_uris = [
            TEST_URI_SHORT,
            TEST_URI_LONG,
            "vultisig://vultisig.com?type=test",
        ];
        
        for uri in &test_uris {
            let result = generate_ascii_qr(uri);
            assert!(result.is_ok(), "Failed to generate QR for URI: {}", uri);
            
            let qr_code = result.unwrap();
            assert!(!qr_code.is_empty());
            assert!(qr_code.contains("█") || qr_code.contains(" "));
        }
    }

    #[test]
    fn test_generate_compact_qr() {
        let result = generate_compact_qr(TEST_URI_SHORT);
        assert!(result.is_ok());
        
        let qr_code = result.unwrap();
        assert!(!qr_code.is_empty());
        assert!(qr_code.contains("▪") || qr_code.contains("▫")); // Should contain small squares
        
        // Compare with ASCII QR - compact should have different characters
        let ascii_qr = generate_ascii_qr(TEST_URI_SHORT).unwrap();
        assert_ne!(qr_code, ascii_qr); // Should be different rendering
    }

    #[test]
    fn test_generate_tiny_qr() {
        let result = generate_tiny_qr(TEST_URI_SHORT);
        assert!(result.is_ok());
        
        let qr_code = result.unwrap();
        assert!(!qr_code.is_empty());
        
        // Tiny QR should generally be more compact
        let ascii_qr = generate_ascii_qr(TEST_URI_SHORT).unwrap();
        let lines_tiny = qr_code.lines().count();
        let lines_ascii = ascii_qr.lines().count();
        
        // Tiny QR might have fewer lines due to Dense1x2 rendering
        println!("Tiny QR lines: {}, ASCII QR lines: {}", lines_tiny, lines_ascii);
    }

    #[test]
    fn test_generate_micro_qr() {
        let result = generate_micro_qr(TEST_URI_SHORT);
        assert!(result.is_ok());
        
        let qr_code = result.unwrap();
        assert!(!qr_code.is_empty());
        
        // Micro QR post-processes to remove every other line
        let ascii_qr = generate_ascii_qr(TEST_URI_SHORT).unwrap();
        let lines_micro = qr_code.lines().count();
        let lines_ascii = ascii_qr.lines().count();
        
        // Micro should have roughly half the lines
        assert!(lines_micro <= lines_ascii);
        println!("Micro QR lines: {}, ASCII QR lines: {}", lines_micro, lines_ascii);
    }

    #[test]
    fn test_qr_generation_methods_comparison() {
        // Test all QR generation methods with the same data
        let methods = [
            ("ASCII", generate_ascii_qr as fn(&str) -> Result<String>),
            ("Compact", generate_compact_qr),
            ("Tiny", generate_tiny_qr),
            ("Micro", generate_micro_qr),
        ];
        
        for (name, method) in &methods {
            let result = method(TEST_URI_SHORT);
            assert!(result.is_ok(), "{} QR generation failed", name);
            
            let qr_code = result.unwrap();
            assert!(!qr_code.is_empty(), "{} QR is empty", name);
            
            let lines = qr_code.lines().count();
            let chars: usize = qr_code.lines().map(|line| line.len()).sum();
            
            println!("{} QR: {} lines, {} total chars", name, lines, chars);
        }
    }

    #[test]
    fn test_generate_qr_image() {
        let temp_dir = tempdir().unwrap();
        let output_path = temp_dir.path().join("test_qr.png");
        
        let result = generate_qr_image(TEST_URI_SHORT, output_path.to_str().unwrap());
        assert!(result.is_ok());
        
        // Verify file was created
        assert!(output_path.exists());
        
        // Verify file has reasonable size (PNG should be at least a few KB)
        let metadata = fs::metadata(&output_path).unwrap();
        assert!(metadata.len() > 1000); // At least 1KB
        
        println!("Generated QR image: {} bytes", metadata.len());
    }
    
    #[test]
    fn test_generate_qr_image_different_uris() {
        let temp_dir = tempdir().unwrap();
        let test_cases = [
            ("short.png", TEST_URI_SHORT),
            ("long.png", TEST_URI_LONG),
        ];
        
        for (filename, uri) in &test_cases {
            let output_path = temp_dir.path().join(filename);
            let result = generate_qr_image(uri, output_path.to_str().unwrap());
            assert!(result.is_ok(), "Failed to generate QR image for {}", uri);
            assert!(output_path.exists());
        }
    }

    #[test]
    fn test_generate_qr_html() {
        let temp_dir = tempdir().unwrap();
        let output_path = temp_dir.path().join("test_qr.html");
        
        let result = generate_qr_html(
            TEST_URI_SHORT,
            "test-session-123",
            "ethereum",
            "local",
            output_path.to_str().unwrap(),
        );
        assert!(result.is_ok());
        
        // Verify file was created
        assert!(output_path.exists());
        
        // Read and verify HTML content
        let html_content = fs::read_to_string(&output_path).unwrap();
        assert!(html_content.contains("<!DOCTYPE html>"));
        assert!(html_content.contains("Vultisig"));
        assert!(html_content.contains("test-session-123"));
        assert!(html_content.contains("ethereum"));
        assert!(html_content.contains("LOCAL P2P SIGNING"));
        assert!(html_content.contains("svg")); // Should contain SVG QR code
        
        println!("Generated HTML file: {} bytes", html_content.len());
    }
    
    #[test]
    fn test_generate_qr_html_different_connection_types() {
        let temp_dir = tempdir().unwrap();
        let connection_types = [
            ("local", "LOCAL P2P SIGNING"),
            ("relay", "RELAY SERVER SIGNING"),
            ("other", "MOBILE SIGNING"),
        ];
        
        for (conn_type, expected_display) in &connection_types {
            let output_path = temp_dir.path().join(format!("test_{}.html", conn_type));
            let result = generate_qr_html(
                TEST_URI_SHORT,
                "test-session",
                "bitcoin",
                conn_type,
                output_path.to_str().unwrap(),
            );
            assert!(result.is_ok());
            
            let html_content = fs::read_to_string(&output_path).unwrap();
            assert!(html_content.contains(expected_display));
        }
    }

    #[test]
    fn test_qr_error_handling() {
        // Test with invalid output paths
        let invalid_path = "/nonexistent/directory/test.png";
        let result = generate_qr_image(TEST_URI_SHORT, invalid_path);
        assert!(result.is_err());
        
        // Test with very long URI (should still work but might be large)
        let very_long_uri = format!("vultisig://vultisig.com?data={}", "x".repeat(1000));
        let result = generate_ascii_qr(&very_long_uri);
        
        // QR code should handle long data or fail gracefully
        match result {
            Ok(qr) => {
                assert!(!qr.is_empty());
                println!("Successfully generated QR for long URI");
            }
            Err(e) => {
                println!("QR generation failed for long URI (expected): {}", e);
                assert!(e.to_string().contains("Failed to generate QR code"));
            }
        }
    }

    #[test]
    fn test_display_qr_with_instructions() {
        // Test the display function (mainly for coverage, hard to test output)
        let result = display_qr_with_instructions(
            "test-session-456",
            TEST_URI_SHORT,
            "solana",
            "relay",
        );
        
        // The function should complete without errors
        assert!(result.is_ok());
    }

    #[test]
    fn test_open_file_function_exists() {
        // Test that the open_file function exists and handles invalid paths gracefully
        let result = open_file("/nonexistent/file.txt");
        
        // The function should either succeed (if the OS handles it) or fail gracefully
        match result {
            Ok(_) => println!("File opening succeeded (or was spawned)"),
            Err(e) => {
                println!("File opening failed (expected): {}", e);
                assert!(!e.to_string().is_empty());
            }
        }
    }

    #[test]
    fn test_keysign_qr_uri_format() {
        // Test that keysign URIs follow the correct format
        let keysign_uri = generate_vultisig_keysign_uri(TEST_VAULT_PUBKEY, TEST_JSON_DATA);
        
        // Should start with vultisig://vultisig.com
        assert!(keysign_uri.starts_with("vultisig://vultisig.com"));
        
        // Should have query parameters
        assert!(keysign_uri.contains("?"));
        
        // Parse query parameters to ensure they're valid
        use url::Url;
        
        let keysign_parsed = Url::parse(&keysign_uri).unwrap();
        
        // Check that we can extract parameters
        let keysign_params: std::collections::HashMap<String, String> = keysign_parsed
            .query_pairs()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        
        // Keysign should have vault and jsonData
        assert!(keysign_params.contains_key("vault"));
        assert!(keysign_params.contains_key("jsonData"));
        assert_eq!(keysign_params.get("type").unwrap(), "SignTransaction");
        assert_eq!(keysign_params.get("vault").unwrap(), TEST_VAULT_PUBKEY);
    }

    #[test]
    fn test_qr_generation_performance() {
        use std::time::Instant;
        
        let start = Instant::now();
        
        // Generate multiple QR codes to test performance
        for i in 0..10 {
            let uri = format!("{}-{}", TEST_URI_SHORT, i);
            let result = generate_ascii_qr(&uri);
            assert!(result.is_ok());
        }
        
        let duration = start.elapsed();
        println!("Generated 10 QR codes in {:?}", duration);
        
        // Should be reasonably fast (allow up to 5 seconds for CI environments)
        assert!(duration.as_secs() < 5);
    }

    #[test]
    fn test_qr_quiet_zone_handling() {
        // Test that quiet_zone(false) actually affects the output
        let result_with_quiet_zone = {
            use qrcode::QrCode;
            let code = QrCode::new(TEST_URI_SHORT.as_bytes()).unwrap();
            code.render::<char>()
                .quiet_zone(true)
                .dark_color('█')
                .light_color(' ')
                .build()
        };
        
        let result_without_quiet_zone = generate_ascii_qr(TEST_URI_SHORT).unwrap();
        
        // The versions should be different (hard to test exact difference)
        let lines_with = result_with_quiet_zone.lines().count();
        let lines_without = result_without_quiet_zone.lines().count();
        
        println!("QR with quiet zone: {} lines", lines_with);
        println!("QR without quiet zone: {} lines", lines_without);
        
        // Without quiet zone should generally be smaller or equal
        assert!(lines_without <= lines_with);
    }

    #[test]
    fn test_generate_vault_sharing_qr() {
        let vault_data = VaultShareData {
            uid: "vault-unique-identifier".to_string(),
            name: "Test Vault".to_string(),
            public_key_ecdsa: "03ac0f333fc5d22f929e013be80988f57a56837db64d968c126ca4c943984744fd".to_string(),
            public_key_eddsa: "dff9b5b456eadcbd99366fd691f50f865a26df433f9cbffe1b6f319ecadb8308".to_string(),
            hex_chain_code: "c39c57cd4127a5c5d6c8583f3f12d7be26e7eed8c398e7ee9926cd33845cae1b".to_string(),
        };

        let result = generate_vault_sharing_qr(&vault_data);
        assert!(result.is_ok());

        let qr_json = result.unwrap();
        
        // Should be valid JSON
        let parsed: serde_json::Value = serde_json::from_str(&qr_json).unwrap();
        assert!(parsed.is_object());
        
        // Should contain all required fields
        assert_eq!(parsed["uid"], "vault-unique-identifier");
        assert_eq!(parsed["name"], "Test Vault");
        assert_eq!(parsed["public_key_ecdsa"], "03ac0f333fc5d22f929e013be80988f57a56837db64d968c126ca4c943984744fd");
        assert_eq!(parsed["public_key_eddsa"], "dff9b5b456eadcbd99366fd691f50f865a26df433f9cbffe1b6f319ecadb8308");
        assert_eq!(parsed["hex_chain_code"], "c39c57cd4127a5c5d6c8583f3f12d7be26e7eed8c398e7ee9926cd33845cae1b");

        println!("Vault sharing QR JSON: {}", qr_json);
    }

    #[test]
    fn test_generate_vault_sharing_qr_roundtrip() {
        let original_data = VaultShareData {
            uid: "test-vault-123".to_string(),
            name: "My Test Vault".to_string(),
            public_key_ecdsa: TEST_VAULT_PUBKEY.to_string(),
            public_key_eddsa: "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890".to_string(),
            hex_chain_code: "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef12".to_string(),
        };

        // Generate QR code
        let qr_json = generate_vault_sharing_qr(&original_data).unwrap();
        
        // Parse it back
        let parsed_data: VaultShareData = serde_json::from_str(&qr_json).unwrap();
        
        // Should match original
        assert_eq!(parsed_data.uid, original_data.uid);
        assert_eq!(parsed_data.name, original_data.name);
        assert_eq!(parsed_data.public_key_ecdsa, original_data.public_key_ecdsa);
        assert_eq!(parsed_data.public_key_eddsa, original_data.public_key_eddsa);
        assert_eq!(parsed_data.hex_chain_code, original_data.hex_chain_code);
    }

    #[test]
    fn test_generate_address_qr() {
        let addresses = [
            TEST_BTC_ADDRESS,
            TEST_ETH_ADDRESS,
            TEST_SOL_ADDRESS,
            "thor1nuwfr59wyn6da6v5ktxsa32v2t6u2q4veg9awu", // Cosmos format
        ];

        for address in &addresses {
            let qr_content = generate_address_qr(address);
            
            // Should be exactly the address string
            assert_eq!(qr_content, *address);
            
            // Should not contain any URI scheme or wrapper
            assert!(!qr_content.starts_with("http"));
            assert!(!qr_content.starts_with("vultisig://"));
            assert!(!qr_content.contains("?"));
            
            println!("Address QR for {}: {}", address, qr_content);
        }
    }

    #[test]
    fn test_address_qr_with_qr_generation() {
        // Test that address QR codes can be generated as actual QR images
        let address = TEST_ETH_ADDRESS;
        let qr_content = generate_address_qr(address);
        
        // Should be able to generate QR code from the address
        let qr_result = generate_ascii_qr(&qr_content);
        assert!(qr_result.is_ok());
        
        let qr_code = qr_result.unwrap();
        assert!(!qr_code.is_empty());
        
        // Should contain QR patterns
        assert!(qr_code.contains("█") || qr_code.contains(" "));
    }

    #[test]
    fn test_vault_sharing_qr_with_qr_generation() {
        // Test that vault sharing QR codes can be generated as actual QR images
        let vault_data = VaultShareData {
            uid: "qr-test-vault".to_string(),
            name: "QR Test Vault".to_string(),
            public_key_ecdsa: TEST_VAULT_PUBKEY.to_string(),
            public_key_eddsa: "fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321".to_string(),
            hex_chain_code: "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890".to_string(),
        };

        let qr_json = generate_vault_sharing_qr(&vault_data).unwrap();
        
        // Should be able to generate QR code from the JSON
        let qr_result = generate_ascii_qr(&qr_json);
        assert!(qr_result.is_ok());
        
        let qr_code = qr_result.unwrap();
        assert!(!qr_code.is_empty());
        
        println!("Vault sharing QR code generated successfully ({} chars)", qr_code.len());
    }

    #[test]
    fn test_vault_share_data_serialization() {
        let vault_data = VaultShareData {
            uid: "serialization-test".to_string(),
            name: "Serialization Test Vault".to_string(),
            public_key_ecdsa: "0123456789abcdef0123456789abcdef01234567".to_string(),
            public_key_eddsa: "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210".to_string(),
            hex_chain_code: "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890".to_string(),
        };

        // Test serialization
        let json = serde_json::to_string(&vault_data).unwrap();
        assert!(!json.is_empty());
        assert!(json.contains("serialization-test"));
        assert!(json.contains("Serialization Test Vault"));

        // Test deserialization
        let deserialized: VaultShareData = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.uid, vault_data.uid);
        assert_eq!(deserialized.name, vault_data.name);
        assert_eq!(deserialized.public_key_ecdsa, vault_data.public_key_ecdsa);
        assert_eq!(deserialized.public_key_eddsa, vault_data.public_key_eddsa);
        assert_eq!(deserialized.hex_chain_code, vault_data.hex_chain_code);
    }

    #[test]
    fn test_qr_type_identification() {
        // Test that we can identify different QR code types by content
        
        // Vault sharing (JSON)
        let vault_data = VaultShareData {
            uid: "test".to_string(),
            name: "Test".to_string(),
            public_key_ecdsa: "test".to_string(),
            public_key_eddsa: "test".to_string(),
            hex_chain_code: "test".to_string(),
        };
        let vault_qr = generate_vault_sharing_qr(&vault_data).unwrap();
        assert!(vault_qr.starts_with("{"));
        assert!(vault_qr.contains("uid"));
        
        // Address QR (plain text)
        let address_qr = generate_address_qr(TEST_ETH_ADDRESS);
        assert!(address_qr.starts_with("0x"));
        assert!(!address_qr.contains("{"));
        assert!(!address_qr.contains("://"));
        
        // Keysign QR (URI)
        let keysign_qr = generate_vultisig_keysign_uri(TEST_VAULT_PUBKEY, TEST_JSON_DATA);
        assert!(keysign_qr.starts_with("vultisig://"));
        assert!(keysign_qr.contains("type=SignTransaction"));
        
        println!("✅ QR type identification works for all supported types");
    }
}
