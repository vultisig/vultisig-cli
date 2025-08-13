use anyhow::{anyhow, Result};
use base64::Engine;
use flate2::{Compression, write::ZlibEncoder};
use lzma_rs::lzma_compress;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::Write;

use crate::keysign_message::{KeysignMessage, VultisigQRGenerator};

#[cfg(test)]
use std::collections::HashMap;
#[cfg(test)]
use tempfile;

/// Dense QR code handler with multi-tier optimization strategy
pub struct DenseQRHandler {
    pub relay_server: String,
    pub size_threshold: usize,
    pub qr_generator: VultisigQRGenerator,
}

/// Payload service for uploading/downloading large payloads
pub struct PayloadService {
    pub server_url: String,
    pub client: reqwest::Client,
}

/// Compression method enumeration
#[derive(Debug, Clone, Copy)]
pub enum CompressionMethod {
    Zlib,
    Lzma,
}

impl DenseQRHandler {
    /// Create a new dense QR handler
    pub fn new(vault_ecdsa_pubkey: String, relay_server: String) -> Self {
        Self {
            relay_server,
            size_threshold: 2048, // Same as Vultisig mobile app
            qr_generator: VultisigQRGenerator::new(vault_ecdsa_pubkey),
        }
    }

    /// Generate optimized QR code with automatic compression and payload upload
    pub async fn generate_optimized_qr(
        &self,
        message: &KeysignMessage,
    ) -> Result<String> {
        
        // Step 1: Serialize and compress
        let json = serde_json::to_string(message)
            .map_err(|e| anyhow!("Failed to serialize message: {}", e))?;
        
        let compressed = self.compress_data(&json, CompressionMethod::Lzma)?;
        let base64_compressed = base64::engine::general_purpose::STANDARD.encode(&compressed);
        
        println!("Original size: {} bytes", json.len());
        println!("Compressed size: {} bytes", compressed.len());
        println!("Base64 compressed size: {} bytes", base64_compressed.len());
        
        // Step 2: Check if we need to upload to relay
        if base64_compressed.len() > self.size_threshold {
            println!("Payload exceeds {} bytes, uploading to relay server...", self.size_threshold);
            
            let payload_service = PayloadService::new(&self.relay_server);
            let hash = payload_service.upload_payload(&base64_compressed).await?;
            
            // Create lightweight message with only hash
            let light_message = KeysignMessage {
                session_id: message.session_id.clone(),
                service_name: message.service_name.clone(),
                payload: None,  // Remove heavy payload
                custom_message_payload: message.custom_message_payload.clone(),
                encryption_key_hex: message.encryption_key_hex.clone(),
                use_vultisig_relay: true,  // Force relay mode for uploaded payloads
                payload_id: hash,
            };
            
            let light_json = serde_json::to_string(&light_message)?;
            let light_compressed = self.compress_data(&light_json, CompressionMethod::Zlib)?;
            let light_base64 = base64::engine::general_purpose::STANDARD.encode(&light_compressed);
            
            println!("Lightweight message size: {} bytes", light_base64.len());
            
                    // Generate QR with lightweight data (URL encode the base64)
        return Ok(format!(
            "vultisig://vultisig.com?type=SignTransaction&vault={}&jsonData={}",
            self.qr_generator.vault_ecdsa_pubkey,
            urlencoding::encode(&light_base64)
        ));
        }
        
        // Step 3: Generate standard QR code with compressed data (URL encode the base64)
        Ok(format!(
            "vultisig://vultisig.com?type=SignTransaction&vault={}&jsonData={}",
            self.qr_generator.vault_ecdsa_pubkey,
            urlencoding::encode(&base64_compressed)
        ))
    }
    
    /// Compress data using specified method
    fn compress_data(&self, data: &str, method: CompressionMethod) -> Result<Vec<u8>> {
        match method {
            CompressionMethod::Zlib => {
                let mut encoder = ZlibEncoder::new(Vec::new(), Compression::best());
                encoder.write_all(data.as_bytes())
                    .map_err(|e| anyhow!("Failed to write to zlib encoder: {}", e))?;
                encoder.finish()
                    .map_err(|e| anyhow!("Failed to finish zlib compression: {}", e))
            },
            CompressionMethod::Lzma => {
                let mut compressed = Vec::new();
                lzma_compress(&mut data.as_bytes(), &mut compressed)
                    .map_err(|e| anyhow!("Failed to compress with LZMA: {}", e))?;
                Ok(compressed)
            },
        }
    }
    
    /// Decompress data using specified method
    pub fn decompress_data(&self, compressed: &[u8], method: CompressionMethod) -> Result<String> {
        match method {
            CompressionMethod::Zlib => {
                use flate2::read::ZlibDecoder;
                use std::io::Read;
                
                let mut decoder = ZlibDecoder::new(compressed);
                let mut decompressed = String::new();
                decoder.read_to_string(&mut decompressed)
                    .map_err(|e| anyhow!("Failed to decompress with zlib: {}", e))?;
                Ok(decompressed)
            },
            CompressionMethod::Lzma => {
                use lzma_rs::lzma_decompress;
                
                let mut decompressed = Vec::new();
                let mut compressed_slice = compressed;
                lzma_decompress(&mut compressed_slice, &mut decompressed)
                    .map_err(|e| anyhow!("Failed to decompress with LZMA: {}", e))?;
                String::from_utf8(decompressed)
                    .map_err(|e| anyhow!("Failed to convert decompressed data to string: {}", e))
            },
        }
    }
    
    /// Calculate SHA256 hash of data
    fn calculate_hash(&self, data: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(data.as_bytes());
        hex::encode(hasher.finalize())
    }
    
    /// Generate QR code with optimal error correction for dense data
    pub fn generate_dense_qr_image(&self, data: &str, size: u32) -> Result<Vec<u8>> {
        use qrcode::{QrCode, EcLevel};
        
        // Use medium error correction for dense data (balances density vs reliability)
        let code = QrCode::with_error_correction_level(data, EcLevel::M)
            .map_err(|e| anyhow!("Failed to create QR code: {}", e))?;
        
        // Render QR code as a simple string representation first, then convert to image
        let string_qr = code.render::<char>()
            .quiet_zone(false)
            .module_dimensions(1, 1)
            .build();
        
        // Create a simple black and white image from the QR code
        let qr_size = code.width();
        let img_size = qr_size * 8; // Scale up for better visibility
        let mut img_buffer = image::ImageBuffer::new(img_size as u32, img_size as u32);
        
        // Parse the string representation and create image
        let lines: Vec<&str> = string_qr.lines().collect();
        for (y, line) in lines.iter().enumerate() {
            for (x, ch) in line.chars().enumerate() {
                let pixel_value = if ch == '█' || ch == '▄' || ch == '▀' { 0u8 } else { 255u8 };
                
                // Scale up the pixel
                for dy in 0..8 {
                    for dx in 0..8 {
                        let px = (x * 8 + dx) as u32;
                        let py = (y * 8 + dy) as u32;
                        if px < img_size as u32 && py < img_size as u32 {
                            img_buffer.put_pixel(px, py, image::Luma([pixel_value]));
                        }
                    }
                }
            }
        }
        
        // Convert to PNG bytes
        let mut buffer = Vec::new();
        use std::io::Cursor;
        img_buffer.write_to(&mut Cursor::new(&mut buffer), image::ImageFormat::Png)
            .map_err(|e| anyhow!("Failed to write QR image: {}", e))?;
        
        Ok(buffer)
    }
}

impl PayloadService {
    /// Create a new payload service
    pub fn new(server_url: &str) -> Self {
        Self {
            server_url: server_url.to_string(),
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .expect("Failed to create HTTP client"),
        }
    }
    
    /// Check if payload should be uploaded to relay server
    pub fn should_upload_to_relay(&self, payload: &str) -> bool {
        payload.len() > 2048 // Same threshold as Vultisig mobile app
    }
    
    /// Upload payload to relay server and return hash
    pub async fn upload_payload(&self, payload: &str) -> Result<String> {
        let hash = self.calculate_hash(payload);
        let url = format!("{}/payload/{}", self.server_url, hash);
        
        let response = self.client
            .post(&url)
            .header("Content-Type", "application/octet-stream")
            .body(payload.to_string())
            .send()
            .await
            .map_err(|e| anyhow!("Failed to upload payload: {}", e))?;
            
        if response.status().is_success() {
            println!("Successfully uploaded payload with hash: {}", hash);
            Ok(hash)
        } else {
            Err(anyhow!("Failed to upload payload: HTTP {}", response.status()))
        }
    }
    
    /// Retrieve payload from relay server by hash
    pub async fn retrieve_payload(&self, hash: &str) -> Result<String> {
        let url = format!("{}/payload/{}", self.server_url, hash);
        
        let response = self.client
            .get(&url)
            .send()
            .await
            .map_err(|e| anyhow!("Failed to retrieve payload: {}", e))?;
        
        if response.status().is_success() {
            let payload = response.text().await
                .map_err(|e| anyhow!("Failed to read payload response: {}", e))?;
            println!("Successfully retrieved payload with hash: {}", hash);
            Ok(payload)
        } else {
            Err(anyhow!("Failed to retrieve payload: HTTP {}", response.status()))
        }
    }
    
    /// Calculate SHA256 hash of payload
    fn calculate_hash(&self, data: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(data.as_bytes());
        hex::encode(hasher.finalize())
    }
}

/// Helper struct for parsing dense QR codes
#[derive(Debug, Serialize, Deserialize)]
pub struct QRCodeData {
    pub vault_pubkey: String,
    pub json_data: String,
    pub is_compressed: bool,
    pub compression_method: Option<String>,
}

impl QRCodeData {
    /// Parse QR code URL and extract components
    pub fn from_url(url: &str) -> Result<Self> {
        use url::Url;
        
        let parsed = Url::parse(url)
            .map_err(|e| anyhow!("Failed to parse QR URL: {}", e))?;
        
        // Extract query parameters
        let mut vault_pubkey = String::new();
        let mut json_data = String::new();
        
        for (key, value) in parsed.query_pairs() {
            match key.as_ref() {
                "vault" => vault_pubkey = value.to_string(),
                "jsonData" => json_data = value.to_string(),
                _ => {},
            }
        }
        
        if vault_pubkey.is_empty() || json_data.is_empty() {
            return Err(anyhow!("Missing required parameters in QR URL"));
        }
        
        Ok(Self {
            vault_pubkey,
            json_data,
            is_compressed: true, // Assume compressed by default
            compression_method: Some("lzma".to_string()),
        })
    }
    
    /// Decompress and parse the JSON data
    pub fn parse_message(&self, dense_qr: &DenseQRHandler) -> Result<KeysignMessage> {
        // URL decode first, then base64 decode
        let url_decoded = urlencoding::decode(&self.json_data)
            .map_err(|e| anyhow!("Failed to URL decode: {}", e))?;
        
        let compressed_data = base64::engine::general_purpose::STANDARD
            .decode(url_decoded.as_bytes())
            .map_err(|e| anyhow!("Failed to decode base64: {}", e))?;
        
        // Try LZMA first, then fall back to zlib
        let decompressed = dense_qr.decompress_data(&compressed_data, CompressionMethod::Lzma)
            .or_else(|_| dense_qr.decompress_data(&compressed_data, CompressionMethod::Zlib))?;
        
        // Parse JSON
        let message: KeysignMessage = serde_json::from_str(&decompressed)
            .map_err(|e| anyhow!("Failed to parse keysign message: {}", e))?;
        
        Ok(message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keysign_message::{NetworkMode, create_eth_transaction_payload, KeysignMessage};
    use std::collections::HashMap;
    use tokio_test;
    use pretty_assertions::assert_eq;
    use tempfile::tempdir;
    use base64::Engine;
    
    // Test constants
    const TEST_VAULT_PUBKEY: &str = "023e4b76861289ad4528b33c2fd21b3a5160cd37b3294234914e21efb6ed4a452b";
    const TEST_RELAY_SERVER: &str = "https://api.vultisig.com";
    const TEST_ETH_ADDRESS: &str = "0x742d35Cc6634C0532925a3b8D45C0D2C0d0Db8f7";
    const TEST_CONTRACT_ADDRESS: &str = "0x1234567890123456789012345678901234567890";
    
    fn create_test_dense_qr_handler() -> DenseQRHandler {
        DenseQRHandler::new(
            TEST_VAULT_PUBKEY.to_string(),
            TEST_RELAY_SERVER.to_string(),
        )
    }
    
    fn create_test_keysign_message() -> KeysignMessage {
        let eth_payload = create_eth_transaction_payload(
            TEST_ETH_ADDRESS,
            "1000000000000000000", // 1 ETH in wei
            1,      // chain_id
            21000,  // gas_limit
            "25000000000",  // gas_price (25 gwei)
            "1000000000",   // max_priority_fee
            TEST_VAULT_PUBKEY,
            TEST_CONTRACT_ADDRESS,
        );
        
        KeysignMessage {
            session_id: "test-session-123".to_string(),
            service_name: "Vultisig-CLI".to_string(),
            payload: Some(eth_payload),
            custom_message_payload: None,
            encryption_key_hex: "test-encryption-key".to_string(),
            use_vultisig_relay: false,
            payload_id: "test-payload-id".to_string(),
        }
    }
    
    fn create_small_test_message() -> KeysignMessage {
        KeysignMessage {
            session_id: "small-test".to_string(),
            service_name: "test-service".to_string(),
            payload: None, // Small test doesn't need full payload
            custom_message_payload: Some(crate::keysign_message::CustomMessagePayload {
                message: "test message".to_string(),
                method: "test".to_string(),
            }),
            encryption_key_hex: "encryption_key".to_string(),
            use_vultisig_relay: false,
            payload_id: "test-id".to_string(),
        }
    }
    
    fn create_large_test_message() -> KeysignMessage {
        // Create a message that will exceed the size threshold
        let large_payload = "x".repeat(3000); // Larger than 2048 bytes threshold
        
        KeysignMessage {
            session_id: "large-test-session".to_string(),
            service_name: "large-test-service".to_string(),
            payload: None, // Use custom message for large test
            custom_message_payload: Some(crate::keysign_message::CustomMessagePayload {
                message: large_payload,
                method: "test".to_string(),
            }),
            encryption_key_hex: "large_encryption_key_hex".repeat(50),
            use_vultisig_relay: false,
            payload_id: "large-test-id".to_string(),
        }
    }

    #[test]
    fn test_dense_qr_handler_creation() {
        let dense_qr = create_test_dense_qr_handler();
        
        assert_eq!(dense_qr.relay_server, TEST_RELAY_SERVER);
        assert_eq!(dense_qr.size_threshold, 2048);
        assert_eq!(dense_qr.qr_generator.vault_ecdsa_pubkey, TEST_VAULT_PUBKEY);
    }

    #[tokio::test]
    async fn test_dense_qr_compression_methods() {
        let dense_qr = create_test_dense_qr_handler();
        let message = create_test_keysign_message();
        
        // Test compression
        let original = serde_json::to_string(&message).unwrap();
        let zlib_compressed = dense_qr.compress_data(&original, CompressionMethod::Zlib).unwrap();
        let lzma_compressed = dense_qr.compress_data(&original, CompressionMethod::Lzma).unwrap();
        
        println!("Original size: {} bytes", original.len());
        println!("Zlib compressed: {} bytes ({:.1}% reduction)", 
                 zlib_compressed.len(), 
                 100.0 * (1.0 - zlib_compressed.len() as f64 / original.len() as f64));
        println!("LZMA compressed: {} bytes ({:.1}% reduction)", 
                 lzma_compressed.len(), 
                 100.0 * (1.0 - lzma_compressed.len() as f64 / original.len() as f64));
        
        // Both methods should achieve some compression
        assert!(zlib_compressed.len() < original.len());
        assert!(lzma_compressed.len() < original.len());
        
        // Test decompression
        let zlib_decompressed = dense_qr.decompress_data(&zlib_compressed, CompressionMethod::Zlib).unwrap();
        let lzma_decompressed = dense_qr.decompress_data(&lzma_compressed, CompressionMethod::Lzma).unwrap();
        
        assert_eq!(original, zlib_decompressed);
        assert_eq!(original, lzma_decompressed);
        
        // LZMA should provide better or equal compression for structured data
        assert!(lzma_compressed.len() <= zlib_compressed.len());
    }
    
    #[test]
    fn test_compression_decompression_roundtrip() {
        let dense_qr = create_test_dense_qr_handler();
        
        let repeated_text = "repeated text ".repeat(100);
        let test_data = [
            "simple test string",
            r#"{"json": "data", "with": ["arrays", "and", "objects"]}"#,
            &repeated_text,
            "mixed data with numbers 123456789 and symbols !@#$%^&*()",
        ];
        
        for (i, data) in test_data.iter().enumerate() {
            println!("Testing data set {}: {} chars", i, data.len());
            
            // Test Zlib
            let zlib_compressed = dense_qr.compress_data(data, CompressionMethod::Zlib).unwrap();
            let zlib_decompressed = dense_qr.decompress_data(&zlib_compressed, CompressionMethod::Zlib).unwrap();
            assert_eq!(*data, zlib_decompressed, "Zlib roundtrip failed for data set {}", i);
            
            // Test LZMA
            let lzma_compressed = dense_qr.compress_data(data, CompressionMethod::Lzma).unwrap();
            let lzma_decompressed = dense_qr.decompress_data(&lzma_compressed, CompressionMethod::Lzma).unwrap();
            assert_eq!(*data, lzma_decompressed, "LZMA roundtrip failed for data set {}", i);
            
            println!("  Zlib: {} -> {} bytes", data.len(), zlib_compressed.len());
            println!("  LZMA: {} -> {} bytes", data.len(), lzma_compressed.len());
        }
    }
    
    #[test]
    fn test_compression_error_handling() {
        let dense_qr = create_test_dense_qr_handler();
        
        // Test decompressing invalid data
        let invalid_data = vec![0x00, 0x01, 0x02, 0x03];
        
        let zlib_result = dense_qr.decompress_data(&invalid_data, CompressionMethod::Zlib);
        assert!(zlib_result.is_err());
        
        let lzma_result = dense_qr.decompress_data(&invalid_data, CompressionMethod::Lzma);
        assert!(lzma_result.is_err());
    }

    #[test]
    fn test_calculate_hash() {
        let dense_qr = create_test_dense_qr_handler();
        
        let test_data = "test data for hashing";
        let hash1 = dense_qr.calculate_hash(test_data);
        let hash2 = dense_qr.calculate_hash(test_data);
        
        // Same input should produce same hash
        assert_eq!(hash1, hash2);
        
        // Hash should be 64 characters (32 bytes in hex)
        assert_eq!(hash1.len(), 64);
        
        // Different input should produce different hash
        let hash3 = dense_qr.calculate_hash("different data");
        assert_ne!(hash1, hash3);
        
        // Hash should only contain hex characters
        assert!(hash1.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[tokio::test]
    async fn test_generate_optimized_qr_small_payload() {
        let dense_qr = create_test_dense_qr_handler();
        let message = create_small_test_message();
        
        // Small payload should not trigger relay upload
        let qr_uri = dense_qr.generate_optimized_qr(&message).await.unwrap();
        
        // Should be a standard Vultisig URL
        assert!(qr_uri.starts_with("vultisig://vultisig.com"));
        assert!(qr_uri.contains("type=SignTransaction"));
        assert!(qr_uri.contains(&format!("vault={}", TEST_VAULT_PUBKEY)));
        assert!(qr_uri.contains("jsonData="));
        
        println!("Small payload QR URI length: {}", qr_uri.len());
    }
    
    // Note: This test is commented out because it requires a real relay server
    // In a real test environment, you would mock the HTTP client or use a test server
    /*
    #[tokio::test]
    async fn test_generate_optimized_qr_large_payload() {
        let dense_qr = create_test_dense_qr_handler();
        let message = create_large_test_message();
        
        // Large payload should trigger relay upload (if server is available)
        let qr_uri = dense_qr.generate_optimized_qr(&message).await;
        
        match qr_uri {
            Ok(uri) => {
                assert!(uri.starts_with("vultisig://vultisig.com"));
                assert!(uri.contains("jsonData="));
                println!("Large payload QR URI length: {}", uri.len());
            }
            Err(e) => {
                // Expected if relay server is not available
                println!("Relay upload failed (expected in test): {}", e);
            }
        }
    }
    */

    #[test]
    fn test_generate_dense_qr_image() {
        let dense_qr = create_test_dense_qr_handler();
        let test_data = "vultisig://vultisig.com?type=test&data=example";
        
        let result = dense_qr.generate_dense_qr_image(test_data, 256);
        assert!(result.is_ok());
        
        let image_data = result.unwrap();
        assert!(!image_data.is_empty());
        
        // Should be PNG format (starts with PNG signature)
        assert_eq!(&image_data[0..8], &[137, 80, 78, 71, 13, 10, 26, 10]);
        
        println!("Generated QR image: {} bytes", image_data.len());
    }
    
    #[test]
    fn test_generate_dense_qr_image_different_sizes() {
        let dense_qr = create_test_dense_qr_handler();
        let test_data = "test data";
        
        let sizes = [128, 256, 512];
        
        for size in &sizes {
            let result = dense_qr.generate_dense_qr_image(test_data, *size);
            assert!(result.is_ok(), "Failed to generate QR image with size {}", size);
            
            let image_data = result.unwrap();
            assert!(!image_data.is_empty());
            
            println!("QR image at size {}: {} bytes", size, image_data.len());
        }
    }

    #[test]
    fn test_payload_service_creation() {
        let payload_service = PayloadService::new(TEST_RELAY_SERVER);
        
        assert_eq!(payload_service.server_url, TEST_RELAY_SERVER);
        // HTTP client should be created successfully
    }
    
    #[test]
    fn test_payload_service_should_upload_threshold() {
        let payload_service = PayloadService::new(TEST_RELAY_SERVER);
        
        // Small payload should not be uploaded
        let small_payload = "x".repeat(1000);
        assert!(!payload_service.should_upload_to_relay(&small_payload));
        
        // Large payload should be uploaded
        let large_payload = "x".repeat(3000);
        assert!(payload_service.should_upload_to_relay(&large_payload));
        
        // Exactly at threshold
        let threshold_payload = "x".repeat(2048);
        assert!(!payload_service.should_upload_to_relay(&threshold_payload));
        
        let over_threshold_payload = "x".repeat(2049);
        assert!(payload_service.should_upload_to_relay(&over_threshold_payload));
    }
    
    #[test]
    fn test_payload_service_calculate_hash() {
        let payload_service = PayloadService::new(TEST_RELAY_SERVER);
        
        let test_payload = "test payload data";
        let hash1 = payload_service.calculate_hash(test_payload);
        let hash2 = payload_service.calculate_hash(test_payload);
        
        // Same payload should produce same hash
        assert_eq!(hash1, hash2);
        
        // Hash should be valid SHA256 (64 hex characters)
        assert_eq!(hash1.len(), 64);
        assert!(hash1.chars().all(|c| c.is_ascii_hexdigit()));
        
        // Different payload should produce different hash
        let hash3 = payload_service.calculate_hash("different payload");
        assert_ne!(hash1, hash3);
    }

    #[test]
    fn test_qr_code_data_from_url() {
        let test_urls = [
            "vultisig://vultisig.com?type=SignTransaction&vault=023e4b76861289ad4528b33c2fd21b3a5160cd37b3294234914e21efb6ed4a452b&jsonData=eyJzZXNzaW9uX2lkIjoidGVzdCJ9",
            "vultisig://vultisig.com?vault=abc123&jsonData=def456&type=SignTransaction",
        ];
        
        for (i, url) in test_urls.iter().enumerate() {
            let qr_data = QRCodeData::from_url(url);
            assert!(qr_data.is_ok(), "Failed to parse URL {}: {}", i, url);
            
            let data = qr_data.unwrap();
            assert!(!data.vault_pubkey.is_empty());
            assert!(!data.json_data.is_empty());
            assert!(data.is_compressed);
            assert_eq!(data.compression_method, Some("lzma".to_string()));
            
            println!("Parsed URL {}: vault={}, jsonData length={}", 
                     i, data.vault_pubkey, data.json_data.len());
        }
    }
    
    #[test]
    fn test_qr_code_data_from_invalid_urls() {
        let invalid_urls = [
            "not a url at all",
            "vultisig://example.com", // Missing required parameters
            "vultisig://vultisig.com?vault=only_vault", // Missing jsonData
            "vultisig://vultisig.com?jsonData=only_data", // Missing vault
        ];
        
        for (i, url) in invalid_urls.iter().enumerate() {
            let result = QRCodeData::from_url(url);
            assert!(result.is_err(), "Should have failed to parse invalid URL {}: {}", i, url);
            
            let error = result.unwrap_err();
            assert!(!error.to_string().is_empty());
            println!("Invalid URL {} failed correctly: {}", i, error);
        }
    }
    
    #[test]
    fn test_qr_code_data_parse_message() {
        let dense_qr = create_test_dense_qr_handler();
        
        // Create a test message, compress it, and encode it as a QR would
        let original_message = create_small_test_message();
        let json_data = serde_json::to_string(&original_message).unwrap();
        let compressed = dense_qr.compress_data(&json_data, CompressionMethod::Lzma).unwrap();
        let base64_data = base64::engine::general_purpose::STANDARD.encode(&compressed);
        let url_encoded = urlencoding::encode(&base64_data);
        
        // Create QRCodeData
        let qr_data = QRCodeData {
            vault_pubkey: TEST_VAULT_PUBKEY.to_string(),
            json_data: url_encoded.to_string(),
            is_compressed: true,
            compression_method: Some("lzma".to_string()),
        };
        
        // Parse the message back
        let parsed_message = qr_data.parse_message(&dense_qr);
        assert!(parsed_message.is_ok());
        
        let message = parsed_message.unwrap();
        assert_eq!(message.session_id, original_message.session_id);
        assert_eq!(message.service_name, original_message.service_name);
    }
    
    #[test]
    fn test_qr_code_data_parse_message_fallback() {
        let dense_qr = create_test_dense_qr_handler();
        
        // Create test data compressed with Zlib (fallback method)
        let original_message = create_small_test_message();
        let json_data = serde_json::to_string(&original_message).unwrap();
        let compressed = dense_qr.compress_data(&json_data, CompressionMethod::Zlib).unwrap();
        let base64_data = base64::engine::general_purpose::STANDARD.encode(&compressed);
        let url_encoded = urlencoding::encode(&base64_data);
        
        let qr_data = QRCodeData {
            vault_pubkey: TEST_VAULT_PUBKEY.to_string(),
            json_data: url_encoded.to_string(),
            is_compressed: true,
            compression_method: Some("zlib".to_string()),
        };
        
        // Should still parse correctly (LZMA fails, falls back to Zlib)
        let parsed_message = qr_data.parse_message(&dense_qr);
        assert!(parsed_message.is_ok());
        
        let message = parsed_message.unwrap();
        assert_eq!(message.session_id, original_message.session_id);
    }
    
    #[test]
    fn test_compression_method_debug_display() {
        let methods = [CompressionMethod::Zlib, CompressionMethod::Lzma];
        
        for method in &methods {
            let debug_str = format!("{:?}", method);
            assert!(!debug_str.is_empty());
            println!("Compression method debug: {}", debug_str);
        }
    }
    
    #[test]
    fn test_qr_code_data_debug_display() {
        let qr_data = QRCodeData {
            vault_pubkey: "test_vault".to_string(),
            json_data: "test_data".to_string(),
            is_compressed: true,
            compression_method: Some("lzma".to_string()),
        };
        
        let debug_str = format!("{:?}", qr_data);
        assert!(debug_str.contains("test_vault"));
        assert!(debug_str.contains("test_data"));
        assert!(debug_str.contains("true"));
        assert!(debug_str.contains("lzma"));
    }
    
    #[test]
    fn test_base64_url_encoding_roundtrip() {
        let test_data = "test data with special chars !@#$%^&*()";
        
        // Encode as base64, then URL encode
        let base64_encoded = base64::engine::general_purpose::STANDARD.encode(test_data);
        let url_encoded = urlencoding::encode(&base64_encoded);
        
        // Decode URL, then base64
        let url_decoded = urlencoding::decode(&url_encoded).unwrap();
        let base64_decoded = base64::engine::general_purpose::STANDARD.decode(url_decoded.as_bytes()).unwrap();
        let final_data = String::from_utf8(base64_decoded).unwrap();
        
        assert_eq!(test_data, final_data);
    }
    
    #[test]
    fn test_error_message_quality() {
        let dense_qr = create_test_dense_qr_handler();
        
        // Test invalid compression data
        let invalid_data = vec![0xFF, 0xFE, 0xFD];
        
        let zlib_error = dense_qr.decompress_data(&invalid_data, CompressionMethod::Zlib)
            .unwrap_err();
        assert!(zlib_error.to_string().contains("Failed to decompress with zlib"));
        
        let lzma_error = dense_qr.decompress_data(&invalid_data, CompressionMethod::Lzma)
            .unwrap_err();
        assert!(lzma_error.to_string().contains("Failed to decompress with LZMA"));
    }
    
    #[test]
    fn test_performance_compression_comparison() {
        let dense_qr = create_test_dense_qr_handler();
        let message = create_test_keysign_message();
        let json_data = serde_json::to_string(&message).unwrap();
        
        use std::time::Instant;
        
        // Test Zlib performance
        let start_zlib = Instant::now();
        let zlib_compressed = dense_qr.compress_data(&json_data, CompressionMethod::Zlib).unwrap();
        let zlib_duration = start_zlib.elapsed();
        
        // Test LZMA performance
        let start_lzma = Instant::now();
        let lzma_compressed = dense_qr.compress_data(&json_data, CompressionMethod::Lzma).unwrap();
        let lzma_duration = start_lzma.elapsed();
        
        println!("Zlib: {} bytes in {:?}", zlib_compressed.len(), zlib_duration);
        println!("LZMA: {} bytes in {:?}", lzma_compressed.len(), lzma_duration);
        
        // Both should complete in reasonable time (allow up to 1 second in CI)
        assert!(zlib_duration.as_secs() < 1);
        assert!(lzma_duration.as_secs() < 1);
    }
    
    // Integration test for the complete QR generation flow
    #[test]
    fn test_complete_qr_generation_flow() {
        let dense_qr = create_test_dense_qr_handler();
        let small_message = create_small_test_message();
        
        // Generate QR URI (this would normally be async for large payloads)
        let json_data = serde_json::to_string(&small_message).unwrap();
        let compressed = dense_qr.compress_data(&json_data, CompressionMethod::Lzma).unwrap();
        let base64_data = base64::engine::general_purpose::STANDARD.encode(&compressed);
        let url_encoded = urlencoding::encode(&base64_data);
        
        let qr_uri = format!(
            "vultisig://vultisig.com?type=SignTransaction&vault={}&jsonData={}",
            TEST_VAULT_PUBKEY, url_encoded
        );
        
        // Parse the QR URI back
        let qr_data = QRCodeData::from_url(&qr_uri).unwrap();
        let parsed_message = qr_data.parse_message(&dense_qr).unwrap();
        
        // Should match original message
        assert_eq!(parsed_message.session_id, small_message.session_id);
        assert_eq!(parsed_message.service_name, small_message.service_name);
        assert_eq!(parsed_message.payload, small_message.payload);
        
        println!("Complete QR generation flow test passed");
    }
}
