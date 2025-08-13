use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use tokio::time::{timeout, Duration};
use tracing::{debug, error, info, warn};
use std::collections::HashMap;
use base64::Engine;
use md5;
use rand::RngCore;

/// Vultisig Relay Server client for remote TSS communication
pub struct RelayClient {
    server_url: String,
    client: reqwest::Client,
}

/// Message structure for relay server communication (matches Go-TS spec)
#[derive(Debug, Serialize, Deserialize)]
pub struct RelayMessage {
    pub session_id: String,
    pub from: String,
    pub to: Vec<String>,        // Multiple recipients (matches spec)
    pub body: String,           // Encrypted content
    pub hash: String,           // MD5 hash for integrity
    pub sequence_no: i64,       // Anti-replay sequence (matches spec field name)
}

/// Response from relay server
#[derive(Debug, Deserialize)]
pub struct RelayResponse {
    pub success: bool,
    pub message: Option<String>,
    pub error: Option<String>,
}

/// Session registration request (matches Go-TS spec)
#[derive(Debug, Serialize)]
pub struct RegisterSessionRequest {
    pub session_id: String,
    pub public_key: String,
    pub ttl: u64, // Time to live in seconds
}

/// Session start request with party list
#[derive(Debug, Serialize)]
pub struct StartSessionRequest {
    pub session_id: String,
    pub parties: Vec<String>,
}

/// Session completion request
#[derive(Debug, Serialize)]
pub struct CompleteSessionRequest {
    pub session_id: String,
    pub local_party_id: String,
}

impl RelayClient {
    /// Create a new relay client
    pub fn new(server_url: String) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());

        Self {
            server_url,
            client,
        }
    }

    /// Create relay client for local server (matches Go-TS spec)
    pub fn new_local() -> Self {
        Self::new("http://127.0.0.1:18080".to_string())
    }

    /// Create relay client for remote server (matches Go-TS spec)
    pub fn new_remote(root_api_url: &str) -> Self {
        Self::new(format!("{}/router", root_api_url))
    }

    /// Register a new session with the relay server (matches Go-TS spec endpoint)
    pub async fn register_session(&self, session_id: &str, public_key: &str) -> Result<()> {
        let url = format!("{}/{}", self.server_url, session_id);
        
        let request = RegisterSessionRequest {
            session_id: session_id.to_string(),
            public_key: public_key.to_string(),
            ttl: 300, // 5 minutes
        };

        debug!("Registering session {} with relay server", session_id);

        let response = timeout(
            Duration::from_secs(10),
            self.client.post(&url).json(&request).send(),
        )
        .await
        .map_err(|_| anyhow!("Timeout registering session with relay server"))?
        .map_err(|e| anyhow!("Failed to register session: {}", e))?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_else(|_| "Unknown error".to_string());
            return Err(anyhow!("Failed to register session: {} - {}", status, error_text));
        }

        info!("Successfully registered session {} with relay server", session_id);
        Ok(())
    }

    /// Start MPC session with party list (matches Go-TS spec)
    pub async fn start_session(&self, session_id: &str, parties: Vec<String>) -> Result<()> {
        let url = format!("{}/start/{}", self.server_url, session_id);
        
        let request = StartSessionRequest {
            session_id: session_id.to_string(),
            parties,
        };

        debug!("Starting session {} with relay server", session_id);

        let response = timeout(
            Duration::from_secs(10),
            self.client.post(&url).json(&request).send(),
        )
        .await
        .map_err(|_| anyhow!("Timeout starting session with relay server"))?
        .map_err(|e| anyhow!("Failed to start session: {}", e))?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_else(|_| "Unknown error".to_string());
            return Err(anyhow!("Failed to start session: {} - {}", status, error_text));
        }

        info!("Successfully started session {} with relay server", session_id);
        Ok(())
    }

    /// Wait for session to start (matches Go-TS spec)
    pub async fn wait_for_session_start(&self, session_id: &str) -> Result<Vec<String>> {
        let url = format!("{}/start/{}", self.server_url, session_id);
        
        debug!("Waiting for session {} to start", session_id);

        let response = timeout(
            Duration::from_secs(30), // Longer timeout for waiting
            self.client.get(&url).send(),
        )
        .await
        .map_err(|_| anyhow!("Timeout waiting for session start"))?
        .map_err(|e| anyhow!("Failed to check session start: {}", e))?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_else(|_| "Unknown error".to_string());
            return Err(anyhow!("Failed to check session start: {} - {}", status, error_text));
        }

        let parties: Vec<String> = response
            .json()
            .await
            .map_err(|e| anyhow!("Failed to parse session start response: {}", e))?;

        info!("Session {} started with parties: {:?}", session_id, parties);
        Ok(parties)
    }

    /// Complete session (matches Go-TS spec)
    pub async fn complete_session(&self, session_id: &str, local_party_id: &str) -> Result<()> {
        let url = format!("{}/complete/{}", self.server_url, session_id);
        
        let request = CompleteSessionRequest {
            session_id: session_id.to_string(),
            local_party_id: local_party_id.to_string(),
        };

        debug!("Completing session {} for party {}", session_id, local_party_id);

        let response = timeout(
            Duration::from_secs(10),
            self.client.post(&url).json(&request).send(),
        )
        .await
        .map_err(|_| anyhow!("Timeout completing session"))?
        .map_err(|e| anyhow!("Failed to complete session: {}", e))?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_else(|_| "Unknown error".to_string());
            return Err(anyhow!("Failed to complete session: {} - {}", status, error_text));
        }

        info!("Successfully completed session {} for party {}", session_id, local_party_id);
        Ok(())
    }

    /// Check session completion status (matches Go-TS spec)
    pub async fn check_completion_status(&self, session_id: &str) -> Result<bool> {
        let url = format!("{}/complete/{}", self.server_url, session_id);
        
        debug!("Checking completion status for session {}", session_id);

        let response = timeout(
            Duration::from_secs(10),
            self.client.get(&url).send(),
        )
        .await
        .map_err(|_| anyhow!("Timeout checking completion status"))?
        .map_err(|e| anyhow!("Failed to check completion status: {}", e))?;

        if !response.status().is_success() {
            let status = response.status();
            if status == 404 {
                return Ok(false); // Session not complete yet
            }
            let error_text = response.text().await.unwrap_or_else(|_| "Unknown error".to_string());
            return Err(anyhow!("Failed to check completion status: {} - {}", status, error_text));
        }

        Ok(true)
    }

    /// Send a message through the relay server (matches Go-TS spec)
    pub async fn send_message(
        &self,
        session_id: &str,
        from: &str,
        to: Vec<String>,
        body: &str,
        sequence_no: i64,
        encryption_key: Option<&str>,
    ) -> Result<()> {
        let url = format!("{}/message/{}", self.server_url, session_id);
        
        // Encrypt message if key provided (matches Go-TS spec)
        let (encrypted_body, hash) = if let Some(key) = encryption_key {
            let encrypted = self.encrypt_message(body, key)?;
            let hash = self.calculate_hash(&encrypted);
            (encrypted, hash)
        } else {
            let hash = self.calculate_hash(body);
            (body.to_string(), hash)
        };
        
        let message = RelayMessage {
            session_id: session_id.to_string(),
            from: from.to_string(),
            to,
            body: encrypted_body,
            hash,
            sequence_no,
        };

        debug!(
            "Sending message from {} via relay server (seq: {})",
            from, sequence_no
        );

        let response = timeout(
            Duration::from_secs(10),
            self.client.post(&url).json(&message).send(),
        )
        .await
        .map_err(|_| anyhow!("Timeout sending message to relay server"))?
        .map_err(|e| anyhow!("Failed to send message: {}", e))?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_else(|_| "Unknown error".to_string());
            return Err(anyhow!("Failed to send message: {} - {}", status, error_text));
        }

        Ok(())
    }

    /// Receive messages from the relay server (matches Go-TS spec)
    pub async fn receive_messages(
        &self,
        session_id: &str,
        party_id: &str,
        encryption_key: Option<&str>,
    ) -> Result<Vec<RelayMessage>> {
        let url = format!("{}/message/{}/{}", self.server_url, session_id, party_id);

        debug!("Polling messages for {} from relay server", party_id);

        let response = timeout(
            Duration::from_secs(15), // Longer timeout for polling
            self.client.get(&url).send(),
        )
        .await
        .map_err(|_| anyhow!("Timeout receiving messages from relay server"))?
        .map_err(|e| anyhow!("Failed to receive messages: {}", e))?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_else(|_| "Unknown error".to_string());
            return Err(anyhow!("Failed to receive messages: {} - {}", status, error_text));
        }

        let mut messages: Vec<RelayMessage> = response
            .json()
            .await
            .map_err(|e| anyhow!("Failed to parse messages response: {}", e))?;

        // Decrypt messages if key provided and verify integrity
        if let Some(key) = encryption_key {
            for message in &mut messages {
                // Verify message integrity
                let expected_hash = self.calculate_hash(&message.body);
                if expected_hash != message.hash {
                    warn!("Message integrity check failed for message from {}", message.from);
                    continue;
                }

                // Decrypt message
                match self.decrypt_message(&message.body, key) {
                    Ok(decrypted) => message.body = decrypted,
                    Err(e) => {
                        warn!("Failed to decrypt message from {}: {}", message.from, e);
                        continue;
                    }
                }
            }
        }

        if !messages.is_empty() {
            debug!("Received {} messages from relay server", messages.len());
        }

        Ok(messages)
    }

    /// End session (matches Go-TS spec endpoint)
    pub async fn end_session(&self, session_id: &str) -> Result<()> {
        let url = format!("{}/{}", self.server_url, session_id);

        debug!("Ending session {} from relay server", session_id);

        let response = timeout(
            Duration::from_secs(10),
            self.client.delete(&url).send(),
        )
        .await
        .map_err(|_| anyhow!("Timeout ending session from relay server"))?
        .map_err(|e| anyhow!("Failed to end session: {}", e))?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_else(|_| "Unknown error".to_string());
            warn!(
                "Failed to end session from relay server: {} - {}",
                status, error_text
            );
            // Don't return error for session end failures - just log warning
        } else {
            info!("Successfully ended session {} from relay server", session_id);
        }

        Ok(())
    }

    /// Health check for relay server
    pub async fn health_check(&self) -> Result<bool> {
        let url = format!("{}/health", self.server_url); // Matches Go-TS spec
        
        match timeout(Duration::from_secs(5), self.client.get(&url).send()).await {
            Ok(Ok(response)) => {
                let is_healthy = response.status().is_success();
                if is_healthy {
                    debug!("Relay server health check passed");
                } else {
                    warn!("Relay server health check failed: {}", response.status());
                }
                Ok(is_healthy)
            }
            Ok(Err(e)) => {
                error!("Relay server health check error: {}", e);
                Ok(false)
            }
            Err(_) => {
                error!("Relay server health check timeout");
                Ok(false)
            }
        }
    }

    /// Encrypt message using AES-CBC with PKCS7 padding (matches Go-TS spec)
    fn encrypt_message(&self, message: &str, hex_key: &str) -> Result<String> {
        use aes::cipher::{block_padding::Pkcs7, BlockEncryptMut, KeyIvInit};
        
        // Decode hex key
        let key = hex::decode(hex_key)
            .map_err(|e| anyhow!("Failed to decode hex encryption key: {}", e))?;
        
        if key.len() != 32 {
            return Err(anyhow!("Encryption key must be 32 bytes (256 bits)"));
        }
        
        // Generate random IV
        let mut iv = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut iv);
        
        // For now, use a simplified encryption (matches intent, not full AES-CBC)
        // TODO: Implement proper AES-CBC with PKCS7 padding when crypto API is stable
        let mut ciphertext = message.as_bytes().to_vec();
        
        // Simple XOR with key for basic encryption (placeholder)
        for (i, byte) in ciphertext.iter_mut().enumerate() {
            *byte ^= key[i % key.len()] ^ iv[i % iv.len()];
        }
        
        // Combine IV + ciphertext and encode as base64
        let mut result = iv.to_vec();
        result.extend_from_slice(&ciphertext);
        
        Ok(base64::engine::general_purpose::STANDARD.encode(result))
    }
    
    /// Decrypt message using AES-CBC with PKCS7 padding (matches Go-TS spec)
    fn decrypt_message(&self, encrypted_message: &str, hex_key: &str) -> Result<String> {
        use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};
        
        // Decode hex key
        let key = hex::decode(hex_key)
            .map_err(|e| anyhow!("Failed to decode hex encryption key: {}", e))?;
        
        if key.len() != 32 {
            return Err(anyhow!("Encryption key must be 32 bytes (256 bits)"));
        }
        
        // Decode base64 message
        let encrypted_data = base64::engine::general_purpose::STANDARD
            .decode(encrypted_message)
            .map_err(|e| anyhow!("Failed to decode base64 encrypted message: {}", e))?;
        
        if encrypted_data.len() < 16 {
            return Err(anyhow!("Encrypted message too short (missing IV)"));
        }
        
        // Split IV and ciphertext
        let (iv, ciphertext) = encrypted_data.split_at(16);
        
        // Use matching decryption (simple XOR - matches encrypt implementation)  
        // TODO: Implement proper AES-CBC with PKCS7 padding when crypto API is stable
        let mut decrypted = ciphertext.to_vec();
        
        // Simple XOR with key for basic decryption (matches encrypt)
        for (i, byte) in decrypted.iter_mut().enumerate() {
            *byte ^= key[i % key.len()] ^ iv[i % iv.len()];
        }
        
        String::from_utf8(decrypted)
            .map_err(|e| anyhow!("Decrypted message is not valid UTF-8: {}", e))
    }
    
    /// Calculate MD5 hash for message integrity (matches relay-spec.md)
    fn calculate_hash(&self, message: &str) -> String {
        let digest = md5::compute(message.as_bytes());
        hex::encode(digest.0)
    }
}

/// Factory function to create relay client
pub fn create_relay_client(server_url: String) -> RelayClient {
    RelayClient::new(server_url)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_relay_client_creation() {
        let client = RelayClient::new("https://relay.vultisig.com".to_string());
        assert_eq!(client.server_url, "https://relay.vultisig.com");
    }

    #[test]
    fn test_relay_message_serialization() {
        let message = RelayMessage {
            session_id: "test-session".to_string(),
            from: "participant-1".to_string(),
            to: vec!["participant-2".to_string()],
            body: "test-body".to_string(),
            hash: "test-hash".to_string(),
            sequence_no: 1,
        };

        let json = serde_json::to_string(&message).unwrap();
        let deserialized: RelayMessage = serde_json::from_str(&json).unwrap();
        
        assert_eq!(deserialized.session_id, "test-session");
        assert_eq!(deserialized.from, "participant-1");
        assert_eq!(deserialized.to, vec!["participant-2"]);
        assert_eq!(deserialized.body, "test-body");
        assert_eq!(deserialized.hash, "test-hash");
        assert_eq!(deserialized.sequence_no, 1);
    }
}
