use anyhow::{anyhow, Result};

use sha3::Digest;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::time::{Duration, Instant};
use uuid::Uuid;

#[cfg(test)]
use futures_util;

// Include the generated protobuf code
pub mod commondata {
    include!(concat!(env!("OUT_DIR"), "/commondata.rs"));
}

pub use commondata::{SigningRequest, SigningResult, SessionInfo};

/// Session state for tracking signing requests
#[derive(Debug, Clone)]
pub struct Session {
    pub id: String,
    pub network: String,
    pub message_type: String,
    pub payload_hash: Vec<u8>,
    pub payload_bytes: Vec<u8>,
    pub metadata: HashMap<String, String>,
    pub created_at: Instant,
    pub status: SessionStatus,
}

#[derive(Debug, Clone, PartialEq)]
pub enum SessionStatus {
    Pending,
    WaitingForMobile,
    Completed,
    Failed(String),
}

/// Session manager for coordinating signing requests with mobile devices
#[derive(Debug, Clone)]
pub struct SessionManager {
    sessions: Arc<RwLock<HashMap<String, Session>>>,
    results: Arc<RwLock<HashMap<String, SigningResult>>>,
    cleanup_interval: Duration,
}

impl SessionManager {
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
            results: Arc::new(RwLock::new(HashMap::new())),
            cleanup_interval: Duration::from_secs(300), // 5 minutes
        }
    }

    /// Create a new signing session
    pub async fn create_session(
        &self,
        network: String,
        message_type: String,
        payload_bytes: Vec<u8>,
        metadata: HashMap<String, String>,
    ) -> Result<String> {
        let session_id = Uuid::new_v4().to_string();
        let payload_hash = sha3::Keccak256::digest(&payload_bytes).to_vec();

        let session = Session {
            id: session_id.clone(),
            network,
            message_type,
            payload_hash,
            payload_bytes,
            metadata,
            created_at: Instant::now(),
            status: SessionStatus::Pending,
        };

        let mut sessions = self.sessions.write().await;
        sessions.insert(session_id.clone(), session);

        Ok(session_id)
    }

    /// Get a session by ID
    pub async fn get_session(&self, session_id: &str) -> Option<Session> {
        let sessions = self.sessions.read().await;
        sessions.get(session_id).cloned()
    }

    /// Update session status
    pub async fn update_session_status(&self, session_id: &str, status: SessionStatus) -> Result<()> {
        let mut sessions = self.sessions.write().await;
        if let Some(session) = sessions.get_mut(session_id) {
            session.status = status;
            Ok(())
        } else {
            Err(anyhow!("Session not found: {}", session_id))
        }
    }

    /// Store signing result
    pub async fn store_result(&self, session_id: String, result: SigningResult) -> Result<()> {
        let mut results = self.results.write().await;
        results.insert(session_id, result);
        Ok(())
    }

    /// Get signing result
    pub async fn get_result(&self, session_id: &str) -> Option<SigningResult> {
        let results = self.results.read().await;
        results.get(session_id).cloned()
    }

    /// Wait for signing result with timeout
    pub async fn wait_for_result(&self, session_id: &str, timeout: Duration) -> Result<SigningResult> {
        let start = Instant::now();
        
        loop {
            if let Some(result) = self.get_result(session_id).await {
                return Ok(result);
            }

            if start.elapsed() > timeout {
                return Err(anyhow!("Timeout waiting for signing result"));
            }

            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    /// Clean up expired sessions
    pub async fn cleanup_expired_sessions(&self) {
        let mut sessions = self.sessions.write().await;
        let mut results = self.results.write().await;
        
        let now = Instant::now();
        let expired_ids: Vec<String> = sessions
            .iter()
            .filter(|(_, session)| now.duration_since(session.created_at) > self.cleanup_interval)
            .map(|(id, _)| id.clone())
            .collect();

        for id in expired_ids {
            sessions.remove(&id);
            results.remove(&id);
        }
    }

    /// Start cleanup task
    pub async fn start_cleanup_task(&self) {
        let manager = self.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            loop {
                interval.tick().await;
                manager.cleanup_expired_sessions().await;
            }
        });
    }

    /// Convert session to SigningRequest protobuf message
    pub fn session_to_signing_request(&self, session: &Session) -> SigningRequest {
        SigningRequest {
            session_id: session.id.clone(),
            network: session.network.clone(),
            message_type: session.message_type.clone(),
            payload_hash: session.payload_hash.clone(),
            payload_bytes: session.payload_bytes.clone(),
            metadata: session.metadata.clone(),
        }
    }

    /// Create SessionInfo for QR code generation
    pub fn create_session_info(
        &self,
        session_id: String,
        host: String,
        port: u32,
        network: String,
    ) -> SessionInfo {
        SessionInfo {
            session_id,
            connection_type: "local".to_string(),
            host,
            port,
            network,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        }
    }
}

impl Default for SessionManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::{sleep, Duration};
    use tokio_test;
    use pretty_assertions::assert_eq;
    use tokio::time::Instant;

    fn create_test_session_manager() -> SessionManager {
        SessionManager::new()
    }

    fn create_test_metadata() -> HashMap<String, String> {
        let mut metadata = HashMap::new();
        metadata.insert("chain_id".to_string(), "1".to_string());
        metadata.insert("gas_limit".to_string(), "21000".to_string());
        metadata.insert("gas_price".to_string(), "20000000000".to_string());
        metadata
    }

    #[tokio::test]
    async fn test_session_manager_creation() {
        let manager = create_test_session_manager();
        
        // Check initial state
        assert_eq!(manager.sessions.read().await.len(), 0);
        assert_eq!(manager.results.read().await.len(), 0);
        assert_eq!(manager.cleanup_interval, Duration::from_secs(300));
    }

    #[tokio::test]
    async fn test_create_session() {
        let manager = create_test_session_manager();
        let metadata = create_test_metadata();
        
        let session_id = manager.create_session(
            "ethereum".to_string(),
            "send_transaction".to_string(),
            vec![1, 2, 3, 4],
            metadata.clone(),
        ).await.unwrap();
        
        // Verify session was created
        assert!(!session_id.is_empty());
        
        // Verify session can be retrieved
        let session = manager.get_session(&session_id).await.unwrap();
        assert_eq!(session.id, session_id);
        assert_eq!(session.network, "ethereum");
        assert_eq!(session.message_type, "send_transaction");
        assert_eq!(session.payload_bytes, vec![1, 2, 3, 4]);
        assert_eq!(session.metadata, metadata);
        assert_eq!(session.status, SessionStatus::Pending);
        
        // Verify payload hash is calculated correctly
        let expected_hash = sha3::Keccak256::digest(&[1, 2, 3, 4]).to_vec();
        assert_eq!(session.payload_hash, expected_hash);
    }

    #[tokio::test]
    async fn test_session_status_updates() {
        let manager = create_test_session_manager();
        
        let session_id = manager.create_session(
            "bitcoin".to_string(),
            "send_transaction".to_string(),
            vec![5, 6, 7, 8],
            HashMap::new(),
        ).await.unwrap();
        
        // Test status progression
        assert_eq!(manager.get_session(&session_id).await.unwrap().status, SessionStatus::Pending);
        
        manager.update_session_status(&session_id, SessionStatus::WaitingForMobile).await.unwrap();
        assert_eq!(manager.get_session(&session_id).await.unwrap().status, SessionStatus::WaitingForMobile);
        
        manager.update_session_status(&session_id, SessionStatus::Completed).await.unwrap();
        assert_eq!(manager.get_session(&session_id).await.unwrap().status, SessionStatus::Completed);
        
        manager.update_session_status(&session_id, SessionStatus::Failed("Test error".to_string())).await.unwrap();
        if let SessionStatus::Failed(error) = &manager.get_session(&session_id).await.unwrap().status {
            assert_eq!(error, "Test error");
        } else {
            panic!("Expected Failed status");
        }
    }

    #[tokio::test]
    async fn test_update_nonexistent_session_status() {
        let manager = create_test_session_manager();
        
        let result = manager.update_session_status("nonexistent", SessionStatus::Completed).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Session not found"));
    }

    #[tokio::test]
    async fn test_signing_results() {
        let manager = create_test_session_manager();
        
        let session_id = "test-session".to_string();
        let mut metadata = HashMap::new();
        metadata.insert("tx_hash".to_string(), "0x123".to_string());
        
        let result = SigningResult {
            session_id: session_id.clone(),
            success: true,
            signature: vec![1, 2, 3, 4, 5],
            signed_tx: vec![6, 7, 8, 9],
            error_message: String::new(),
            metadata,
        };
        
        // Test storing and retrieving result
        manager.store_result(session_id.clone(), result.clone()).await.unwrap();
        
        let retrieved_result = manager.get_result(&session_id).await.unwrap();
        assert_eq!(retrieved_result.session_id, result.session_id);
        assert_eq!(retrieved_result.success, result.success);
        assert_eq!(retrieved_result.signature, result.signature);
        assert_eq!(retrieved_result.signed_tx, result.signed_tx);
        assert_eq!(retrieved_result.metadata, result.metadata);
    }

    #[tokio::test]
    async fn test_get_nonexistent_result() {
        let manager = create_test_session_manager();
        
        let result = manager.get_result("nonexistent").await;
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_wait_for_result_success() {
        let manager = Arc::new(create_test_session_manager());
        let session_id = "test-wait-session".to_string();
        
        // Spawn task to store result after delay
        let manager_clone = manager.clone();
        let session_id_clone = session_id.clone();
        tokio::spawn(async move {
            sleep(Duration::from_millis(100)).await;
            let result = SigningResult {
                session_id: session_id_clone.clone(),
                success: true,
                signature: vec![1, 2, 3],
                signed_tx: vec![4, 5, 6],
                error_message: String::new(),
                metadata: HashMap::new(),
            };
            manager_clone.store_result(session_id_clone, result).await.unwrap();
        });
        
        // Wait for result
        let result = manager.wait_for_result(&session_id, Duration::from_secs(1)).await.unwrap();
        assert_eq!(result.signature, vec![1, 2, 3]);
        assert!(result.success);
    }

    #[tokio::test]
    async fn test_wait_for_result_timeout() {
        let manager = create_test_session_manager();
        
        let start = Instant::now();
        let result = manager.wait_for_result("nonexistent", Duration::from_millis(200)).await;
        let elapsed = start.elapsed();
        
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Timeout"));
        assert!(elapsed >= Duration::from_millis(200));
        assert!(elapsed < Duration::from_millis(300)); // Should not take much longer
    }

    #[tokio::test]
    async fn test_cleanup_expired_sessions() {
        // Create manager with short cleanup interval for testing
        let manager = SessionManager {
            sessions: Arc::new(RwLock::new(HashMap::new())),
            results: Arc::new(RwLock::new(HashMap::new())),
            cleanup_interval: Duration::from_millis(100),
        };
        
        // Create sessions
        let session_id1 = manager.create_session(
            "ethereum".to_string(),
            "test".to_string(),
            vec![1, 2, 3],
            HashMap::new(),
        ).await.unwrap();
        
        let session_id2 = manager.create_session(
            "bitcoin".to_string(),
            "test".to_string(),
            vec![4, 5, 6],
            HashMap::new(),
        ).await.unwrap();
        
        // Store results
        let result1 = SigningResult {
            session_id: session_id1.clone(),
            success: true,
            signature: vec![],
            signed_tx: vec![],
            error_message: String::new(),
            metadata: HashMap::new(),
        };
        manager.store_result(session_id1.clone(), result1).await.unwrap();
        
        // Verify sessions exist
        assert_eq!(manager.sessions.read().await.len(), 2);
        assert_eq!(manager.results.read().await.len(), 1);
        
        // Wait for expiration + some buffer
        sleep(Duration::from_millis(150)).await;
        
        // Run cleanup
        manager.cleanup_expired_sessions().await;
        
        // Verify cleanup worked
        assert_eq!(manager.sessions.read().await.len(), 0);
        assert_eq!(manager.results.read().await.len(), 0);
    }

    #[tokio::test]
    async fn test_session_to_signing_request() {
        let manager = create_test_session_manager();
        let metadata = create_test_metadata();
        
        let session = Session {
            id: "test-session".to_string(),
            network: "ethereum".to_string(),
            message_type: "send_transaction".to_string(),
            payload_hash: vec![1, 2, 3, 4],
            payload_bytes: vec![5, 6, 7, 8],
            metadata: metadata.clone(),
            created_at: Instant::now(),
            status: SessionStatus::Pending,
        };
        
        let signing_request = manager.session_to_signing_request(&session);
        
        assert_eq!(signing_request.session_id, "test-session");
        assert_eq!(signing_request.network, "ethereum");
        assert_eq!(signing_request.message_type, "send_transaction");
        assert_eq!(signing_request.payload_hash, vec![1, 2, 3, 4]);
        assert_eq!(signing_request.payload_bytes, vec![5, 6, 7, 8]);
        assert_eq!(signing_request.metadata, metadata);
    }

    #[tokio::test]
    async fn test_create_session_info() {
        let manager = create_test_session_manager();
        
        let session_info = manager.create_session_info(
            "test-session".to_string(),
            "192.168.1.100".to_string(),
            8787,
            "ethereum".to_string(),
        );
        
        assert_eq!(session_info.session_id, "test-session");
        assert_eq!(session_info.connection_type, "local");
        assert_eq!(session_info.host, "192.168.1.100");
        assert_eq!(session_info.port, 8787);
        assert_eq!(session_info.network, "ethereum");
        assert!(session_info.timestamp > 0);
    }

    #[tokio::test]
    async fn test_session_status_equality() {
        assert_eq!(SessionStatus::Pending, SessionStatus::Pending);
        assert_eq!(SessionStatus::WaitingForMobile, SessionStatus::WaitingForMobile);
        assert_eq!(SessionStatus::Completed, SessionStatus::Completed);
        assert_eq!(SessionStatus::Failed("error1".to_string()), SessionStatus::Failed("error1".to_string()));
        
        assert_ne!(SessionStatus::Pending, SessionStatus::Completed);
        assert_ne!(SessionStatus::Failed("error1".to_string()), SessionStatus::Failed("error2".to_string()));
    }

    #[tokio::test]
    async fn test_concurrent_session_operations() {
        let manager = Arc::new(create_test_session_manager());
        
        // Spawn multiple tasks creating sessions concurrently
        let mut handles = Vec::new();
        
        for i in 0..10 {
            let manager_clone = manager.clone();
            let handle = tokio::spawn(async move {
                let session_id = manager_clone.create_session(
                    format!("network_{}", i),
                    "test".to_string(),
                    vec![i as u8],
                    HashMap::new(),
                ).await.unwrap();
                
                // Update status
                manager_clone.update_session_status(&session_id, SessionStatus::Completed).await.unwrap();
                
                // Store result
                let result = SigningResult {
                    session_id: session_id.clone(),
                    success: true,
                    signature: vec![i as u8],
                    signed_tx: vec![],
                    error_message: String::new(),
                    metadata: HashMap::new(),
                };
                manager_clone.store_result(session_id.clone(), result).await.unwrap();
                
                session_id
            });
            handles.push(handle);
        }
        
        // Wait for all tasks to complete
        let session_ids: Vec<String> = futures_util::future::join_all(handles).await
            .into_iter()
            .map(|result| result.unwrap())
            .collect();
        
        // Verify all sessions were created
        assert_eq!(manager.sessions.read().await.len(), 10);
        assert_eq!(manager.results.read().await.len(), 10);
        
        // Verify each session can be retrieved
        for session_id in session_ids {
            let session = manager.get_session(&session_id).await.unwrap();
            assert_eq!(session.status, SessionStatus::Completed);
            
            let result = manager.get_result(&session_id).await.unwrap();
            assert!(result.success);
        }
    }

    #[test]
    fn test_session_debug_display() {
        let session = Session {
            id: "test".to_string(),
            network: "eth".to_string(),
            message_type: "tx".to_string(),
            payload_hash: vec![1, 2],
            payload_bytes: vec![3, 4],
            metadata: HashMap::new(),
            created_at: Instant::now(),
            status: SessionStatus::Pending,
        };
        
        let debug_str = format!("{:?}", session);
        assert!(debug_str.contains("test"));
        assert!(debug_str.contains("eth"));
        assert!(debug_str.contains("tx"));
        assert!(debug_str.contains("Pending"));
    }

    #[test]
    fn test_session_status_debug_display() {
        let statuses = vec![
            SessionStatus::Pending,
            SessionStatus::WaitingForMobile,
            SessionStatus::Completed,
            SessionStatus::Failed("test error".to_string()),
        ];
        
        for status in statuses {
            let debug_str = format!("{:?}", status);
            assert!(!debug_str.is_empty());
        }
    }
}
