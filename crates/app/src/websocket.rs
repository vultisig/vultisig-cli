use anyhow::{anyhow, Result};
use futures_util::{SinkExt, StreamExt};
use prost::Message;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio_tungstenite::{accept_async, tungstenite::Message as WsMessage};
use tracing::{error, info, warn};

use crate::session::{SessionManager, SigningResult, SessionStatus};
use crate::tss::TssMessage;
use crate::mpc_coordinator::MpcCoordinator;

/// Start WebSocket server function for external use
pub async fn start_websocket_server(
    port: u16,
    session_manager: Arc<SessionManager>,
    mpc_coordinator: Arc<MpcCoordinator>,
) -> Result<()> {
    let server = WebSocketServer::new(session_manager, mpc_coordinator, port);
    server.start().await
}

#[cfg(test)]
use futures_util;

/// WebSocket server for handling mobile app connections
#[derive(Debug)]
pub struct WebSocketServer {
    session_manager: Arc<SessionManager>,
    mpc_coordinator: Arc<MpcCoordinator>,
    port: u16,
}

impl WebSocketServer {
    pub fn new(session_manager: Arc<SessionManager>, mpc_coordinator: Arc<MpcCoordinator>, port: u16) -> Self {
        Self {
            session_manager,
            mpc_coordinator,
            port,
        }
    }

    /// Start the WebSocket server
    pub async fn start(&self) -> Result<()> {
        let addr = SocketAddr::from(([0, 0, 0, 0], self.port));
        let listener = TcpListener::bind(&addr).await
            .map_err(|e| anyhow!("Failed to bind WebSocket server to {}: {}", addr, e))?;

        info!("WebSocket server listening on {}", addr);

        while let Ok((stream, peer_addr)) = listener.accept().await {
            info!("New connection from {}", peer_addr);
            
            let session_manager = self.session_manager.clone();
            let mpc_coordinator = self.mpc_coordinator.clone();
            tokio::spawn(async move {
                if let Err(e) = handle_websocket_connection(stream, session_manager, mpc_coordinator).await {
                    error!("WebSocket connection error: {}", e);
                }
            });
        }

        Ok(())
    }
}

/// Handle individual WebSocket connection
async fn handle_websocket_connection(
    stream: TcpStream,
    session_manager: Arc<SessionManager>,
    mpc_coordinator: Arc<MpcCoordinator>,
) -> Result<()> {
    let ws_stream = accept_async(stream).await
        .map_err(|e| anyhow!("WebSocket handshake failed: {}", e))?;

    let (mut ws_sender, mut ws_receiver) = ws_stream.split();
    
    // Channel for sending messages to the WebSocket
    let (tx, mut rx) = mpsc::unbounded_channel::<WsMessage>();

    // Spawn task to handle outgoing messages
    let send_task = tokio::spawn(async move {
        while let Some(message) = rx.recv().await {
            if let Err(e) = ws_sender.send(message).await {
                error!("Failed to send WebSocket message: {}", e);
                break;
            }
        }
    });

    // Handle incoming messages
    let mut current_session_id: Option<String> = None;
    
    while let Some(message) = ws_receiver.next().await {
        match message {
            Ok(WsMessage::Binary(data)) => {
                if let Err(e) = handle_binary_message(
                    &data,
                    &session_manager,
                    &mpc_coordinator,
                    &tx,
                    &mut current_session_id,
                ).await {
                    error!("Failed to handle binary message: {}", e);
                    break;
                }
            }
            Ok(WsMessage::Text(text)) => {
                info!("Received text message: {}", text);
                // Handle text-based protocol if needed
            }
            Ok(WsMessage::Close(_)) => {
                info!("WebSocket connection closed by client");
                break;
            }
            Ok(WsMessage::Ping(data)) => {
                if let Err(e) = tx.send(WsMessage::Pong(data)) {
                    error!("Failed to send pong: {}", e);
                    break;
                }
            }
            Ok(_) => {
                // Ignore other message types
            }
            Err(e) => {
                error!("WebSocket error: {}", e);
                break;
            }
        }
    }

    // Clean up
    send_task.abort();
    if let Some(session_id) = current_session_id {
        let _ = session_manager.update_session_status(
            &session_id,
            SessionStatus::Failed("Connection closed".to_string()),
        ).await;
    }

    Ok(())
}

/// Handle binary protobuf messages
async fn handle_binary_message(
    data: &[u8],
    session_manager: &Arc<SessionManager>,
    mpc_coordinator: &Arc<MpcCoordinator>,
    _tx: &mpsc::UnboundedSender<WsMessage>,
    current_session_id: &mut Option<String>,
) -> Result<()> {
    // Try to decode as TssMessage first
    if let Ok(tss_message) = serde_json::from_slice::<TssMessage>(data) {
        info!("📥 WEBSOCKET: Received TSS message: {:?}", std::mem::discriminant(&tss_message));
        info!("📊 WEBSOCKET: Message size: {} bytes", data.len());
        
        // Extract session ID from the message
        let session_id = match &tss_message {
            TssMessage::SetupRequest { session_id, .. } => session_id.clone(),
            TssMessage::SetupResponse { session_id, .. } => session_id.clone(),
            TssMessage::EcdsaRound1 { .. } | TssMessage::EcdsaRound2 { .. } | TssMessage::EcdsaRound3 { .. } |
            TssMessage::EddsaRound1 { .. } | TssMessage::EddsaRound2 { .. } => {
                // For round messages, use the current session ID
                current_session_id.clone().unwrap_or_default()
            }
            TssMessage::SigningComplete { .. } | TssMessage::SigningError { .. } => {
                // For completion messages, use the current session ID
                current_session_id.clone().unwrap_or_default()
            }
        };
        
        if !session_id.is_empty() {
            *current_session_id = Some(session_id.clone());
            info!("🔄 WEBSOCKET: Forwarding TSS message to MPC coordinator (session={})", session_id);
            
            // Forward to MPC coordinator
            mpc_coordinator.handle_mobile_message(&session_id, tss_message).await?;
            info!("✅ WEBSOCKET: TSS message forwarded successfully");
        } else {
            warn!("⚠️ WEBSOCKET: Received TSS message without valid session ID");
        }
        
        return Ok(());
    }

    // Try to decode as SigningResult (legacy support)
    if let Ok(signing_result) = SigningResult::decode(data) {
        info!("Received signing result for session: {}", signing_result.session_id);
        
        // Store the result
        session_manager.store_result(
            signing_result.session_id.clone(),
            signing_result.clone(),
        ).await?;

        // Update session status
        let status = if signing_result.success {
            SessionStatus::Completed
        } else {
            SessionStatus::Failed(signing_result.error_message.clone())
        };
        
        session_manager.update_session_status(&signing_result.session_id, status).await?;
        
        return Ok(());
    }

    // If not a known message type, log and continue
    warn!("Received unknown binary message of {} bytes", data.len());
    Ok(())
}

/// Send SigningRequest to mobile app
pub async fn send_signing_request_to_mobile(
    session_id: &str,
    session_manager: &Arc<SessionManager>,
    tx: &mpsc::UnboundedSender<WsMessage>,
) -> Result<()> {
    if let Some(session) = session_manager.get_session(session_id).await {
        let signing_request = session_manager.session_to_signing_request(&session);
        
        let mut buffer = Vec::new();
        signing_request.encode(&mut buffer)
            .map_err(|e| anyhow!("Failed to encode SigningRequest: {}", e))?;
        
        tx.send(WsMessage::Binary(buffer))
            .map_err(|e| anyhow!("Failed to send SigningRequest: {}", e))?;
        
        // Update session status
        session_manager.update_session_status(session_id, SessionStatus::WaitingForMobile).await?;
        
        info!("Sent signing request to mobile for session: {}", session_id);
    } else {
        return Err(anyhow!("Session not found: {}", session_id));
    }
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::{SessionManager, SessionStatus};
    use crate::mpc_coordinator::{MpcCoordinator, create_mpc_coordinator};
    use crate::tss::{TssMessage};
    use tokio::sync::mpsc;
    use tokio::time::{timeout, Duration};
    use tokio_test;
    use pretty_assertions::assert_eq;
    use std::collections::HashMap;
    use std::sync::Arc;
    use tokio_tungstenite::tungstenite::Message as WsMessage;
    use prost::Message;

    fn create_test_session_manager() -> Arc<SessionManager> {
        Arc::new(SessionManager::new())
    }

    fn create_test_mpc_coordinator() -> Arc<MpcCoordinator> {
        let session_manager = create_test_session_manager();
        create_mpc_coordinator(session_manager)
    }

    #[test]
    fn test_websocket_server_creation() {
        let session_manager = create_test_session_manager();
        let mpc_coordinator = create_test_mpc_coordinator();
        let server = WebSocketServer::new(session_manager.clone(), mpc_coordinator.clone(), 8787);
        
        assert_eq!(server.port, 8787);
        assert!(Arc::ptr_eq(&server.session_manager, &session_manager));
        assert!(Arc::ptr_eq(&server.mpc_coordinator, &mpc_coordinator));
    }

    #[tokio::test]
    async fn test_send_signing_request_to_mobile_success() {
        let session_manager = create_test_session_manager();
        let (tx, mut rx) = mpsc::unbounded_channel();
        
        // Create a test session
        let session_id = session_manager.create_session(
            "ethereum".to_string(),
            "send_transaction".to_string(),
            vec![1, 2, 3, 4],
            HashMap::new(),
        ).await.unwrap();
        
        // Send signing request
        let result = send_signing_request_to_mobile(
            &session_id,
            &session_manager,
            &tx,
        ).await;
        
        assert!(result.is_ok());
        
        // Verify message was sent
        let message = rx.recv().await.unwrap();
        match message {
            WsMessage::Binary(data) => {
                assert!(!data.is_empty());
                // The data should be a valid protobuf-encoded SigningRequest
            }
            _ => panic!("Expected binary message"),
        }
        
        // Verify session status was updated
        let session = session_manager.get_session(&session_id).await.unwrap();
        assert_eq!(session.status, SessionStatus::WaitingForMobile);
    }

    #[tokio::test]
    async fn test_send_signing_request_to_mobile_nonexistent_session() {
        let session_manager = create_test_session_manager();
        let (tx, _rx) = mpsc::unbounded_channel();
        
        let result = send_signing_request_to_mobile(
            "nonexistent",
            &session_manager,
            &tx,
        ).await;
        
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Session not found"));
    }

    #[tokio::test]
    async fn test_handle_binary_message_tss_setup_request() {
        let session_manager = create_test_session_manager();
        let mpc_coordinator = create_test_mpc_coordinator();
        let (tx, _rx) = mpsc::unbounded_channel();
        let mut current_session_id = None;
        
        // Create test TSS message
        let tss_message = TssMessage::SetupRequest {
            session_id: "test-session".to_string(),
            keyshare_info: crate::tss::TssKeyshareInfo {
                public_key: vec![0x02; 33],
                chain_code: vec![0x01; 32],
                party_id: "daemon".to_string(),
            },
        };
        
        let message_data = serde_json::to_vec(&tss_message).unwrap();
        
        let result = handle_binary_message(
            &message_data,
            &session_manager,
            &mpc_coordinator,
            &tx,
            &mut current_session_id,
        ).await;
        
        assert!(result.is_ok());
        assert_eq!(current_session_id, Some("test-session".to_string()));
    }

    #[tokio::test]
    async fn test_handle_binary_message_tss_setup_response() {
        let session_manager = create_test_session_manager();
        let mpc_coordinator = create_test_mpc_coordinator();
        let (tx, _rx) = mpsc::unbounded_channel();
        let mut current_session_id = None;
        
        // Create test TSS message
        let tss_message = TssMessage::SetupResponse {
            session_id: "test-session".to_string(),
            public_keys: vec![vec![0x02; 33], vec![0x03; 33]],
            party_ids: vec!["daemon".to_string(), "mobile".to_string()],
        };
        
        let message_data = serde_json::to_vec(&tss_message).unwrap();
        
        let result = handle_binary_message(
            &message_data,
            &session_manager,
            &mpc_coordinator,
            &tx,
            &mut current_session_id,
        ).await;
        
        assert!(result.is_ok());
        assert_eq!(current_session_id, Some("test-session".to_string()));
    }

    #[tokio::test]
    async fn test_handle_binary_message_ecdsa_rounds() {
        let session_manager = create_test_session_manager();
        let mpc_coordinator = create_test_mpc_coordinator();
        let (tx, _rx) = mpsc::unbounded_channel();
        let mut current_session_id = Some("existing-session".to_string());
        
        // Test ECDSA Round 1 message
        let round1_message = TssMessage::EcdsaRound1 {
            sender: "mobile".to_string(),
            share_data: vec![0x01; 64],
        };
        
        let message_data = serde_json::to_vec(&round1_message).unwrap();
        
        let result = handle_binary_message(
            &message_data,
            &session_manager,
            &mpc_coordinator,
            &tx,
            &mut current_session_id,
        ).await;
        
        assert!(result.is_ok());
        assert_eq!(current_session_id, Some("existing-session".to_string()));
        
        // Test ECDSA Round 2 message
        let round2_message = TssMessage::EcdsaRound2 {
            sender: "mobile".to_string(),
            signature_share: vec![0x02; 32],
        };
        
        let message_data2 = serde_json::to_vec(&round2_message).unwrap();
        
        let result2 = handle_binary_message(
            &message_data2,
            &session_manager,
            &mpc_coordinator,
            &tx,
            &mut current_session_id,
        ).await;
        
        assert!(result2.is_ok());
    }

    #[tokio::test]
    async fn test_handle_binary_message_eddsa_rounds() {
        let session_manager = create_test_session_manager();
        let mpc_coordinator = create_test_mpc_coordinator();
        let (tx, _rx) = mpsc::unbounded_channel();
        let mut current_session_id = Some("eddsa-session".to_string());
        
        // Test EdDSA Round 1 message
        let round1_message = TssMessage::EddsaRound1 {
            sender: "mobile".to_string(),
            commitment: vec![0x01; 32],
        };
        
        let message_data = serde_json::to_vec(&round1_message).unwrap();
        
        let result = handle_binary_message(
            &message_data,
            &session_manager,
            &mpc_coordinator,
            &tx,
            &mut current_session_id,
        ).await;
        
        assert!(result.is_ok());
        
        // Test EdDSA Round 2 message
        let round2_message = TssMessage::EddsaRound2 {
            sender: "mobile".to_string(),
            signature_share: vec![0x02; 64],
        };
        
        let message_data2 = serde_json::to_vec(&round2_message).unwrap();
        
        let result2 = handle_binary_message(
            &message_data2,
            &session_manager,
            &mpc_coordinator,
            &tx,
            &mut current_session_id,
        ).await;
        
        assert!(result2.is_ok());
    }

    #[tokio::test]
    async fn test_handle_binary_message_signing_complete() {
        let session_manager = create_test_session_manager();
        let mpc_coordinator = create_test_mpc_coordinator();
        let (tx, _rx) = mpsc::unbounded_channel();
        let mut current_session_id = Some("complete-session".to_string());
        
        // Create signing complete message
        let complete_message = TssMessage::SigningComplete {
            signature: vec![0x01, 0x02, 0x03, 0x04, 0x05],
            recovery_id: Some(0),
        };
        
        let message_data = serde_json::to_vec(&complete_message).unwrap();
        
        let result = handle_binary_message(
            &message_data,
            &session_manager,
            &mpc_coordinator,
            &tx,
            &mut current_session_id,
        ).await;
        
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_handle_binary_message_signing_error() {
        let session_manager = create_test_session_manager();
        let mpc_coordinator = create_test_mpc_coordinator();
        let (tx, _rx) = mpsc::unbounded_channel();
        let mut current_session_id = Some("error-session".to_string());
        
        // Create signing error message
        let error_message = TssMessage::SigningError {
            error: "Invalid signature share".to_string(),
        };
        
        let message_data = serde_json::to_vec(&error_message).unwrap();
        
        let result = handle_binary_message(
            &message_data,
            &session_manager,
            &mpc_coordinator,
            &tx,
            &mut current_session_id,
        ).await;
        
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_handle_binary_message_legacy_signing_result() {
        let session_manager = create_test_session_manager();
        let mpc_coordinator = create_test_mpc_coordinator();
        let (tx, _rx) = mpsc::unbounded_channel();
        let mut current_session_id = None;
        
        // Create a legacy SigningResult message
        let signing_result = crate::session::SigningResult {
            session_id: "legacy-session".to_string(),
            success: true,
            signature: vec![0x01, 0x02, 0x03, 0x04, 0x05],
            signed_tx: vec![0x06, 0x07, 0x08, 0x09],
            error_message: String::new(),
            metadata: HashMap::new(),
        };
        
        let mut buffer = Vec::new();
        signing_result.encode(&mut buffer).unwrap();
        
        let result = handle_binary_message(
            &buffer,
            &session_manager,
            &mpc_coordinator,
            &tx,
            &mut current_session_id,
        ).await;
        
        assert!(result.is_ok());
        
        // Verify result was stored
        let stored_result = session_manager.get_result("legacy-session").await;
        assert!(stored_result.is_some());
        let result = stored_result.unwrap();
        assert!(result.success);
        assert_eq!(result.signature, vec![0x01, 0x02, 0x03, 0x04, 0x05]);
    }

    #[tokio::test]
    async fn test_handle_binary_message_unknown_format() {
        let session_manager = create_test_session_manager();
        let mpc_coordinator = create_test_mpc_coordinator();
        let (tx, _rx) = mpsc::unbounded_channel();
        let mut current_session_id = None;
        
        // Send random binary data
        let random_data = vec![0x01, 0x02, 0x03, 0x04, 0x05];
        
        let result = handle_binary_message(
            &random_data,
            &session_manager,
            &mpc_coordinator,
            &tx,
            &mut current_session_id,
        ).await;
        
        // Should not error, just log and continue
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_handle_binary_message_empty_session_id() {
        let session_manager = create_test_session_manager();
        let mpc_coordinator = create_test_mpc_coordinator();
        let (tx, _rx) = mpsc::unbounded_channel();
        let mut current_session_id = None;
        
        // Create TSS message without session ID (using round message that depends on current_session_id)
        let round1_message = TssMessage::EcdsaRound1 {
            sender: "mobile".to_string(),
            share_data: vec![0x01; 64],
        };
        
        let message_data = serde_json::to_vec(&round1_message).unwrap();
        
        let result = handle_binary_message(
            &message_data,
            &session_manager,
            &mpc_coordinator,
            &tx,
            &mut current_session_id,
        ).await;
        
        // Should handle gracefully (warn and continue)
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_concurrent_binary_message_handling() {
        let session_manager = Arc::new(create_test_session_manager());
        let mpc_coordinator = Arc::new(create_test_mpc_coordinator());
        
        let mut handles = Vec::new();
        
        // Process multiple TSS messages concurrently
        for i in 0..5 {
            let session_manager_clone = session_manager.clone();
            let mpc_coordinator_clone = mpc_coordinator.clone();
            
            let handle = tokio::spawn(async move {
                let (tx, _rx) = mpsc::unbounded_channel();
                let mut current_session_id = None;
                
                let tss_message = TssMessage::SetupRequest {
                    session_id: format!("concurrent-session-{}", i),
                    keyshare_info: crate::tss::TssKeyshareInfo {
                        public_key: vec![0x02; 33],
                        chain_code: vec![0x01; 32],
                        party_id: "daemon".to_string(),
                    },
                };
                
                let message_data = serde_json::to_vec(&tss_message).unwrap();
                
                handle_binary_message(
                    &message_data,
                    &session_manager_clone,
                    &mpc_coordinator_clone,
                    &tx,
                    &mut current_session_id,
                ).await
            });
            
            handles.push(handle);
        }
        
        // Wait for all messages to be processed
        let results = futures_util::future::join_all(handles).await;
        
        // All should succeed
        for result in results {
            assert!(result.is_ok());
            assert!(result.unwrap().is_ok());
        }
    }

    #[tokio::test]
    async fn test_channel_closed_error_handling() {
        let session_manager = create_test_session_manager();
        
        // Create a session
        let session_id = session_manager.create_session(
            "ethereum".to_string(),
            "test".to_string(),
            vec![1, 2, 3],
            HashMap::new(),
        ).await.unwrap();
        
        // Create channel and immediately close it
        let (tx, rx) = mpsc::unbounded_channel();
        drop(rx); // Close the receiver
        
        // Attempt to send signing request
        let result = send_signing_request_to_mobile(
            &session_id,
            &session_manager,
            &tx,
        ).await;
        
        // Should fail because channel is closed
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Failed to send"));
    }

    #[test]
    fn test_websocket_server_debug_display() {
        let session_manager = create_test_session_manager();
        let mpc_coordinator = create_test_mpc_coordinator();
        let server = WebSocketServer::new(session_manager, mpc_coordinator, 8787);
        
        let debug_str = format!("{:?}", server);
        assert!(debug_str.contains("WebSocketServer"));
        // The debug output should include the port
        assert!(debug_str.contains("8787") || debug_str.contains("port"));
    }

    // Note: Full integration tests with actual WebSocket connections would require
    // more complex setup with test WebSocket clients. The above tests cover the
    // core message handling logic without requiring actual network connections.

    #[tokio::test]
    async fn test_message_size_limits() {
        let session_manager = create_test_session_manager();
        let mpc_coordinator = create_test_mpc_coordinator();
        let (tx, _rx) = mpsc::unbounded_channel();
        let mut current_session_id = None;
        
        // Test with very large message (should handle gracefully)
        let large_data = vec![0u8; 1024 * 1024]; // 1MB of data
        
        let result = handle_binary_message(
            &large_data,
            &session_manager,
            &mpc_coordinator,
            &tx,
            &mut current_session_id,
        ).await;
        
        // Should handle gracefully (either process or log warning)
        assert!(result.is_ok());
    }
}
