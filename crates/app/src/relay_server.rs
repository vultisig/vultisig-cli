use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::time::{Duration, Instant};
use tracing::{debug, error, info};
use warp::Filter;
use crate::network;

/// In-memory storage for relay server (matches Go-TS spec)
#[derive(Debug, Clone)]
pub struct RelayStorage {
    sessions: Arc<RwLock<HashMap<String, SessionData>>>,
    messages: Arc<RwLock<HashMap<String, Vec<StoredMessage>>>>,
}

/// Session data stored in memory
#[derive(Debug, Clone)]
pub struct SessionData {
    pub session_id: String,
    pub parties: Vec<String>,
    pub started: bool,
    pub completed: Vec<String>, // Parties that marked session complete
    pub created_at: Instant,
    pub ttl: Duration,
}

/// Message stored in relay server
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredMessage {
    pub session_id: String,
    pub from: String,
    pub to: Vec<String>,
    pub body: String,
    pub hash: String,
    pub sequence_no: i64,
    pub timestamp: u64,
}

/// Relay server implementation (matches Go-TS mediator spec)
pub struct RelayServer {
    storage: RelayStorage,
    port: u16,
    session_manager: Option<Arc<crate::session::SessionManager>>,
    mpc_coordinator: Option<Arc<crate::mpc_coordinator::MpcCoordinator>>,
    websocket_port: u16,
}

/// Request/Response types (matches Go-TS spec)

#[derive(Debug, Deserialize)]
pub struct RegisterSessionRequest {
    pub session_id: String,
    pub public_key: String,
    pub ttl: Option<u64>,
}

#[derive(Debug, Deserialize)]
pub struct StartSessionRequest {
    pub session_id: String,
    pub parties: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct CompleteSessionRequest {
    pub session_id: String,
    pub local_party_id: String,
}

#[derive(Debug, Serialize)]
pub struct SessionResponse {
    pub success: bool,
    pub message: Option<String>,
    pub parties: Option<Vec<String>>,
}

// Discovery structures moved to local_server.rs to avoid duplication

/// Session status response for API (matches QR polling requirements)
#[derive(Debug, Serialize, Deserialize)]
pub struct SessionStatusResponse {
    pub session_id: String,
    pub status: String,
    pub metadata: std::collections::HashMap<String, String>,
}

impl RelayStorage {
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
            messages: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Register a party in a session (creates session if not exists)
    pub async fn register_session(&self, session_id: &str, _public_key: &str, ttl_seconds: u64) -> Result<()> {
        let mut sessions = self.sessions.write().await;
        
        if !sessions.contains_key(session_id) {
            let session_data = SessionData {
                session_id: session_id.to_string(),
                parties: Vec::new(),
                started: false,
                completed: Vec::new(),
                created_at: Instant::now(),
                ttl: Duration::from_secs(ttl_seconds),
            };
            sessions.insert(session_id.to_string(), session_data);
            debug!("Created new session: {}", session_id);
        }
        
        Ok(())
    }

    /// Start a session with party list
    pub async fn start_session(&self, session_id: &str, parties: Vec<String>) -> Result<()> {
        let mut sessions = self.sessions.write().await;
        
        match sessions.get_mut(session_id) {
            Some(session) => {
                session.parties = parties.clone();
                session.started = true;
                info!("Started session {} with parties: {:?}", session_id, parties);
                Ok(())
            }
            None => Err(anyhow!("Session {} not found", session_id))
        }
    }

    /// Check if session is started and return parties
    pub async fn get_session_parties(&self, session_id: &str) -> Result<Option<Vec<String>>> {
        let sessions = self.sessions.read().await;
        
        match sessions.get(session_id) {
            Some(session) if session.started => Ok(Some(session.parties.clone())),
            Some(_) => Ok(None), // Session exists but not started
            None => Err(anyhow!("Session {} not found", session_id))
        }
    }

    /// Mark session as complete for a party
    pub async fn complete_session(&self, session_id: &str, party_id: &str) -> Result<()> {
        let mut sessions = self.sessions.write().await;
        
        match sessions.get_mut(session_id) {
            Some(session) => {
                if !session.completed.contains(&party_id.to_string()) {
                    session.completed.push(party_id.to_string());
                    debug!("Party {} completed session {}", party_id, session_id);
                }
                Ok(())
            }
            None => Err(anyhow!("Session {} not found", session_id))
        }
    }

    /// Check if session is complete (all parties marked complete)
    pub async fn is_session_complete(&self, session_id: &str) -> Result<bool> {
        let sessions = self.sessions.read().await;
        
        match sessions.get(session_id) {
            Some(session) => {
                let all_complete = session.parties.len() > 0 && 
                                 session.completed.len() == session.parties.len();
                Ok(all_complete)
            }
            None => Err(anyhow!("Session {} not found", session_id))
        }
    }

    /// Store a message for relay
    pub async fn store_message(&self, message: StoredMessage) -> Result<()> {
        let mut messages = self.messages.write().await;
        let session_messages = messages.entry(message.session_id.clone()).or_insert_with(Vec::new);
        session_messages.push(message);
        Ok(())
    }

    /// Get messages for a party in a session
    pub async fn get_messages(&self, session_id: &str, party_id: &str) -> Result<Vec<StoredMessage>> {
        let messages = self.messages.read().await;
        
        match messages.get(session_id) {
            Some(session_messages) => {
                let party_messages: Vec<StoredMessage> = session_messages
                    .iter()
                    .filter(|msg| msg.to.contains(&party_id.to_string()))
                    .cloned()
                    .collect();
                Ok(party_messages)
            }
            None => Ok(Vec::new()) // No messages for this session
        }
    }

    /// End session and cleanup
    pub async fn end_session(&self, session_id: &str) -> Result<()> {
        let mut sessions = self.sessions.write().await;
        let mut messages = self.messages.write().await;
        
        sessions.remove(session_id);
        messages.remove(session_id);
        
        info!("Ended and cleaned up session: {}", session_id);
        Ok(())
    }

    /// Cleanup expired sessions
    pub async fn cleanup_expired_sessions(&self) -> Result<()> {
        let mut sessions = self.sessions.write().await;
        let mut messages = self.messages.write().await;
        let now = Instant::now();
        
        let expired_sessions: Vec<String> = sessions
            .iter()
            .filter(|(_, session)| now.duration_since(session.created_at) > session.ttl)
            .map(|(id, _)| id.clone())
            .collect();
        
        for session_id in expired_sessions {
            sessions.remove(&session_id);
            messages.remove(&session_id);
            debug!("Cleaned up expired session: {}", session_id);
        }
        
        Ok(())
    }
}

impl RelayServer {
    /// Create new relay server (matches Go-TS mediator spec)
    pub fn new(port: u16) -> Self {
        Self {
            storage: RelayStorage::new(),
            port,
            session_manager: None,
            mpc_coordinator: None,
            websocket_port: 8787,
        }
    }

    /// Create new relay server with discovery support
    pub fn with_discovery(port: u16, session_manager: Arc<crate::session::SessionManager>, websocket_port: u16) -> Self {
        Self {
            storage: RelayStorage::new(),
            port,
            session_manager: Some(session_manager),
            mpc_coordinator: None,
            websocket_port,
        }
    }

    /// Create new relay server with discovery and MPC status support
    pub fn with_mpc_support(
        port: u16, 
        session_manager: Arc<crate::session::SessionManager>, 
        mpc_coordinator: Arc<crate::mpc_coordinator::MpcCoordinator>,
        websocket_port: u16
    ) -> Self {
        Self {
            storage: RelayStorage::new(),
            port,
            session_manager: Some(session_manager),
            mpc_coordinator: Some(mpc_coordinator),
            websocket_port,
        }
    }

    /// Start the relay server (matches Go-TS spec endpoints)
    pub async fn start(&self) -> Result<()> {
        let storage = self.storage.clone();
        let addr = ([0, 0, 0, 0], self.port);

        info!("Starting relay server on port {}", self.port);

        // Start cleanup task for expired sessions
        let cleanup_storage = storage.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60)); // Cleanup every minute
            loop {
                interval.tick().await;
                if let Err(e) = cleanup_storage.cleanup_expired_sessions().await {
                    error!("Session cleanup error: {}", e);
                }
            }
        });

        // Clone storage and session manager for each route
        let storage1 = storage.clone();
        let storage2 = storage.clone();
        let storage3 = storage.clone();
        let storage4 = storage.clone();
        let storage5 = storage.clone();
        let storage6 = storage.clone();
        let storage7 = storage.clone();
        let storage8 = storage.clone();
        let _storage9 = storage.clone();
        let storage10 = storage.clone();
        
        let session_mgr_status = self.session_manager.clone();
        let mpc_coordinator = self.mpc_coordinator.clone();

        // POST /{sessionId} - Register party in session
        let register_route = warp::path!(String)
            .and(warp::post())
            .and(warp::body::json())
            .and(warp::any().map(move || storage1.clone()))
            .and_then(handle_register_session);

        // POST /start/{sessionId} - Start session with party list
        let start_route = warp::path!("start" / String)
            .and(warp::post())
            .and(warp::body::json())
            .and(warp::any().map(move || storage2.clone()))
            .and_then(handle_start_session);

        // GET /start/{sessionId} - Wait for session to start
        let wait_start_route = warp::path!("start" / String)
            .and(warp::get())
            .and(warp::any().map(move || storage3.clone()))
            .and_then(handle_wait_session_start);

        // DELETE /{sessionId} - End session
        let end_route = warp::path!(String)
            .and(warp::delete())
            .and(warp::any().map(move || storage4.clone()))
            .and_then(handle_end_session);

        // POST /complete/{sessionId} - Mark session complete
        let complete_route = warp::path!("complete" / String)
            .and(warp::post())
            .and(warp::body::json())
            .and(warp::any().map(move || storage5.clone()))
            .and_then(handle_complete_session);

        // GET /complete/{sessionId} - Check completion status
        let check_complete_route = warp::path!("complete" / String)
            .and(warp::get())
            .and(warp::any().map(move || storage6.clone()))
            .and_then(handle_check_completion);

        // POST /message/{sessionId} - Send message
        let send_message_route = warp::path!("message" / String)
            .and(warp::post())
            .and(warp::body::json())
            .and(warp::any().map(move || storage7.clone()))
            .and_then(handle_send_message);

        // GET /message/{sessionId}/{partyId} - Get messages for party
        let get_messages_route = warp::path!("message" / String / String)
            .and(warp::get())
            .and(warp::any().map(move || storage8.clone()))
            .and_then(handle_get_messages);

        // GET /api/session/{sessionId}/status - Get session status for QR page polling
        let session_status_route = warp::path!("api" / "session" / String / "status")
            .and(warp::get())
            .and(warp::any().map(move || session_mgr_status.clone()))
            .and(warp::any().map(move || mpc_coordinator.clone()))
            .and(warp::any().map(move || storage10.clone()))
            .and_then(handle_session_status);

        // GET /health - Health check  
        let health_route = warp::path("health")
            .and(warp::get())
            .map(|| warp::reply::with_status("OK".to_string(), warp::http::StatusCode::OK));

        let routes = register_route
            .or(start_route)
            .or(wait_start_route)
            .or(end_route)
            .or(complete_route)
            .or(check_complete_route)
            .or(send_message_route)
            .or(get_messages_route)
            .or(session_status_route)
            .or(health_route)
            .with(warp::cors().allow_any_origin())
            .with(warp::log("relay_server"));

        info!("Relay server listening on http://{}:{}", "0.0.0.0", self.port);
        
        warp::serve(routes)
            .run(addr)
            .await;

        Ok(())
    }
}

// Handler functions (matches Go-TS spec)

async fn handle_register_session(
    session_id: String,
    request: RegisterSessionRequest,
    storage: RelayStorage,
) -> Result<impl warp::Reply, warp::Rejection> {
    let ttl = request.ttl.unwrap_or(300); // Default 5 minutes
    
    match storage.register_session(&session_id, &request.public_key, ttl).await {
        Ok(_) => {
            debug!("Registered session: {}", session_id);
            Ok(warp::reply::with_status(
                warp::reply::json(&SessionResponse {
                    success: true,
                    message: Some("Session registered".to_string()),
                    parties: None,
                }),
                warp::http::StatusCode::CREATED,
            ))
        }
        Err(e) => {
            error!("Failed to register session {}: {}", session_id, e);
            Ok(warp::reply::with_status(
                warp::reply::json(&SessionResponse {
                    success: false,
                    message: Some(e.to_string()),
                    parties: None,
                }),
                warp::http::StatusCode::BAD_REQUEST,
            ))
        }
    }
}

async fn handle_start_session(
    session_id: String,
    request: StartSessionRequest,
    storage: RelayStorage,
) -> Result<impl warp::Reply, warp::Rejection> {
    match storage.start_session(&session_id, request.parties).await {
        Ok(_) => {
            debug!("Started session: {}", session_id);
            Ok(warp::reply::with_status(
                warp::reply::json(&SessionResponse {
                    success: true,
                    message: Some("Session started".to_string()),
                    parties: None,
                }),
                warp::http::StatusCode::OK,
            ))
        }
        Err(e) => {
            error!("Failed to start session {}: {}", session_id, e);
            Ok(warp::reply::with_status(
                warp::reply::json(&SessionResponse {
                    success: false,
                    message: Some(e.to_string()),
                    parties: None,
                }),
                warp::http::StatusCode::BAD_REQUEST,
            ))
        }
    }
}

async fn handle_wait_session_start(
    session_id: String,
    storage: RelayStorage,
) -> Result<impl warp::Reply, warp::Rejection> {
    match storage.get_session_parties(&session_id).await {
        Ok(Some(parties)) => {
            debug!("Session {} is started with parties: {:?}", session_id, parties);
            Ok(warp::reply::with_status(
                warp::reply::json(&parties),
                warp::http::StatusCode::OK,
            ))
        }
        Ok(None) => {
            debug!("Session {} not started yet", session_id);
            Ok(warp::reply::with_status(
                warp::reply::json(&Vec::<String>::new()),
                warp::http::StatusCode::ACCEPTED,
            ))
        }
        Err(e) => {
            error!("Failed to check session {}: {}", session_id, e);
            Ok(warp::reply::with_status(
                warp::reply::json(&SessionResponse {
                    success: false,
                    message: Some(e.to_string()),
                    parties: None,
                }),
                warp::http::StatusCode::NOT_FOUND,
            ))
        }
    }
}

async fn handle_end_session(
    session_id: String,
    storage: RelayStorage,
) -> Result<impl warp::Reply, warp::Rejection> {
    match storage.end_session(&session_id).await {
        Ok(_) => {
            debug!("Ended session: {}", session_id);
            Ok(warp::reply::with_status(
                warp::reply::json(&SessionResponse {
                    success: true,
                    message: Some("Session ended".to_string()),
                    parties: None,
                }),
                warp::http::StatusCode::OK,
            ))
        }
        Err(e) => {
            error!("Failed to end session {}: {}", session_id, e);
            Ok(warp::reply::with_status(
                warp::reply::json(&SessionResponse {
                    success: false,
                    message: Some(e.to_string()),
                    parties: None,
                }),
                warp::http::StatusCode::BAD_REQUEST,
            ))
        }
    }
}

async fn handle_complete_session(
    session_id: String,
    request: CompleteSessionRequest,
    storage: RelayStorage,
) -> Result<impl warp::Reply, warp::Rejection> {
    match storage.complete_session(&session_id, &request.local_party_id).await {
        Ok(_) => {
            debug!("Party {} completed session {}", request.local_party_id, session_id);
            Ok(warp::reply::with_status(
                warp::reply::json(&SessionResponse {
                    success: true,
                    message: Some("Session marked complete".to_string()),
                    parties: None,
                }),
                warp::http::StatusCode::OK,
            ))
        }
        Err(e) => {
            error!("Failed to complete session {} for party {}: {}", session_id, request.local_party_id, e);
            Ok(warp::reply::with_status(
                warp::reply::json(&SessionResponse {
                    success: false,
                    message: Some(e.to_string()),
                    parties: None,
                }),
                warp::http::StatusCode::BAD_REQUEST,
            ))
        }
    }
}

async fn handle_check_completion(
    session_id: String,
    storage: RelayStorage,
) -> Result<impl warp::Reply, warp::Rejection> {
    match storage.is_session_complete(&session_id).await {
        Ok(complete) => {
            if complete {
                debug!("Session {} is complete", session_id);
                Ok(warp::reply::with_status(
                    warp::reply::json(&SessionResponse {
                        success: true,
                        message: Some("Session complete".to_string()),
                        parties: None,
                    }),
                    warp::http::StatusCode::OK,
                ))
            } else {
                debug!("Session {} not complete yet", session_id);
                Ok(warp::reply::with_status(
                    warp::reply::json(&SessionResponse {
                        success: false,
                        message: Some("Session not complete".to_string()),
                        parties: None,
                    }),
                    warp::http::StatusCode::NOT_FOUND,
                ))
            }
        }
        Err(e) => {
            error!("Failed to check completion for session {}: {}", session_id, e);
            Ok(warp::reply::with_status(
                warp::reply::json(&SessionResponse {
                    success: false,
                    message: Some(e.to_string()),
                    parties: None,
                }),
                warp::http::StatusCode::BAD_REQUEST,
            ))
        }
    }
}

async fn handle_send_message(
    session_id: String,
    message: StoredMessage,
    storage: RelayStorage,
) -> Result<impl warp::Reply, warp::Rejection> {
    // Add timestamp to message
    let mut message = message;
    message.timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    match storage.store_message(message).await {
        Ok(_) => {
            debug!("Stored message for session: {}", session_id);
            Ok(warp::reply::with_status(
                warp::reply::json(&SessionResponse {
                    success: true,
                    message: Some("Message stored".to_string()),
                    parties: None,
                }),
                warp::http::StatusCode::ACCEPTED,
            ))
        }
        Err(e) => {
            error!("Failed to store message for session {}: {}", session_id, e);
            Ok(warp::reply::with_status(
                warp::reply::json(&SessionResponse {
                    success: false,
                    message: Some(e.to_string()),
                    parties: None,
                }),
                warp::http::StatusCode::BAD_REQUEST,
            ))
        }
    }
}

async fn handle_get_messages(
    session_id: String,
    party_id: String,
    storage: RelayStorage,
) -> Result<impl warp::Reply, warp::Rejection> {
    match storage.get_messages(&session_id, &party_id).await {
        Ok(messages) => {
            debug!("Retrieved {} messages for party {} in session {}", messages.len(), party_id, session_id);
            Ok(warp::reply::with_status(
                warp::reply::json(&messages),
                warp::http::StatusCode::OK,
            ))
        }
        Err(e) => {
            error!("Failed to get messages for party {} in session {}: {}", party_id, session_id, e);
            Ok(warp::reply::with_status(
                warp::reply::json(&Vec::<StoredMessage>::new()),
                warp::http::StatusCode::OK, // Return empty array instead of error
            ))
        }
    }
}

/// Factory function to create relay server
pub fn create_relay_server(port: u16) -> RelayServer {
    RelayServer::new(port)
}

/// Factory function to create relay server with discovery support
pub fn create_relay_server_with_discovery(
    port: u16, 
    session_manager: Arc<crate::session::SessionManager>, 
    websocket_port: u16
) -> RelayServer {
    RelayServer::with_discovery(port, session_manager, websocket_port)
}

/// Factory function to create relay server with full MPC status support
pub fn create_relay_server_with_mpc_support(
    port: u16, 
    session_manager: Arc<crate::session::SessionManager>, 
    mpc_coordinator: Arc<crate::mpc_coordinator::MpcCoordinator>,
    websocket_port: u16
) -> RelayServer {
    RelayServer::with_mpc_support(port, session_manager, mpc_coordinator, websocket_port)
}

// Discovery functionality handled by local_server.rs

/// Handle session status request for QR polling
async fn handle_session_status(
    session_id: String,
    session_manager: Option<Arc<crate::session::SessionManager>>,
    mpc_coordinator: Option<Arc<crate::mpc_coordinator::MpcCoordinator>>,
    _storage: RelayStorage,
) -> Result<impl warp::Reply, warp::Rejection> {
    debug!("Session status request for: {}", session_id);

    if let Some(session_mgr) = session_manager {
        match session_mgr.get_session(&session_id).await {
            Some(session) => {
                // Get MPC coordinator state if available
                let mpc_state = if let Some(coordinator) = &mpc_coordinator {
                    coordinator.get_session_state(&session_id).await
                } else {
                    None
                };

                // Convert status to API format - MPC states take precedence
                let status_string = match (&session.status, &mpc_state) {
                    // MPC states take precedence when available
                    (_, Some(crate::mpc_coordinator::MpcSigningState::WaitingForMobile)) => "waiting_for_mobile".to_string(),
                    (_, Some(crate::mpc_coordinator::MpcSigningState::Round1InProgress)) => "round1_in_progress".to_string(),
                    (_, Some(crate::mpc_coordinator::MpcSigningState::Round2InProgress)) => "round2_in_progress".to_string(),
                    (_, Some(crate::mpc_coordinator::MpcSigningState::Round3InProgress)) => "round3_in_progress".to_string(),
                    (_, Some(crate::mpc_coordinator::MpcSigningState::Completed)) => "completed".to_string(),
                    (_, Some(crate::mpc_coordinator::MpcSigningState::Failed(error))) => {
                        let mut metadata = session.metadata.clone();
                        metadata.insert("error".to_string(), error.clone());
                        
                        let response = SessionStatusResponse {
                            session_id: session.id,
                            status: "failed".to_string(),
                            metadata,
                        };
                        return Ok(warp::reply::json(&response));
                    }
                    // Fallback to session manager status when no MPC state
                    (crate::session::SessionStatus::Pending, None) => "pending".to_string(),
                    (crate::session::SessionStatus::WaitingForMobile, None) => "waiting_for_mobile".to_string(),
                    (crate::session::SessionStatus::Completed, None) => "completed".to_string(),
                    (crate::session::SessionStatus::Failed(error), None) => {
                        let mut metadata = session.metadata.clone();
                        metadata.insert("error".to_string(), error.clone());
                        
                        let response = SessionStatusResponse {
                            session_id: session.id,
                            status: "failed".to_string(),
                            metadata,
                        };
                        return Ok(warp::reply::json(&response));
                    }
                };

                // Check for signing result to add transaction hash
                let mut metadata = session.metadata.clone();
                if let Some(result) = session_mgr.get_result(&session_id).await {
                    if result.success {
                        // Add transaction hash if available
                        if let Some(tx_hash) = result.metadata.get("tx_hash") {
                            metadata.insert("tx_hash".to_string(), tx_hash.clone());
                        }
                        // Add signature info
                        if !result.signature.is_empty() {
                            metadata.insert("signature_length".to_string(), result.signature.len().to_string());
                            metadata.insert("has_signature".to_string(), "true".to_string());
                        }
                    } else if !result.error_message.is_empty() {
                        // Add error from result if not already present
                        metadata.insert("error".to_string(), result.error_message);
                    }
                }

                let response = SessionStatusResponse {
                    session_id: session.id,
                    status: status_string,
                    metadata,
                };

                Ok(warp::reply::json(&response))
            }
            None => {
                let error_response = serde_json::json!({
                    "error": "Session not found",
                    "session_id": session_id
                });
                Ok(warp::reply::json(&error_response))
            }
        }
    } else {
        // No session manager - status not available
        let error_response = serde_json::json!({
            "error": "Session management not supported",
            "session_id": session_id
        });
        Ok(warp::reply::json(&error_response))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::Duration;

    #[tokio::test]
    async fn test_relay_storage_session_lifecycle() {
        let storage = RelayStorage::new();
        let session_id = "test-session-123";
        let public_key = "test-pubkey";
        let parties = vec!["party-1".to_string(), "party-2".to_string()];

        // Register session
        storage.register_session(session_id, public_key, 300).await.unwrap();

        // Session should not be started yet
        let result = storage.get_session_parties(session_id).await.unwrap();
        assert_eq!(result, None);

        // Start session
        storage.start_session(session_id, parties.clone()).await.unwrap();

        // Session should now be started
        let result = storage.get_session_parties(session_id).await.unwrap();
        assert_eq!(result, Some(parties));

        // Mark complete for each party
        storage.complete_session(session_id, "party-1").await.unwrap();
        assert!(!storage.is_session_complete(session_id).await.unwrap());

        storage.complete_session(session_id, "party-2").await.unwrap();
        assert!(storage.is_session_complete(session_id).await.unwrap());

        // End session
        storage.end_session(session_id).await.unwrap();
        
        // Session should be gone
        assert!(storage.get_session_parties(session_id).await.is_err());
    }

    #[tokio::test]
    async fn test_relay_storage_message_handling() {
        let storage = RelayStorage::new();
        let session_id = "test-session-456";

        let message = StoredMessage {
            session_id: session_id.to_string(),
            from: "party-1".to_string(),
            to: vec!["party-2".to_string()],
            body: "test message".to_string(),
            hash: "testhash".to_string(),
            sequence_no: 1,
            timestamp: 0, // Will be set by handler
        };

        // Store message
        storage.store_message(message.clone()).await.unwrap();

        // Get messages for party-2
        let messages = storage.get_messages(session_id, "party-2").await.unwrap();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].body, "test message");

        // Get messages for party-1 (should be empty)
        let messages = storage.get_messages(session_id, "party-1").await.unwrap();
        assert_eq!(messages.len(), 0);
    }

    #[test]
    fn test_relay_server_creation() {
        let server = RelayServer::new(18080);
        assert_eq!(server.port, 18080);
    }
}
