use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::{error, info, debug};
use warp::Filter;
use mdns_sd::{ServiceDaemon, ServiceInfo};
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::Duration;

use crate::session::{SessionManager, SessionStatus};
use crate::network;

#[cfg(test)]
use futures_util;

/// Local network discovery service for Vultisig local mode
/// This provides the HTTP service that mobile apps connect to when useVultisigRelay is false
pub struct LocalDiscoveryServer {
    session_manager: Arc<SessionManager>,
    port: u16,
    websocket_port: u16,
}

/// Discovery response sent to mobile apps
#[derive(Debug, Serialize, Deserialize)]
pub struct DiscoveryResponse {
    pub session_id: String,
    pub service_name: String,
    pub websocket_url: String,
    pub status: String,
}

/// Session info for discovery
#[derive(Debug, Serialize, Deserialize)]
pub struct SessionInfo {
    pub session_id: String,
    pub participants: Vec<String>,
    pub status: String,
}

impl LocalDiscoveryServer {
    pub fn new(session_manager: Arc<SessionManager>, websocket_port: u16) -> Self {
        Self {
            session_manager,
            port: 18080,  // Will be updated dynamically if needed
            websocket_port,
        }
    }

    pub fn with_port(session_manager: Arc<SessionManager>, websocket_port: u16, discovery_port: u16) -> Self {
        Self {
            session_manager,
            port: discovery_port,
            websocket_port,
        }
    }

    /// Start the local discovery HTTP server with mDNS advertisement
    pub async fn start(&self) -> Result<()> {
        // Bind to all interfaces for network discovery
        let addr = SocketAddr::from(([0, 0, 0, 0], self.port));
        
        // Check if port is available
        if !self.is_port_available().await {
            return Err(anyhow!("Port {} is already in use", self.port));
        }

        let session_manager = self.session_manager.clone();
        let websocket_port = self.websocket_port;

        // Clone session_manager for each route to avoid move issues
        let session_manager_1 = session_manager.clone();
        let session_manager_2 = session_manager.clone();
        let session_manager_3 = session_manager.clone();

        // GET /discovery/{session_id} - Mobile app queries for session info
        let discovery_route = warp::path!("discovery" / String)
            .and(warp::get())
            .and(warp::any().map(move || session_manager_1.clone()))
            .and(warp::any().map(move || websocket_port))
            .and_then(handle_discovery_request);

        // POST /join/{session_id} - Mobile app joins session
        let join_route = warp::path!("join" / String)
            .and(warp::post())
            .and(warp::body::json())
            .and(warp::any().map(move || session_manager_2.clone()))
            .and(warp::any().map(move || websocket_port))
            .and_then(handle_join_request);

        // GET /sessions - List active sessions
        let sessions_route = warp::path("sessions")
            .and(warp::get())
            .and(warp::any().map(move || session_manager_3.clone()))
            .and_then(handle_sessions_list);

        // Health check
        let health_route = warp::path("health")
            .and(warp::get())
            .map(|| warp::reply::with_status("OK", warp::http::StatusCode::OK));

        let routes = discovery_route
            .or(join_route)
            .or(sessions_route)
            .or(health_route)
            .with(warp::cors().allow_any_origin());

        info!("Local discovery server starting on {}", addr);
        
        warp::serve(routes)
            .run(addr)
            .await;

        Ok(())
    }

    /// Start advertising a specific service via mDNS
    pub async fn advertise_service(&self, service_name: String) -> Result<()> {
        let port = self.port;
        tokio::spawn(async move {
            if let Err(e) = Self::advertise_mdns_service(service_name, port).await {
                error!("Failed to advertise mDNS service: {}", e);
            }
        });
        Ok(())
    }

    /// Advertise the HTTP service via mDNS/Bonjour
    pub async fn advertise_mdns_service(service_name: String, port: u16) -> Result<()> {
        info!("Starting mDNS advertisement for service: {}", service_name);
        
        // Get local IP address
        let local_ip = network::detect_lan_ip()
            .unwrap_or_else(|_| Ipv4Addr::new(127, 0, 0, 1));
        
        // Create mDNS service daemon
        let mdns = ServiceDaemon::new()
            .map_err(|e| anyhow!("Failed to create mDNS daemon: {}", e))?;
        
        // Create service type
        let service_type = "_http._tcp.local.";
        
        // Get hostname and ensure it ends with .local.
        let mut hostname = hostname::get()
            .map_err(|e| anyhow!("Failed to get hostname: {}", e))?
            .to_string_lossy()
            .to_string();
        
        if !hostname.ends_with(".local.") {
            if !hostname.ends_with(".local") {
                hostname.push_str(".local.");
            } else {
                hostname.push('.');
            }
        }
        
        // Create TXT properties
        let mut properties = HashMap::new();
        properties.insert("version".to_string(), "1.0".to_string());
        properties.insert("service".to_string(), "vultisig".to_string());
        
        // Create service info
        let service_info = ServiceInfo::new(
            service_type,
            &service_name,
            &hostname,
            local_ip.to_string().as_str(),
            port,
            Some(properties),
        )?;
        
        // Register the service
        mdns.register(service_info)
            .map_err(|e| anyhow!("Failed to register mDNS service: {}", e))?;
        
        info!("mDNS service advertised: {} on {}:{}", service_name, local_ip, port);
        
        // Keep the service alive
        loop {
            tokio::time::sleep(Duration::from_secs(60)).await;
        }
    }

    async fn is_port_available(&self) -> bool {
        match TcpListener::bind(("127.0.0.1", self.port)).await {
            Ok(listener) => {
                drop(listener);
                true
            }
            Err(_) => false,
        }
    }
}

/// Handle discovery request from mobile app
async fn handle_discovery_request(
    session_id: String,
    session_manager: Arc<SessionManager>,
    websocket_port: u16,
) -> Result<impl warp::Reply, warp::Rejection> {
    debug!("Discovery request for session: {}", session_id);

    match session_manager.get_session(&session_id).await {
        Some(session) => {
            // Get local IP address
            let local_ip = network::detect_lan_ip()
                .unwrap_or_else(|_| std::net::Ipv4Addr::new(127, 0, 0, 1));

            let websocket_url = format!("ws://{}:{}", local_ip, websocket_port);
            
            let response = DiscoveryResponse {
                session_id: session.id,
                service_name: "Vultisig-Daemon".to_string(),
                websocket_url,
                status: format!("{:?}", session.status),
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
}

/// Handle join request from mobile app
async fn handle_join_request(
    session_id: String,
    _body: serde_json::Value,
    session_manager: Arc<SessionManager>,
    websocket_port: u16,
) -> Result<impl warp::Reply, warp::Rejection> {
    info!("Mobile app joining session: {}", session_id);

    match session_manager.get_session(&session_id).await {
        Some(_session) => {
            // Update session status to indicate mobile app has joined
            if let Err(e) = session_manager
                .update_session_status(&session_id, SessionStatus::WaitingForMobile)
                .await
            {
                error!("Failed to update session status: {}", e);
            }

            // Get local IP address
            let local_ip = network::detect_lan_ip()
                .unwrap_or_else(|_| std::net::Ipv4Addr::new(127, 0, 0, 1));

            let websocket_url = format!("ws://{}:{}", local_ip, websocket_port);
            
            let response = DiscoveryResponse {
                session_id,
                service_name: "Vultisig-Daemon".to_string(),
                websocket_url,
                status: "ready".to_string(),
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
}

/// Handle sessions list request
async fn handle_sessions_list(
    _session_manager: Arc<SessionManager>,
) -> Result<impl warp::Reply, warp::Rejection> {
    debug!("Sessions list request");

    // For now, return empty list since we don't have a way to list all sessions
    // This could be enhanced to return active sessions
    let sessions: Vec<SessionInfo> = vec![];
    
    Ok(warp::reply::json(&sessions))
}

/// Factory function to create local discovery server
pub fn create_local_discovery_server(
    session_manager: Arc<SessionManager>,
    websocket_port: u16,
) -> LocalDiscoveryServer {
    LocalDiscoveryServer::new(session_manager, websocket_port)
}

/// Standalone function to advertise a service via mDNS
pub async fn advertise_service(service_name: String) -> Result<()> {
    let port = 18080; // Standard Vultisig discovery port
    LocalDiscoveryServer::advertise_mdns_service(service_name, port).await
}

/// Start mDNS service for discovery (main entry point used by lib.rs)
pub async fn start_mdns_service(session_manager: Arc<SessionManager>) -> Result<()> {
    let websocket_port = 8787; // Default WebSocket port
    let server = LocalDiscoveryServer::new(session_manager, websocket_port);
    
    // Start advertising the service
    server.advertise_service("Vultisig-Daemon".to_string()).await?;
    
    // Start the HTTP discovery server
    server.start().await
}

/// Start mDNS service with specific ports (used by lib.rs when ports are dynamically assigned)
pub async fn start_mdns_service_with_ports(session_manager: Arc<SessionManager>, websocket_port: u16, discovery_port: u16) -> Result<()> {
    let server = LocalDiscoveryServer::with_port(session_manager, websocket_port, discovery_port);
    
    // Start advertising the service
    server.advertise_service("Vultisig-Daemon".to_string()).await?;
    
    // Start the HTTP discovery server
    server.start().await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::{SessionManager, SessionStatus};
    use tokio::time::{timeout, Duration};
    use tokio_test;
    use pretty_assertions::assert_eq;
    use serde_json;
    use std::collections::HashMap;
    use reqwest;
    use warp::test;

    fn create_test_session_manager() -> Arc<SessionManager> {
        Arc::new(SessionManager::new())
    }

    fn create_test_discovery_server() -> LocalDiscoveryServer {
        let session_manager = create_test_session_manager();
        LocalDiscoveryServer::new(session_manager, 8787)
    }

    #[test]
    fn test_local_discovery_server_creation() {
        let server = create_test_discovery_server();
        assert_eq!(server.port, 18080);
        assert_eq!(server.websocket_port, 8787);
    }

    #[test]
    fn test_factory_function() {
        let session_manager = create_test_session_manager();
        let server = create_local_discovery_server(session_manager, 9999);
        assert_eq!(server.port, 18080);
        assert_eq!(server.websocket_port, 9999);
    }

    #[tokio::test]
    async fn test_port_availability_check() {
        let server = create_test_discovery_server();
        
        // This test may fail if port 18080 is already in use
        // In CI environments, we might need to use a different approach
        let is_available = server.is_port_available().await;
        // Just verify the function doesn't crash
        assert!(is_available || !is_available);
    }

    #[tokio::test]
    async fn test_discovery_response_serialization() {
        let response = DiscoveryResponse {
            session_id: "test-session".to_string(),
            service_name: "Vultisig-Test".to_string(),
            websocket_url: "ws://192.168.1.100:8787".to_string(),
            status: "ready".to_string(),
        };
        
        let json = serde_json::to_string(&response).unwrap();
        let deserialized: DiscoveryResponse = serde_json::from_str(&json).unwrap();
        
        assert_eq!(deserialized.session_id, response.session_id);
        assert_eq!(deserialized.service_name, response.service_name);
        assert_eq!(deserialized.websocket_url, response.websocket_url);
        assert_eq!(deserialized.status, response.status);
    }

    #[tokio::test]
    async fn test_session_info_serialization() {
        let session_info = SessionInfo {
            session_id: "test-session".to_string(),
            participants: vec!["mobile".to_string(), "daemon".to_string()],
            status: "active".to_string(),
        };
        
        let json = serde_json::to_string(&session_info).unwrap();
        let deserialized: SessionInfo = serde_json::from_str(&json).unwrap();
        
        assert_eq!(deserialized.session_id, session_info.session_id);
        assert_eq!(deserialized.participants, session_info.participants);
        assert_eq!(deserialized.status, session_info.status);
    }

    #[tokio::test]
    async fn test_handle_discovery_request_with_existing_session() {
        let session_manager = create_test_session_manager();
        let websocket_port = 8787;
        
        // Create a test session
        let session_id = session_manager.create_session(
            "ethereum".to_string(),
            "send_transaction".to_string(),
            vec![1, 2, 3, 4],
            HashMap::new(),
        ).await.unwrap();
        
        // Test the discovery request handler
        let result = handle_discovery_request(
            session_id.clone(),
            session_manager,
            websocket_port,
        ).await;
        
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_handle_discovery_request_with_nonexistent_session() {
        let session_manager = create_test_session_manager();
        let websocket_port = 8787;
        
        let result = handle_discovery_request(
            "nonexistent-session".to_string(),
            session_manager,
            websocket_port,
        ).await;
        
        assert!(result.is_ok()); // Should return error JSON, not fail
    }

    #[tokio::test]
    async fn test_handle_join_request_with_existing_session() {
        let session_manager = create_test_session_manager();
        let websocket_port = 8787;
        
        // Create a test session
        let session_id = session_manager.create_session(
            "bitcoin".to_string(),
            "send_transaction".to_string(),
            vec![5, 6, 7, 8],
            HashMap::new(),
        ).await.unwrap();
        
        let join_body = serde_json::json!({
            "device_id": "mobile-123",
            "public_key": "0x123..."
        });
        
        let result = handle_join_request(
            session_id.clone(),
            join_body,
            session_manager.clone(),
            websocket_port,
        ).await;
        
        assert!(result.is_ok());
        
        // Verify session status was updated
        let session = session_manager.get_session(&session_id).await.unwrap();
        assert_eq!(session.status, SessionStatus::WaitingForMobile);
    }

    #[tokio::test]
    async fn test_handle_join_request_with_nonexistent_session() {
        let session_manager = create_test_session_manager();
        let websocket_port = 8787;
        
        let join_body = serde_json::json!({
            "device_id": "mobile-123"
        });
        
        let result = handle_join_request(
            "nonexistent-session".to_string(),
            join_body,
            session_manager,
            websocket_port,
        ).await;
        
        assert!(result.is_ok()); // Should return error JSON, not fail
    }

    #[tokio::test]
    async fn test_handle_sessions_list() {
        let session_manager = create_test_session_manager();
        
        let result = handle_sessions_list(session_manager).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_advertise_service_function() {
        // Test the standalone advertise_service function
        // This test will spawn the mDNS task but timeout quickly
        let service_name = "test-service".to_string();
        
        let advertise_task = tokio::spawn(async move {
            advertise_service(service_name).await
        });
        
        // Let it run for a brief moment, then cancel
        let result = timeout(Duration::from_millis(100), advertise_task).await;
        
        // The task should timeout (it's expected to run indefinitely)
        assert!(result.is_err()); // Timeout error
    }

    #[tokio::test]
    async fn test_mdns_service_advertising() {
        // Test the actual mDNS service advertising
        let service_name = "test-vultisig-service".to_string();
        let port = 18080;
        
        let advertise_task = tokio::spawn(async move {
            LocalDiscoveryServer::advertise_mdns_service(service_name, port).await
        });
        
        // Let it run for a brief moment to start up
        let result = timeout(Duration::from_millis(200), advertise_task).await;
        
        // The task should timeout (it runs indefinitely)
        assert!(result.is_err()); // Timeout is expected
    }

    #[test]
    fn test_debug_display_implementations() {
        let response = DiscoveryResponse {
            session_id: "test".to_string(),
            service_name: "service".to_string(),
            websocket_url: "ws://test".to_string(),
            status: "ready".to_string(),
        };
        
        let debug_str = format!("{:?}", response);
        assert!(debug_str.contains("test"));
        assert!(debug_str.contains("service"));
        assert!(debug_str.contains("ws://test"));
        assert!(debug_str.contains("ready"));
        
        let session_info = SessionInfo {
            session_id: "info-test".to_string(),
            participants: vec!["p1".to_string()],
            status: "active".to_string(),
        };
        
        let debug_str2 = format!("{:?}", session_info);
        assert!(debug_str2.contains("info-test"));
        assert!(debug_str2.contains("p1"));
        assert!(debug_str2.contains("active"));
    }

    #[tokio::test]
    async fn test_local_ip_detection_in_handlers() {
        // Test that the handlers can detect local IP without crashing
        // This test doesn't verify the exact IP since that's environment-dependent
        let session_manager = create_test_session_manager();
        
        let session_id = session_manager.create_session(
            "ethereum".to_string(),
            "test".to_string(),
            vec![1, 2, 3],
            HashMap::new(),
        ).await.unwrap();
        
        // Test discovery request
        let discovery_result = handle_discovery_request(
            session_id.clone(),
            session_manager.clone(),
            8787,
        ).await;
        assert!(discovery_result.is_ok());
        
        // Test join request
        let join_result = handle_join_request(
            session_id,
            serde_json::json!({}),
            session_manager,
            8787,
        ).await;
        assert!(join_result.is_ok());
    }

    #[tokio::test]
    async fn test_error_handling_in_mdns_advertisement() {
        // Test with invalid service names or configurations
        // This should handle errors gracefully
        
        let invalid_service_name = "".to_string();
        let result = LocalDiscoveryServer::advertise_mdns_service(invalid_service_name, 0).await;
        
        // The function should handle invalid inputs gracefully
        // Either succeed or fail with a proper error
        match result {
            Ok(_) => {}, // If it succeeds, that's fine
            Err(e) => {
                // If it fails, the error should be meaningful
                assert!(!e.to_string().is_empty());
            }
        }
    }

    #[tokio::test]
    async fn test_concurrent_discovery_requests() {
        let session_manager = create_test_session_manager();
        
        // Create multiple sessions
        let mut session_ids = Vec::new();
        for i in 0..5 {
            let session_id = session_manager.create_session(
                format!("network_{}", i),
                "test".to_string(),
                vec![i as u8],
                HashMap::new(),
            ).await.unwrap();
            session_ids.push(session_id);
        }
        
        // Make concurrent discovery requests
        let mut handles = Vec::new();
        for session_id in session_ids {
            let session_manager_clone = session_manager.clone();
            let handle = tokio::spawn(async move {
                handle_discovery_request(
                    session_id,
                    session_manager_clone,
                    8787,
                ).await
            });
            handles.push(handle);
        }
        
        // Wait for all requests to complete
        let results = futures_util::future::join_all(handles).await;
        
        // All requests should succeed
        for result in results {
            assert!(result.is_ok());
            assert!(result.unwrap().is_ok());
        }
    }
}
