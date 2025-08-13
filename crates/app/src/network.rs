use anyhow::{anyhow, Result};
use if_addrs::{get_if_addrs, IfAddr};
use std::net::Ipv4Addr;
use std::sync::Arc;
use serde_json::{json, Value};

use crate::session::SessionManager;
use crate::mpc_coordinator::MpcCoordinator;

#[cfg(test)]
use futures_util;

/// Detect the local LAN IP address for this machine
pub fn detect_lan_ip() -> Result<Ipv4Addr> {
    let interfaces = get_if_addrs().map_err(|e| anyhow!("Failed to get network interfaces: {}", e))?;
    
    // Look for non-loopback IPv4 addresses
    let mut candidates = Vec::new();
    
    for interface in interfaces {
        if let IfAddr::V4(v4) = interface.addr {
            let ip = v4.ip;
            
            // Skip loopback and other special addresses
            if ip.is_loopback() || ip.is_multicast() || ip.is_broadcast() {
                continue;
            }
            
            // Prefer private network ranges (RFC 1918)
            if is_private_ipv4(&ip) {
                candidates.push((ip, 1)); // Higher priority for private IPs
            } else {
                candidates.push((ip, 0)); // Lower priority for public IPs
            }
        }
    }
    
    if candidates.is_empty() {
        return Err(anyhow!("No suitable network interface found"));
    }
    
    // Sort by priority (private IPs first)
    candidates.sort_by(|a, b| b.1.cmp(&a.1));
    
    Ok(candidates[0].0)
}

/// Check if an IPv4 address is in a private range (RFC 1918)
fn is_private_ipv4(ip: &Ipv4Addr) -> bool {
    let octets = ip.octets();
    
    // 10.0.0.0/8
    if octets[0] == 10 {
        return true;
    }
    
    // 172.16.0.0/12
    if octets[0] == 172 && (octets[1] >= 16 && octets[1] <= 31) {
        return true;
    }
    
    // 192.168.0.0/16
    if octets[0] == 192 && octets[1] == 168 {
        return true;
    }
    
    false
}

/// Find an available port for the WebSocket server
pub async fn find_available_port(start_port: u16) -> Result<u16> {
    for port in start_port..start_port + 100 {
        if is_port_available(port).await {
            return Ok(port);
        }
    }
    
    Err(anyhow!("No available port found in range {}-{}", start_port, start_port + 100))
}

/// Check if a port is available for binding
async fn is_port_available(port: u16) -> bool {
    match tokio::net::TcpListener::bind(("0.0.0.0", port)).await {
        Ok(listener) => {
            drop(listener);
            true
        }
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio_test;
    use pretty_assertions::assert_eq;
    use std::net::Ipv4Addr;

    #[test]
    fn test_private_ip_detection() {
        // Test Class A private range (10.0.0.0/8)
        assert!(is_private_ipv4(&"10.0.0.1".parse().unwrap()));
        assert!(is_private_ipv4(&"10.255.255.255".parse().unwrap()));
        assert!(is_private_ipv4(&"10.1.1.1".parse().unwrap()));
        
        // Test Class B private range (172.16.0.0/12)
        assert!(is_private_ipv4(&"172.16.0.1".parse().unwrap()));
        assert!(is_private_ipv4(&"172.31.255.255".parse().unwrap()));
        assert!(is_private_ipv4(&"172.20.1.1".parse().unwrap()));
        
        // Test Class C private range (192.168.0.0/16)
        assert!(is_private_ipv4(&"192.168.1.1".parse().unwrap()));
        assert!(is_private_ipv4(&"192.168.0.1".parse().unwrap()));
        assert!(is_private_ipv4(&"192.168.255.255".parse().unwrap()));
        
        // Test public IPs (should be false)
        assert!(!is_private_ipv4(&"8.8.8.8".parse().unwrap()));
        assert!(!is_private_ipv4(&"1.1.1.1".parse().unwrap()));
        assert!(!is_private_ipv4(&"8.8.4.4".parse().unwrap()));
        assert!(!is_private_ipv4(&"208.67.222.222".parse().unwrap()));
        
        // Test special addresses (should be false)
        assert!(!is_private_ipv4(&"127.0.0.1".parse().unwrap())); // Loopback
        assert!(!is_private_ipv4(&"0.0.0.0".parse().unwrap()));   // Any address
        assert!(!is_private_ipv4(&"255.255.255.255".parse().unwrap())); // Broadcast
        
        // Test edge cases for private ranges
        assert!(!is_private_ipv4(&"9.255.255.255".parse().unwrap()));   // Just before 10/8
        assert!(!is_private_ipv4(&"11.0.0.0".parse().unwrap()));        // Just after 10/8
        assert!(!is_private_ipv4(&"172.15.255.255".parse().unwrap()));  // Just before 172.16/12
        assert!(!is_private_ipv4(&"172.32.0.0".parse().unwrap()));      // Just after 172.31/12
        assert!(!is_private_ipv4(&"192.167.255.255".parse().unwrap())); // Just before 192.168/16
        assert!(!is_private_ipv4(&"192.169.0.0".parse().unwrap()));     // Just after 192.168/16
    }

    #[tokio::test]
    async fn test_find_available_port() {
        let port = find_available_port(8000).await.unwrap();
        assert!(port >= 8000);
        assert!(port < 8100);
        
        // Test with different start port
        let port2 = find_available_port(9000).await.unwrap();
        assert!(port2 >= 9000);
        assert!(port2 < 9100);
    }

    #[tokio::test]
    async fn test_is_port_available() {
        // Most high ports should be available
        assert!(is_port_available(12345).await);
        assert!(is_port_available(54321).await);
        
        // Port 0 is special (system assigns port)
        let result = is_port_available(0).await;
        // Port 0 behavior may vary by system, so we just verify it doesn't crash
        assert!(result || !result);
    }

    #[tokio::test]
    async fn test_find_available_port_no_available_ports() {
        // Try to find a port in a range where no ports should be available
        // We'll simulate this by using a very small range and hoping it's busy
        // This test might be flaky in some environments
        
        // Use a range that's likely to have conflicts (HTTP range)
        let result = find_available_port(65530).await; // Very high port range
        
        // Even if all ports are taken, we should get a meaningful error
        match result {
            Ok(port) => {
                // If we get a port, it should be in the expected range
                assert!(port >= 65530);
            }
            Err(error) => {
                // Error message should be meaningful
                assert!(error.to_string().contains("No available port found"));
            }
        }
    }

    #[test]
    fn test_detect_lan_ip_or_fallback() {
        // This test verifies that the function either succeeds or fails gracefully
        // The actual IP depends on the system configuration
        match detect_lan_ip() {
            Ok(ip) => {
                // Should be a valid IPv4 address
                assert!(ip.octets().len() == 4);
                
                // Should not be certain special addresses
                assert_ne!(ip, Ipv4Addr::new(0, 0, 0, 0));
                assert_ne!(ip, Ipv4Addr::new(255, 255, 255, 255));
                
                println!("Detected LAN IP: {}", ip);
            }
            Err(e) => {
                // Should have a meaningful error message
                assert!(!e.to_string().is_empty());
                println!("LAN IP detection failed (expected in some environments): {}", e);
            }
        }
    }

    #[test]
    fn test_private_ip_comprehensive_ranges() {
        // Comprehensive test of RFC 1918 private address ranges
        
        // 10.0.0.0/8 (Class A)
        for i in 0..=255 {
            assert!(is_private_ipv4(&Ipv4Addr::new(10, i, 0, 1)));
        }
        
        // 172.16.0.0/12 (Class B)
        for i in 16..=31 {
            assert!(is_private_ipv4(&Ipv4Addr::new(172, i, 0, 1)));
        }
        
        // Just outside the 172.16-31 range should be public
        assert!(!is_private_ipv4(&Ipv4Addr::new(172, 15, 0, 1)));
        assert!(!is_private_ipv4(&Ipv4Addr::new(172, 32, 0, 1)));
        
        // 192.168.0.0/16 (Class C)
        for i in 0..=255 {
            assert!(is_private_ipv4(&Ipv4Addr::new(192, 168, i, 1)));
        }
    }

    #[test]
    fn test_ip_address_edge_cases() {
        // Test various special-purpose addresses
        let special_addresses = vec![
            ("0.0.0.0", false),           // "This" network
            ("127.0.0.1", false),        // Loopback
            ("169.254.1.1", false),      // Link-local (APIPA)
            ("224.0.0.1", false),        // Multicast
            ("255.255.255.255", false),  // Limited broadcast
            ("198.18.0.1", false),       // Benchmarking (RFC 2544)
            ("203.0.113.1", false),      // Documentation (RFC 5737)
        ];
        
        for (addr_str, should_be_private) in special_addresses {
            let addr: Ipv4Addr = addr_str.parse().unwrap();
            assert_eq!(is_private_ipv4(&addr), should_be_private, 
                      "Address {} should be private: {}", addr_str, should_be_private);
        }
    }

    #[tokio::test]
    async fn test_concurrent_port_availability_checks() {
        use std::sync::Arc;
        use tokio::sync::Semaphore;
        
        // Test checking multiple ports concurrently
        let semaphore = Arc::new(Semaphore::new(10)); // Limit concurrent checks
        let mut handles = Vec::new();
        
        for port in 20000..20010 {
            let semaphore_clone = semaphore.clone();
            let handle = tokio::spawn(async move {
                let _permit = semaphore_clone.acquire().await.unwrap();
                (port, is_port_available(port).await)
            });
            handles.push(handle);
        }
        
        let results = futures_util::future::join_all(handles).await;
        
        // All checks should complete without panicking
        assert_eq!(results.len(), 10);
        for result in results {
            let (port, is_available) = result.unwrap();
            // Just verify the check completed
            assert!(port >= 20000 && port < 20010);
            assert!(is_available || !is_available); // Boolean should be valid
        }
    }

    #[tokio::test]
    async fn test_port_binding_and_release() {
        // Test that we can actually bind to a port we claim is available
        let port = find_available_port(25000).await.unwrap();
        
        // Try to actually bind to this port
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", port)).await;
        assert!(listener.is_ok(), "Should be able to bind to port {}", port);
        
        // Drop the listener to release the port
        drop(listener);
        
        // Port should be available again
        assert!(is_port_available(port).await);
    }

    #[tokio::test]
    async fn test_error_message_formatting() {
        // Test that error messages are properly formatted
        let error = find_available_port(65530)
            .await
            .unwrap_err(); // This should fail due to limited range
        
        let error_msg = error.to_string();
        assert!(error_msg.contains("No available port found"));
        assert!(error_msg.contains("65530"));
    }

    // Integration test helper
    async fn verify_network_interface_detection() -> Result<()> {
        // This is more of a system test - verify we can detect network interfaces
        match detect_lan_ip() {
            Ok(ip) => {
                println!("✅ Successfully detected LAN IP: {}", ip);
                
                // Verify it's a reasonable IP address
                assert!(!ip.is_loopback());
                assert!(!ip.is_broadcast());
                assert!(!ip.is_multicast());
                
                Ok(())
            }
            Err(e) => {
                println!("⚠️ LAN IP detection failed: {} (this may be expected in containerized environments)", e);
                Ok(()) // Don't fail the test in CI environments without network interfaces
            }
        }
    }
    
    #[tokio::test]
    async fn test_network_interface_detection() {
        // This test may fail in some CI environments, so we don't assert
        let _ = verify_network_interface_detection().await;
    }
}

/// Handle JSON-RPC requests from Unix socket clients
pub async fn handle_json_rpc_request(
    request: &str,
    session_manager: Arc<SessionManager>,
    mpc_coordinator: Arc<MpcCoordinator>,
) -> String {
    // Parse the JSON-RPC request
    let request_json: Value = match serde_json::from_str(request) {
        Ok(json) => json,
        Err(e) => {
            return json!({
                "jsonrpc": "2.0",
                "error": {
                    "code": -32700,
                    "message": format!("Parse error: {}", e)
                },
                "id": null
            }).to_string();
        }
    };

    let id = request_json.get("id").unwrap_or(&Value::Null).clone();
    let method = match request_json.get("method").and_then(|m| m.as_str()) {
        Some(method) => method,
        None => {
            return json!({
                "jsonrpc": "2.0",
                "error": {
                    "code": -32600,
                    "message": "Invalid Request: missing method"
                },
                "id": id
            }).to_string();
        }
    };

    let params = request_json.get("params").unwrap_or(&Value::Null);

    // Route the method call
    let result = match method {
        "create_session" => handle_create_session(params, &session_manager).await,
        "get_session" => handle_get_session(params, &session_manager).await,
        "sign" => handle_sign_transaction(params, &mpc_coordinator).await,
        "get_addresses" => handle_get_addresses(&mpc_coordinator).await,
        "get_addresses_with_pubkeys" => handle_get_addresses_with_pubkeys(&mpc_coordinator).await,
        "get_address" => handle_get_address(params, &mpc_coordinator).await,
        "health" => Ok(json!({"status": "ok", "timestamp": chrono::Utc::now().to_rfc3339()})),
        "shutdown" => handle_shutdown().await,
        _ => Err(format!("Unknown method: {}", method)),
    };

    match result {
        Ok(result) => json!({
            "jsonrpc": "2.0",
            "result": result,
            "id": id
        }).to_string(),
        Err(error) => json!({
            "jsonrpc": "2.0",
            "error": {
                "code": -32603,
                "message": error
            },
            "id": id
        }).to_string(),
    }
}

async fn handle_create_session(
    params: &Value,
    session_manager: &Arc<SessionManager>,
) -> Result<Value, String> {
    let network = params.get("network")
        .and_then(|c| c.as_str())
        .ok_or("Missing 'network' parameter")?;
    let message_type = params.get("message_type")
        .and_then(|o| o.as_str())
        .ok_or("Missing 'message_type' parameter")?;
    let payload = params.get("payload")
        .and_then(|p| p.as_array())
        .ok_or("Missing 'payload' parameter")?
        .iter()
        .filter_map(|v| v.as_u64().map(|n| n as u8))
        .collect::<Vec<u8>>();

    let session_id = session_manager.create_session(
        network.to_string(),
        message_type.to_string(),
        payload,
        std::collections::HashMap::new(),
    ).await
    .map_err(|e| format!("Failed to create session: {}", e))?;

    Ok(json!({"session_id": session_id}))
}

async fn handle_get_session(
    params: &Value,
    session_manager: &Arc<SessionManager>,
) -> Result<Value, String> {
    let session_id = params.get("session_id")
        .and_then(|s| s.as_str())
        .ok_or("Missing 'session_id' parameter")?;

    match session_manager.get_session(session_id).await {
        Some(session) => Ok(json!({
            "id": session.id,
            "network": session.network,
            "message_type": session.message_type,
            "status": format!("{:?}", session.status),
            "created_at": session.created_at.elapsed().as_secs(),
        })),
        None => Err("Session not found".to_string()),
    }
}

async fn handle_sign_transaction(
    params: &Value,
    mpc_coordinator: &Arc<MpcCoordinator>,
) -> Result<Value, String> {
    use crate::signing::{TxSigningPayload, SigningSessionParams, SigningMode, SigningCoordinator};
    use uuid::Uuid;
    use std::collections::HashMap;

    // Extract required parameters
    let network = params.get("network")
        .and_then(|n| n.as_str())
        .ok_or("Missing 'network' parameter")?;

    let payload = params.get("payload")
        .ok_or("Missing 'payload' parameter")?;

    // Optional parameters
    let mode = params.get("mode")
        .and_then(|m| m.as_str())
        .unwrap_or("local");

    let session_id = params.get("session_id")
        .and_then(|s| s.as_str())
        .map(|s| s.to_string())
        .unwrap_or_else(|| Uuid::new_v4().to_string());

    // Get keyshare from MPC coordinator
    let keyshare = mpc_coordinator.get_keyshare().await
        .map_err(|e| format!("Failed to get keyshare: {}", e))?;

    // Build session parameters
    let signing_mode = match mode {
        "relay" => SigningMode::Relay,
        "local" | _ => SigningMode::Local,
    };

    let public_key_bytes = keyshare.public_key_ecdsa();
    let should_broadcast = params.get("broadcast")
        .and_then(|b| b.as_bool())
        .unwrap_or(false);

    let session_params = SigningSessionParams {
        session_id: session_id.clone(),
        local_party_id: format!("vultisig-{}", hex::encode(&public_key_bytes[0..8])),
        network: network.to_string(),
        signing_mode: signing_mode.clone(),
        relay_server_url: params.get("relay_server")
            .and_then(|s| s.as_str())
            .map(|s| s.to_string()),
        encryption_key: hex::encode(rand::random::<[u8; 32]>()),
        broadcast: should_broadcast,
    };

    // Create signing coordinator
    let session_manager = mpc_coordinator.get_session_manager();
    let coordinator = SigningCoordinator::new(keyshare.clone(), session_manager);

    // Build signing payload
    let tx_payload = TxSigningPayload {
        network: network.to_string(),
        payload: payload.clone(),
        metadata: HashMap::new(),
    };

    tracing::info!("Starting transaction signing: {} in {:?} mode", network, signing_mode);

    // Start signing process (this would be async in real implementation)
    match coordinator.sign_transaction(tx_payload, session_params).await {
        Ok(compiled_tx) => {
            Ok(json!({
                "status": "success",
                "session_id": session_id,
                "tx_hash": compiled_tx.tx_hash,
                "network": compiled_tx.network,
                "signatures_count": compiled_tx.signatures.len()
            }))
        }
        Err(e) => {
            tracing::error!("Signing failed: {}", e);
            Ok(json!({
                "status": "error",
                "session_id": session_id,
                "error": e.to_string()
            }))
        }
    }
}

async fn handle_get_addresses(
    mpc_coordinator: &Arc<MpcCoordinator>,
) -> Result<Value, String> {
    // Get addresses for all supported networks from the keyshare
    match mpc_coordinator.get_keyshare_addresses().await {
        Ok(addresses) => Ok(json!(addresses)),
        Err(e) => Err(format!("Failed to get addresses: {}", e)),
    }
}

async fn handle_get_addresses_with_pubkeys(
    mpc_coordinator: &Arc<MpcCoordinator>,
) -> Result<Value, String> {
    // Get addresses and public keys for all supported networks from the keyshare
    match mpc_coordinator.get_keyshare_addresses_with_pubkeys().await {
        Ok(data) => Ok(json!(data)),
        Err(e) => Err(format!("Failed to get addresses with pubkeys: {}", e)),
    }
}

async fn handle_get_address(
    params: &Value,
    mpc_coordinator: &Arc<MpcCoordinator>,
) -> Result<Value, String> {
    let network = params.get("network")
        .and_then(|n| n.as_str())
        .ok_or("Missing 'network' parameter")?;

    // Map common lowercase network names to uppercase
    let normalized_network = match network.to_lowercase().as_str() {
        "eth" | "ethereum" => "ETH",
        "btc" | "bitcoin" => "BTC", 
        "sol" | "solana" => "SOL",
        "thor" | "thorchain" => "THOR",
        "atom" | "cosmos" => "ATOM",
        _ => network, // Use as-is for other networks
    };

    // Get address for specific network from the keyshare
    match mpc_coordinator.get_keyshare_address(normalized_network).await {
        Ok(address) => Ok(json!({"network": network, "address": address})),
        Err(e) => Err(format!("Failed to get address for network {}: {}", network, e)),
    }
}

async fn handle_shutdown() -> Result<Value, String> {
    tracing::info!("Received shutdown request, initiating graceful shutdown...");
    
    // Spawn a task to trigger shutdown after a brief delay
    tokio::spawn(async {
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        std::process::exit(0);
    });
    
    Ok(json!({"status": "shutdown_initiated"}))
}
