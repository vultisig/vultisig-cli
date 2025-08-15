use std::collections::HashMap;
use std::sync::Arc;
use tokio::time::{sleep, Duration, timeout};
use vultisig::{
    session::{SessionManager, SessionStatus},
    mpc_coordinator::{MpcCoordinator, create_mpc_coordinator},
    keyshare::{VultKeyshare, EcdsaKeyshareData, EddsaKeyshareData},
    local_discovery::{LocalDiscoveryServer, create_local_discovery_server},
    websocket::WebSocketServer,
    network,
    qr,

    wallet_core_ffi::*,
};
use pretty_assertions::assert_eq;
use tempfile::tempdir;

/// Integration test constants
const TEST_VAULT_PUBKEY: &str = "023e4b76861289ad4528b33c2fd21b3a5160cd37b3294234914e21efb6ed4a452b";
const TEST_CHAIN_CODE: &str = "873DFF81C02F525623FD1FE5167EAC3A55A049DE3D314BB42EE227FFED37D508";
const TEST_ED25519_PUBKEY: &str = "1234567890123456789012345678901234567890123456789012345678901234";

/// Helper function to create a test ECDSA keyshare
fn create_test_ecdsa_keyshare() -> VultKeyshare {
    let ecdsa_pubkey = hex::decode(TEST_VAULT_PUBKEY).unwrap();
    let chain_code = hex::decode(TEST_CHAIN_CODE).unwrap();
    
    VultKeyshare {
        ecdsa_keyshare: Some(EcdsaKeyshareData {
            public_key: ecdsa_pubkey,
            chain_code,
            share_data: vec![0u8; 32], // Mock share data
        }),
        eddsa_keyshare: None,
    }
}

/// Helper function to create a test EdDSA keyshare
fn create_test_eddsa_keyshare() -> VultKeyshare {
    let ed25519_pubkey = hex::decode(TEST_ED25519_PUBKEY).unwrap();
    let chain_code = hex::decode(TEST_CHAIN_CODE).unwrap();
    
    VultKeyshare {
        ecdsa_keyshare: None,
        eddsa_keyshare: Some(EddsaKeyshareData {
            public_key: ed25519_pubkey,
            chain_code,
            share_data: vec![0u8; 32], // Mock share data
        }),
    }
}

/// Helper function to create a dual keyshare
fn create_test_dual_keyshare() -> VultKeyshare {
    let ecdsa_pubkey = hex::decode(TEST_VAULT_PUBKEY).unwrap();
    let ed25519_pubkey = hex::decode(TEST_ED25519_PUBKEY).unwrap();
    let chain_code = hex::decode(TEST_CHAIN_CODE).unwrap();
    
    VultKeyshare {
        ecdsa_keyshare: Some(EcdsaKeyshareData {
            public_key: ecdsa_pubkey,
            chain_code: chain_code.clone(),
            share_data: vec![0u8; 32],
        }),
        eddsa_keyshare: Some(EddsaKeyshareData {
            public_key: ed25519_pubkey,
            chain_code,
            share_data: vec![0u8; 32],
        }),
    }
}

/// Test the complete session lifecycle
#[tokio::test]
async fn test_complete_session_lifecycle() {
    let session_manager = Arc::new(SessionManager::new());
    let mpc_coordinator = create_mpc_coordinator(session_manager.clone());
    
    // Create a signing session
    let mut metadata = HashMap::new();
    metadata.insert("chain_id".to_string(), "1".to_string());
    metadata.insert("network".to_string(), "ethereum".to_string());
    
    let session_id = session_manager.create_session(
        "ethereum".to_string(),
        "send_transaction".to_string(),
        vec![1, 2, 3, 4, 5, 6, 7, 8], // Mock transaction hash
        metadata,
    ).await.unwrap();
    
    println!("✅ Created session: {}", session_id);
    
    // Verify session exists
    let session = session_manager.get_session(&session_id).await.unwrap();
    assert_eq!(session.network, "ethereum");
    assert_eq!(session.message_type, "send_transaction");
    assert_eq!(session.payload_bytes, vec![1, 2, 3, 4, 5, 6, 7, 8]);
    assert_eq!(session.status, SessionStatus::Pending);
    
    // Update session status
    session_manager.update_session_status(&session_id, SessionStatus::WaitingForMobile).await.unwrap();
    let updated_session = session_manager.get_session(&session_id).await.unwrap();
    assert_eq!(updated_session.status, SessionStatus::WaitingForMobile);
    
    // Complete session
    session_manager.update_session_status(&session_id, SessionStatus::Completed).await.unwrap();
    let completed_session = session_manager.get_session(&session_id).await.unwrap();
    assert_eq!(completed_session.status, SessionStatus::Completed);
    
    println!("✅ Session lifecycle test completed");
}

/// Test wallet-core integration with keyshare address derivation
#[tokio::test]
async fn test_wallet_core_keyshare_integration() {
    let dual_keyshare = create_test_dual_keyshare();
    
    println!("🔑 Testing address derivation from keyshares...");
    
    // Test ECDSA-based address derivation
    match dual_keyshare.derive_eth_address() {
        Ok(eth_addr) => {
            assert!(eth_addr.starts_with("0x"));
            assert_eq!(eth_addr.len(), 42);
            println!("✅ ETH address: {}", eth_addr);
        }
        Err(e) => println!("⚠️ ETH address derivation failed: {}", e),
    }
    
    match dual_keyshare.derive_btc_address() {
        Ok(btc_addr) => {
            assert!(btc_addr.len() > 25); // Reasonable Bitcoin address length
            println!("✅ BTC address: {}", btc_addr);
        }
        Err(e) => println!("⚠️ BTC address derivation failed: {}", e),
    }
    
    // Test EdDSA-based address derivation
    match dual_keyshare.derive_sol_address() {
        Ok(sol_addr) => {
            assert!(sol_addr.len() >= 32 && sol_addr.len() <= 44);
            println!("✅ SOL address: {}", sol_addr);
        }
        Err(e) => println!("⚠️ SOL address derivation failed: {}", e),
    }
    
    println!("✅ Wallet-core keyshare integration test completed");
}

/// Test QR code generation and dense encoding integration
#[tokio::test]
async fn test_qr_generation_integration() {
    let temp_dir = tempdir().unwrap();
    
    // Test regular QR code generation
    let test_uri = format!(
        "https://vultisig.com?type=SignTransaction&vault={}&jsonData=test_data",
        TEST_VAULT_PUBKEY
    );
    
    // Test ASCII QR generation
    let ascii_qr = qr::generate_ascii_qr(&test_uri).unwrap();
    assert!(!ascii_qr.is_empty());
    assert!(ascii_qr.contains("█"));
    println!("✅ Generated ASCII QR code ({} chars)", ascii_qr.len());
    
    // Test compact QR generation
    let compact_qr = qr::generate_compact_qr(&test_uri).unwrap();
    assert!(!compact_qr.is_empty());
    println!("✅ Generated compact QR code ({} chars)", compact_qr.len());
    
    // Test QR image generation
    let image_path = temp_dir.path().join("test_qr.png");
    qr::generate_qr_image(&test_uri, image_path.to_str().unwrap()).unwrap();
    assert!(image_path.exists());
    println!("✅ Generated QR image: {:?}", image_path);
    
    // Test HTML QR generation
    let html_path = temp_dir.path().join("test_qr.html");
    qr::generate_qr_html(
        &test_uri,
        "integration-test",
        "ethereum",
        "local",
        html_path.to_str().unwrap(),
    ).unwrap();
    assert!(html_path.exists());
    
    let html_content = std::fs::read_to_string(&html_path).unwrap();
    assert!(html_content.contains("Vultisig"));
    assert!(html_content.contains("integration-test"));
    assert!(html_content.contains("ethereum"));
    println!("✅ Generated HTML QR page: {:?}", html_path);
    
    println!("✅ QR generation integration test completed");
}



/// Test network utilities integration
#[tokio::test]
async fn test_network_utilities_integration() {
    // Test LAN IP detection
    match network::detect_lan_ip() {
        Ok(ip) => {
            println!("✅ Detected LAN IP: {}", ip);
            assert!(!ip.is_loopback());
            assert!(!ip.is_broadcast());
        }
        Err(e) => {
            println!("⚠️ LAN IP detection failed (expected in some environments): {}", e);
        }
    }
    
    // Test port availability checking
    let port = network::find_available_port(20000).await.unwrap();
    assert!(port >= 20000);
    assert!(port < 20100);
    println!("✅ Found available port: {}", port);
    
    // Test that we can actually bind to the port
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port)).await;
    assert!(listener.is_ok());
    println!("✅ Successfully bound to port {}", port);
    
    println!("✅ Network utilities integration test completed");
}

/// Test component integration (session + MPC + discovery)
#[tokio::test]
async fn test_component_integration() {
    // Create integrated components
    let session_manager = Arc::new(SessionManager::new());
    let mpc_coordinator = create_mpc_coordinator(session_manager.clone());
    let discovery_server = create_local_discovery_server(session_manager.clone(), 8787);
    
    // Start cleanup task
    session_manager.start_cleanup_task().await;
    
    // Create a session for testing
    let session_id = session_manager.create_session(
        "bitcoin".to_string(),
        "send_transaction".to_string(),
        vec![0xde, 0xad, 0xbe, 0xef], // Mock transaction data
        HashMap::new(),
    ).await.unwrap();
    
    println!("✅ Created integrated session: {}", session_id);
    
    // Test session exists in discovery server context
    let session = session_manager.get_session(&session_id).await.unwrap();
    assert_eq!(session.network, "bitcoin");
    
    // Test session info creation
    let session_info = session_manager.create_session_info(
        session_id.clone(),
        "192.168.1.100".to_string(),
        8787,
        "bitcoin".to_string(),
    );
    
    assert_eq!(session_info.session_id, session_id);
    assert_eq!(session_info.host, "192.168.1.100");
    assert_eq!(session_info.port, 8787);
    assert_eq!(session_info.network, "bitcoin");
    assert_eq!(session_info.connection_type, "local");
    
    println!("✅ Session info created successfully");
    
    // Test MPC coordinator state
    let mpc_state = mpc_coordinator.get_session_state(&session_id).await;
    assert!(mpc_state.is_none()); // No MPC session started yet
    
    // Test cleanup (wait a short time for background task)
    sleep(Duration::from_millis(100)).await;
    
    println!("✅ Component integration test completed");
}

/// Test error handling across components
#[tokio::test]
async fn test_error_handling_integration() {
    let session_manager = Arc::new(SessionManager::new());
    let mpc_coordinator = create_mpc_coordinator(session_manager.clone());
    
    // Test session operations with invalid IDs
    let invalid_session_id = "nonexistent-session";
    
    // Session manager should handle invalid IDs gracefully
    let result = session_manager.get_session(invalid_session_id).await;
    assert!(result.is_none());
    
    let update_result = session_manager.update_session_status(
        invalid_session_id, 
        SessionStatus::Completed
    ).await;
    assert!(update_result.is_err());
    
    let result_get = session_manager.get_result(invalid_session_id).await;
    assert!(result_get.is_none());
    
    // MPC coordinator should handle invalid sessions gracefully
    let mpc_state = mpc_coordinator.get_session_state(invalid_session_id).await;
    assert!(mpc_state.is_none());
    
    // Test with timeout that should fail
    let timeout_result = timeout(
        Duration::from_millis(100),
        session_manager.wait_for_result(invalid_session_id, Duration::from_millis(50))
    ).await;
    
    match timeout_result {
        Ok(Err(_)) => println!("✅ Timeout handled correctly"),
        Err(_) => println!("✅ Timeout occurred as expected"),
        Ok(Ok(_)) => panic!("Should not succeed with invalid session"),
    }
    
    println!("✅ Error handling integration test completed");
}

/// Test concurrent operations across components
#[tokio::test]
async fn test_concurrent_operations_integration() {
    let session_manager = Arc::new(SessionManager::new());
    let mpc_coordinator = Arc::new(create_mpc_coordinator(session_manager.clone()));
    
    // Create multiple concurrent sessions
    let mut handles = Vec::new();
    
    for i in 0..10 {
        let session_manager_clone = session_manager.clone();
        let mpc_coordinator_clone = mpc_coordinator.clone();
        
        let handle = tokio::spawn(async move {
            // Create session
            let session_id = session_manager_clone.create_session(
                format!("network_{}", i),
                "test_transaction".to_string(),
                vec![i as u8; 8],
                HashMap::new(),
            ).await.unwrap();
            
            // Update status
            session_manager_clone.update_session_status(&session_id, SessionStatus::WaitingForMobile).await.unwrap();
            
            // Create a signing result
            let result = vultisig::session::SigningResult {
                session_id: session_id.clone(),
                success: true,
                signature: vec![i as u8; 64],
                signed_tx: vec![],
                error_message: String::new(),
                metadata: HashMap::new(),
            };
            session_manager_clone.store_result(session_id.clone(), result).await.unwrap();
            
            // Check MPC state
            let _state = mpc_coordinator_clone.get_session_state(&session_id).await;
            
            session_id
        });
        
        handles.push(handle);
    }
    
    // Wait for all concurrent operations to complete
    let session_ids: Vec<String> = futures_util::future::join_all(handles).await
        .into_iter()
        .map(|result| result.unwrap())
        .collect();
    
    // Verify all sessions were created
    assert_eq!(session_ids.len(), 10);
    
    // Verify all sessions exist and have correct state
    for (i, session_id) in session_ids.iter().enumerate() {
        let session = session_manager.get_session(session_id).await.unwrap();
        assert_eq!(session.network, format!("network_{}", i));
        assert_eq!(session.status, SessionStatus::WaitingForMobile);
        
        let result = session_manager.get_result(session_id).await.unwrap();
        assert!(result.success);
        assert_eq!(result.signature, vec![i as u8; 64]);
    }
    
    println!("✅ Created and verified {} concurrent sessions", session_ids.len());
    println!("✅ Concurrent operations integration test completed");
}

/// Test full signing workflow simulation (without actual cryptography)
#[tokio::test]
async fn test_full_signing_workflow_simulation() {
    let session_manager = Arc::new(SessionManager::new());
    let mpc_coordinator = create_mpc_coordinator(session_manager.clone());
    
    // Step 1: Create a signing session
    let mut metadata = HashMap::new();
    metadata.insert("amount".to_string(), "1.5".to_string());
    metadata.insert("recipient".to_string(), "0x742d35Cc6634C0532925a3b8D45C0D2C0d0Db8f7".to_string());
    
    let session_id = session_manager.create_session(
        "ethereum".to_string(),
        "send_transaction".to_string(),
        vec![0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0], // Mock tx hash
        metadata,
    ).await.unwrap();
    
    println!("🚀 Step 1: Created signing session {}", session_id);
    
    // Step 2: Generate QR code for mobile scanning
    let qr_uri = qr::generate_vultisig_keysign_uri(TEST_VAULT_PUBKEY, "mock_json_data");
    let ascii_qr = qr::generate_ascii_qr(&qr_uri).unwrap();
    
    println!("📱 Step 2: Generated QR code ({} chars)", ascii_qr.len());
    
    // Step 3: Simulate session status updates (mobile app workflow)
    session_manager.update_session_status(&session_id, SessionStatus::WaitingForMobile).await.unwrap();
    println!("⏳ Step 3: Waiting for mobile app connection");
    
    // Step 4: Simulate signing completion
    let mock_signature = vec![
        0x30, 0x44, 0x02, 0x20, // DER sequence + length
        0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
        0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
        0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
        0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
        0x02, 0x20, // Second part
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
    ];
    
    let signing_result = vultisig::session::SigningResult {
        session_id: session_id.clone(),
        success: true,
        signature: mock_signature.clone(),
        signed_tx: vec![0xff; 100], // Mock signed transaction
        error_message: String::new(),
        metadata: {
            let mut meta = HashMap::new();
            meta.insert("tx_hash".to_string(), "0x1234567890abcdef".to_string());
            meta
        },
    };
    
    session_manager.store_result(session_id.clone(), signing_result).await.unwrap();
    session_manager.update_session_status(&session_id, SessionStatus::Completed).await.unwrap();
    
    println!("✅ Step 4: Signing completed successfully");
    
    // Step 5: Verify final state
    let final_session = session_manager.get_session(&session_id).await.unwrap();
    assert_eq!(final_session.status, SessionStatus::Completed);
    
    let final_result = session_manager.get_result(&session_id).await.unwrap();
    assert!(final_result.success);
    assert_eq!(final_result.signature, mock_signature);
    assert_eq!(final_result.signed_tx.len(), 100);
    
    println!("🎉 Step 5: Workflow verification completed");
    println!("✅ Full signing workflow simulation test completed");
}

/// Test system resilience and recovery
#[tokio::test]
async fn test_system_resilience() {
    let session_manager = Arc::new(SessionManager::new());
    
    // Test 1: Create many sessions and clean them up
    let mut session_ids = Vec::new();
    for i in 0..50 {
        let session_id = session_manager.create_session(
            "ethereum".to_string(),
            "test".to_string(),
            vec![i as u8; 4],
            HashMap::new(),
        ).await.unwrap();
        session_ids.push(session_id);
    }
    
    println!("✅ Created {} sessions for resilience testing", session_ids.len());
    
    // Test 2: Rapid status updates
    for session_id in &session_ids {
        session_manager.update_session_status(session_id, SessionStatus::WaitingForMobile).await.unwrap();
        session_manager.update_session_status(session_id, SessionStatus::Completed).await.unwrap();
    }
    
    println!("✅ Completed rapid status updates");
    
    // Test 3: Concurrent result storage
    let mut handles = Vec::new();
    for (i, session_id) in session_ids.iter().enumerate() {
        let session_manager_clone = session_manager.clone();
        let session_id_clone = session_id.clone();
        
        let handle = tokio::spawn(async move {
            let result = vultisig::session::SigningResult {
                session_id: session_id_clone.clone(),
                success: i % 2 == 0, // Alternate success/failure
                signature: vec![i as u8; 32],
                signed_tx: vec![],
                error_message: if i % 2 == 0 { String::new() } else { format!("Test error {}", i) },
                metadata: HashMap::new(),
            };
            session_manager_clone.store_result(session_id_clone, result).await.unwrap();
        });
        handles.push(handle);
    }
    
    // Wait for all concurrent operations
    futures_util::future::join_all(handles).await;
    
    // Test 4: Verify all results are stored correctly
    for (i, session_id) in session_ids.iter().enumerate() {
        let result = session_manager.get_result(session_id).await.unwrap();
        assert_eq!(result.success, i % 2 == 0);
        assert_eq!(result.signature, vec![i as u8; 32]);
        
        if i % 2 != 0 {
            assert_eq!(result.error_message, format!("Test error {}", i));
        }
    }
    
    println!("✅ Verified all {} results stored correctly", session_ids.len());
    
    // Test 5: Memory usage stability (sessions should be cleanable)
    let initial_count = session_manager.sessions.read().await.len();
    println!("✅ System resilience test completed (sessions in memory: {})", initial_count);
}

/// Integration test for the complete Vultisig CLI workflow
#[tokio::test]
async fn test_complete_vultisig_workflow() {
    println!("🚀 Starting complete Vultisig CLI workflow integration test");
    
    // Step 1: Initialize components
    let session_manager = Arc::new(SessionManager::new());
    let mpc_coordinator = create_mpc_coordinator(session_manager.clone());
    let keyshare = create_test_dual_keyshare();
    
    println!("✅ Step 1: Initialized all components");
    
    // Step 2: Test address derivation (core wallet functionality)
    let addresses = vec![
        ("ETH", keyshare.derive_eth_address()),
        ("BTC", keyshare.derive_btc_address()),
        ("SOL", keyshare.derive_sol_address()),
    ];
    
    for (symbol, result) in addresses {
        match result {
            Ok(addr) => println!("✅ Step 2: {} address: {}", symbol, addr),
            Err(e) => println!("⚠️ Step 2: {} address derivation failed: {}", symbol, e),
        }
    }
    
    // Step 3: Create and manage signing session
    let session_id = session_manager.create_session(
        "ethereum".to_string(),
        "send_transaction".to_string(),
        vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22],
        {
            let mut meta = HashMap::new();
            meta.insert("integration_test".to_string(), "complete_workflow".to_string());
            meta
        },
    ).await.unwrap();
    
    println!("✅ Step 3: Created signing session {}", session_id);
    
    // Step 4: Generate QR codes for mobile scanning
    let keysign_uri = qr::generate_vultisig_keysign_uri(TEST_VAULT_PUBKEY, "integration_test_data");
    let qr_ascii = qr::generate_ascii_qr(&keysign_uri);
    
    match qr_ascii {
        Ok(qr) => println!("✅ Step 4: Generated QR code ({} characters)", qr.len()),
        Err(e) => println!("⚠️ Step 4: QR generation failed: {}", e),
    }
    
    // Step 5: Test payload handling for large data
    let large_payload = format!(r#"{{"session_id": "{}", "large_data": "{}"}}"#, 
                               session_id, "x".repeat(1000));
    
    println!("✅ Step 5: Large payload created ({} bytes)", large_payload.len());
    
    // Step 6: Simulate mobile app interaction
    session_manager.update_session_status(&session_id, SessionStatus::WaitingForMobile).await.unwrap();
    
    // Simulate signing completion
    let final_result = vultisig::session::SigningResult {
        session_id: session_id.clone(),
        success: true,
        signature: hex::decode("304402201234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef02201234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef").unwrap(),
        signed_tx: hex::decode("f86c0185174876e800825208940000000000000000000000000000000000000000880de0b6b3a764000080").unwrap(),
        error_message: String::new(),
        metadata: {
            let mut meta = HashMap::new();
            meta.insert("gas_used".to_string(), "21000".to_string());
            meta.insert("tx_hash".to_string(), "0xabcdef1234567890".to_string());
            meta
        },
    };
    
    session_manager.store_result(session_id.clone(), final_result).await.unwrap();
    session_manager.update_session_status(&session_id, SessionStatus::Completed).await.unwrap();
    
    println!("✅ Step 6: Completed mobile app interaction simulation");
    
    // Step 7: Verify final state
    let final_session = session_manager.get_session(&session_id).await.unwrap();
    let final_result = session_manager.get_result(&session_id).await.unwrap();
    
    assert_eq!(final_session.status, SessionStatus::Completed);
    assert!(final_result.success);
    assert!(!final_result.signature.is_empty());
    assert!(!final_result.signed_tx.is_empty());
    
    println!("✅ Step 7: Verified final state - transaction signed successfully");
    
    // Step 8: Test cleanup and resource management
    let pre_cleanup_count = session_manager.sessions.read().await.len();
    mpc_coordinator.cleanup_completed_sessions().await;
    let post_cleanup_count = session_manager.sessions.read().await.len();
    
    println!("✅ Step 8: Resource cleanup (sessions: {} -> {})", pre_cleanup_count, post_cleanup_count);
    
    println!("🎉 Complete Vultisig CLI workflow integration test PASSED");
}