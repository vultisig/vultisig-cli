use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::time::Duration;
use tracing::{error, info};



// Make prost available globally for generated protobuf code
pub extern crate prost;

pub mod engines;
pub mod tss;
pub mod session;
pub mod network;
pub mod qr;
pub mod websocket;
pub mod keyshare;
pub mod mpc_coordinator;
pub mod broadcaster;
pub mod relay_client;
pub mod relay_server;
pub mod keysign_message;
pub mod dense_qr;
pub mod local_discovery;
pub mod wallet_core_ffi;
pub mod wallet_core;
pub mod commondata;
pub mod signing;

#[cfg(test)]
pub mod tests;


#[derive(Debug, Clone)]
pub enum SigningMode {
    Local,
    Relay,
}

// For CLI usage - separate enum with ValueEnum
#[derive(Debug, Clone, clap::ValueEnum)]
pub enum SigningModeArg {
    Local,
    Relay,
}

impl From<SigningModeArg> for SigningMode {
    fn from(arg: SigningModeArg) -> Self {
        match arg {
            SigningModeArg::Local => SigningMode::Local,
            SigningModeArg::Relay => SigningMode::Relay,
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ConfigFile {
    pub websocket_port: u16,
    pub http_port: u16,
    pub enable_mobile_signing: bool,
    pub use_vultisig_relay: bool,
    pub enable_local_relay: bool,
}

impl Default for ConfigFile {
    fn default() -> Self {
        ConfigFile {
            websocket_port: 8787,
            http_port: 18080,
            enable_mobile_signing: true,
            use_vultisig_relay: false,
            enable_local_relay: true,
        }
    }
}

pub const DEFAULT_SOCKET_PATH: &str = "/tmp/vultisig.sock";

/// Find an available port starting from the given port
async fn find_available_port(start_port: u16) -> Result<u16> {
    use tokio::net::TcpListener;
    
    for port in start_port..(start_port + 100) {
        if let Ok(listener) = TcpListener::bind(("127.0.0.1", port)).await {
            drop(listener);
            return Ok(port);
        }
    }
    
    Err(anyhow!("No available port found in range {}-{}", start_port, start_port + 99))
}

/// Main server function that starts all services
pub async fn run_server(
    keyshare_file: String,
    password: Option<String>,
    mut config: ConfigFile,
    signing_mode: SigningMode,
) -> Result<()> {
    info!("Starting Vultisig daemon...");
    
    // Find available WebSocket port dynamically (HTTP port must remain 18080 per spec)
    let websocket_port = find_available_port(config.websocket_port).await
        .with_context(|| format!("Failed to find available WebSocket port starting from {}", config.websocket_port))?;
    
    // Update config with the found WebSocket port (keep HTTP port as-is - 18080 is required by spec)
    config.websocket_port = websocket_port;
    
    info!("Selected WebSocket port: {}, HTTP port: {} (required by protocol)", websocket_port, config.http_port);
    
    // Load keyshare
    let keyshare = keyshare::VultKeyshare::load_from_file(&keyshare_file, password.as_deref())
        .with_context(|| format!("Failed to load keyshare from {}", keyshare_file))?;
    
    info!("Loaded keyshare for vault: {}", keyshare.vault_name);
    info!("Public key ECDSA: {}", keyshare.public_key_ecdsa());
    info!("Public key EdDSA: {}", keyshare.public_key_eddsa());
    
    // Create session manager
    let session_manager = Arc::new(session::SessionManager::new());
    
    // Create MPC coordinator
    let mut mpc_coordinator = mpc_coordinator::MpcCoordinator::new(session_manager.clone());
    mpc_coordinator.set_keyshare(keyshare);
    let mpc_coordinator = Arc::new(mpc_coordinator);
    
    // Start Unix socket server
    let socket_path = DEFAULT_SOCKET_PATH;
    if std::path::Path::new(socket_path).exists() {
        fs::remove_file(socket_path).with_context(|| "Failed to remove existing socket")?;
    }
    
    let listener = UnixListener::bind(socket_path)
        .with_context(|| format!("Failed to bind Unix socket at {}", socket_path))?;
    
    info!("Unix socket server listening at {}", socket_path);
    
    // Set socket permissions to be readable/writable by user and group
    let metadata = fs::metadata(socket_path)?;
    let mut permissions = metadata.permissions();
    permissions.set_mode(0o660);
    fs::set_permissions(socket_path, permissions)?;
    
    // Start WebSocket server for mobile communication
    let ws_session_manager = session_manager.clone();
    let ws_mpc_coordinator = mpc_coordinator.clone();
    let ws_port = config.websocket_port;
    
    tokio::spawn(async move {
        if let Err(e) = websocket::start_websocket_server(
            ws_port, 
            ws_session_manager, 
            ws_mpc_coordinator
        ).await {
            error!("WebSocket server error: {}", e);
        }
    });
    
    // Start unified relay server with discovery (matches Go-TS spec)
    if config.enable_local_relay {
        let relay_port = config.http_port;
        let relay_session_manager = session_manager.clone();
        let relay_websocket_port = config.websocket_port;
        let enable_mobile_signing = config.enable_mobile_signing;
        let _relay_handle = tokio::spawn(async move {
            let relay_server = if enable_mobile_signing {
                // Create relay server with discovery support
                relay_server::create_relay_server_with_discovery(
                    relay_port, 
                    relay_session_manager, 
                    relay_websocket_port
                )
            } else {
                // Create basic relay server without discovery
                relay_server::create_relay_server(relay_port)
            };
            
            if let Err(e) = relay_server.start().await {
                error!("Relay server error: {}", e);
            }
        });
        info!("Unified relay server (with discovery): http://localhost:{}", config.http_port);
    }

    // Start mDNS advertisement service (separate from HTTP server)
    if config.enable_mobile_signing {
        let discovery_session_manager = session_manager.clone();
        tokio::spawn(async move {
            if let Err(e) = local_discovery::advertise_service("Vultisig-Daemon".to_string()).await {
                error!("mDNS advertisement error: {}", e);
            }
        });
    }
    
    info!("All services started successfully");
    info!("WebSocket server: ws://localhost:{}", ws_port);
    info!("Unix socket: {}", socket_path);
    info!("Press Ctrl+C to shutdown gracefully");
    
    // Handle Unix socket connections with graceful shutdown
    let socket_path_cleanup = socket_path.to_string();
    tokio::select! {
        // Main server loop
        result = async {
            loop {
                match listener.accept().await {
                    Ok((stream, _)) => {
                        let session_manager_clone = session_manager.clone();
                        let mpc_coordinator_clone = mpc_coordinator.clone();
                        tokio::spawn(async move {
                            if let Err(e) = handle_unix_connection(
                                stream, 
                                session_manager_clone, 
                                mpc_coordinator_clone
                            ).await {
                                error!("Error handling Unix socket connection: {}", e);
                            }
                        });
                    }
                    Err(e) => {
                        error!("Failed to accept Unix socket connection: {}", e);
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                }
            }
        } => {
            // This should never be reached since the loop is infinite
            Ok(())
        },
        
        // Signal handling for graceful shutdown
        result = wait_for_shutdown_signal() => {
            info!("🛑 Received shutdown signal ({}), shutting down gracefully...", result);
            
            // Clean up Unix socket file
            if std::path::Path::new(&socket_path_cleanup).exists() {
                if let Err(e) = fs::remove_file(&socket_path_cleanup) {
                    error!("Failed to remove Unix socket file: {}", e);
                } else {
                    info!("🧹 Cleaned up Unix socket: {}", socket_path_cleanup);
                }
            }
            
            // Clean up any active sessions
            info!("🔄 Cleaning up active MPC sessions...");
            mpc_coordinator.cleanup_completed_sessions().await;
            session_manager.cleanup_expired_sessions().await;
            
            info!("✅ Graceful shutdown complete");
            Ok(())
        }
    }
}

/// Main server function that starts all services with pre-loaded keyshare
pub async fn run_server_with_keyshare(
    keyshare: keyshare::VultKeyshare,
    mut config: ConfigFile,
    _signing_mode: SigningMode,
) -> Result<()> {
    info!("Starting Vultisig daemon...");
    
    // Find available WebSocket port dynamically (HTTP port must remain 18080 per spec)
    let websocket_port = find_available_port(config.websocket_port).await
        .with_context(|| format!("Failed to find available WebSocket port starting from {}", config.websocket_port))?;
    
    // Update config with the found WebSocket port (keep HTTP port as-is - 18080 is required by spec)
    config.websocket_port = websocket_port;
    
    info!("Selected WebSocket port: {}, HTTP port: {} (required by protocol)", websocket_port, config.http_port);
    
    // Use pre-loaded keyshare (no need to load again)
    info!("Loaded keyshare for vault: {}", keyshare.vault_name);
    info!("Public key ECDSA: {}", keyshare.public_key_ecdsa());
    info!("Public key EdDSA: {}", keyshare.public_key_eddsa());
    
    // Create session manager
    let session_manager = Arc::new(session::SessionManager::new());
    
    // Create MPC coordinator
    let mut mpc_coordinator = mpc_coordinator::MpcCoordinator::new(session_manager.clone());
    mpc_coordinator.set_keyshare(keyshare);
    let mpc_coordinator = Arc::new(mpc_coordinator);
    
    // Start Unix socket server
    let socket_path = DEFAULT_SOCKET_PATH;
    if std::path::Path::new(socket_path).exists() {
        fs::remove_file(socket_path).with_context(|| "Failed to remove existing socket")?;
    }
    
    let listener = UnixListener::bind(socket_path)
        .with_context(|| format!("Failed to bind Unix socket at {}", socket_path))?;
    
    info!("Unix socket server listening at {}", socket_path);
    
    // Set socket permissions to be readable/writable by user and group
    let metadata = fs::metadata(socket_path)?;
    let mut permissions = metadata.permissions();
    permissions.set_mode(0o660);
    fs::set_permissions(socket_path, permissions)?;
    
    // Start WebSocket server for mobile communication
    let ws_session_manager = session_manager.clone();
    let ws_mpc_coordinator = mpc_coordinator.clone();
    let ws_port = config.websocket_port;
    
    tokio::spawn(async move {
        if let Err(e) = websocket::start_websocket_server(
            ws_port, 
            ws_session_manager, 
            ws_mpc_coordinator
        ).await {
            error!("WebSocket server error: {}", e);
        }
    });
    
    // Start unified relay server with discovery (matches Go-TS spec)
    if config.enable_local_relay {
        let relay_port = config.http_port;
        let relay_session_manager = session_manager.clone();
        let relay_websocket_port = config.websocket_port;
        let enable_mobile_signing = config.enable_mobile_signing;
        let _relay_handle = tokio::spawn(async move {
            let relay_server = if enable_mobile_signing {
                // Create relay server with discovery support
                relay_server::create_relay_server_with_discovery(
                    relay_port, 
                    relay_session_manager, 
                    relay_websocket_port
                )
            } else {
                // Create basic relay server without discovery
                relay_server::create_relay_server(relay_port)
            };
            
            if let Err(e) = relay_server.start().await {
                error!("Relay server error: {}", e);
            }
        });
        info!("Unified relay server (with discovery): http://localhost:{}", config.http_port);
    }

    // Start mDNS advertisement service (separate from HTTP server)
    if config.enable_mobile_signing {
        let _discovery_session_manager = session_manager.clone();
        tokio::spawn(async move {
            if let Err(e) = local_discovery::advertise_service("Vultisig-Daemon".to_string()).await {
                error!("mDNS advertisement error: {}", e);
            }
        });
    }
    
    info!("All services started successfully");
    info!("WebSocket server: ws://localhost:{}", ws_port);
    info!("Unix socket: {}", socket_path);
    info!("Press Ctrl+C to shutdown gracefully");
    
    // Handle Unix socket connections with graceful shutdown
    let socket_path_cleanup = socket_path.to_string();
    tokio::select! {
        // Main server loop
        _result = async {
            loop {
                match listener.accept().await {
                    Ok((stream, _)) => {
                        let session_manager_clone = session_manager.clone();
                        let mpc_coordinator_clone = mpc_coordinator.clone();
                        tokio::spawn(async move {
                            if let Err(e) = handle_unix_connection(
                                stream, 
                                session_manager_clone, 
                                mpc_coordinator_clone
                            ).await {
                                error!("Error handling Unix socket connection: {}", e);
                            }
                        });
                    }
                    Err(e) => {
                        error!("Failed to accept Unix socket connection: {}", e);
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                }
            }
        } => {
            // This should never be reached since the loop is infinite
            Ok(())
        },
        
        // Signal handling for graceful shutdown
        result = wait_for_shutdown_signal() => {
            info!("🛑 Received shutdown signal ({}), shutting down gracefully...", result);
            
            // Clean up Unix socket file
            if std::path::Path::new(&socket_path_cleanup).exists() {
                if let Err(e) = fs::remove_file(&socket_path_cleanup) {
                    error!("Failed to remove Unix socket file: {}", e);
                } else {
                    info!("🧹 Cleaned up Unix socket: {}", socket_path_cleanup);
                }
            }
            
            // Clean up any active sessions
            info!("🔄 Cleaning up active MPC sessions...");
            mpc_coordinator.cleanup_completed_sessions().await;
            session_manager.cleanup_expired_sessions().await;
            
            info!("✅ Graceful shutdown complete");
            Ok(())
        }
    }
}

/// Wait for shutdown signals (SIGINT/Ctrl-C or SIGTERM)
async fn wait_for_shutdown_signal() -> &'static str {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        
        let mut sigint = signal(SignalKind::interrupt()).expect("Failed to create SIGINT handler");
        let mut sigterm = signal(SignalKind::terminate()).expect("Failed to create SIGTERM handler");
        
        tokio::select! {
            _ = sigint.recv() => "SIGINT/Ctrl-C",
            _ = sigterm.recv() => "SIGTERM",
        }
    }
    
    #[cfg(not(unix))]
    {
        // On non-Unix systems, only handle Ctrl-C
        tokio::signal::ctrl_c().await.expect("Failed to listen for Ctrl-C");
        "Ctrl-C"
    }
}

async fn handle_unix_connection(
    stream: UnixStream,
    session_manager: Arc<session::SessionManager>,
    mpc_coordinator: Arc<mpc_coordinator::MpcCoordinator>,
) -> Result<()> {
    let (reader, writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let mut writer = writer;
    
    // Keep connection alive and process multiple requests
    loop {
        let mut line = String::new();
        
        match reader.read_line(&mut line).await {
            Ok(0) => {
                // EOF - client disconnected gracefully
                tracing::debug!("Unix socket client disconnected");
                break;
            }
            Ok(_) => {
                let request = line.trim();
                if request.is_empty() {
                    continue; // Skip empty lines
                }
                
                tracing::debug!("Processing Unix socket request: {}", request);
                
                let response = network::handle_json_rpc_request(
                    request,
                    session_manager.clone(),
                    mpc_coordinator.clone()
                ).await;
                
                // Send response back to client
                if let Err(e) = writer.write_all(response.as_bytes()).await {
                    tracing::error!("Failed to write response to Unix socket: {}", e);
                    break;
                }
                if let Err(e) = writer.write_all(b"\n").await {
                    tracing::error!("Failed to write newline to Unix socket: {}", e);
                    break;
                }
                if let Err(e) = writer.flush().await {
                    tracing::error!("Failed to flush Unix socket: {}", e);
                    break;
                }
                
                tracing::debug!("Sent response to Unix socket client");
            }
            Err(e) => {
                tracing::error!("Error reading from Unix socket: {}", e);
                break;
            }
        }
    }
    
    tracing::debug!("Unix socket connection closed");
    Ok(())
}