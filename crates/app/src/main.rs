use anyhow::Result;
use clap::{Parser, Subcommand};
use std::fs;
use is_terminal::IsTerminal;
use tokio::net::UnixStream;
use tokio::io::{AsyncWriteExt, AsyncBufReadExt, BufReader};
use serde_json::{json, Value};

use vultisig::{ConfigFile, run_server_with_keyshare, keyshare::VultKeyshare, SigningModeArg};

/// Show addresses for networks based on network parameter (all, specific network, or comma-separated list)
fn show_addresses(keyshare: &VultKeyshare, network: &str) -> Result<()> {
    let all_chains = vec![
        ("BTC", "Bitcoin"),
        ("ETH", "Ethereum"), 
        ("BSC", "BNB Smart Chain"),
        ("MATIC", "Polygon"),
        ("AVAX", "Avalanche"),
        ("ATOM", "Cosmos"),
        ("THOR", "THORChain"),
        ("SOL", "Solana"),
        ("LTC", "Litecoin"),
        ("DOGE", "Dogecoin"),
        ("Optimism", "Optimism"),
        ("Arbitrum", "Arbitrum"),
        ("Base", "Base"),
        ("ADA", "Cardano"),
        ("DOT", "Polkadot"),
        ("XRP", "Ripple"),
        ("TRX", "Tron"),
        ("SUI", "Sui"),
        ("TON", "TON"),
    ];
    
    let chains_to_show = if network.to_lowercase() == "all" {
        all_chains.clone()
    } else {
        // Filter by specific networks (comma-separated)
        let requested: Vec<String> = network.split(',').map(|s| s.trim().to_uppercase()).collect();
        all_chains.into_iter().filter(|(code, _)| {
            requested.iter().any(|req| req.eq_ignore_ascii_case(code))
        }).collect()
    };
    
    if chains_to_show.is_empty() {
        println!("❌ No matching networks found for: {}", network);
        return Ok(());
    }
    
    // Collect supported addresses
    let mut supported_addresses = Vec::new();
    let mut unsupported_chains = Vec::new();
    
    for (chain_code, _chain_name) in chains_to_show {
        match keyshare.derive_address(chain_code) {
            Ok(address) => {
                supported_addresses.push((chain_code, address));
            }
            Err(_) => {
                unsupported_chains.push(chain_code);
            }
        }
    }
    
    // Display supported addresses in clean format
    if !supported_addresses.is_empty() {
        for (chain_code, address) in supported_addresses {
            println!("{}: {}", chain_code, address);
        }
    }
    
    // Show unsupported networks if any were explicitly requested
    if !unsupported_chains.is_empty() && network.to_lowercase() != "all" {
        println!("\n⚠️  Unsupported: {}", unsupported_chains.join(", "));
    }
    
    Ok(())
}

/// Smart keyshare loader that tries passwordless first, then prompts for password with retry
fn load_keyshare_with_smart_password(keyshare_file: &str, provided_password: Option<String>) -> Result<VultKeyshare> {
    // If password was explicitly provided, use it
    if let Some(password) = provided_password {
        println!("🔐 Using provided password...");
        return VultKeyshare::load_from_file(keyshare_file, Some(&password))
            .map_err(|e| anyhow::anyhow!("Failed to load keyshare with provided password: {}", e));
    }
    
    // First, try without password
    println!("🔓 Trying to load keyshare without password...");
    match VultKeyshare::load_from_file(keyshare_file, None) {
        Ok(keyshare) => {
            println!("✅ Keyshare loaded successfully (no password required)");
            return Ok(keyshare);
        }
        Err(e) => {
            println!("🔒 Keyshare appears to be encrypted: {}", e);
        }
    }
    
    // If that failed and we're in an interactive terminal, prompt for password with retry
    if std::io::stdin().is_terminal() {
        const MAX_RETRIES: usize = 3;
        for attempt in 1..=MAX_RETRIES {
            match rpassword::prompt_password(&format!("🔑 Enter keyshare password (attempt {}/{}): ", attempt, MAX_RETRIES)) {
                Ok(password) if !password.is_empty() => {
                    match VultKeyshare::load_from_file(keyshare_file, Some(&password)) {
                        Ok(keyshare) => {
                            println!("✅ Keyshare loaded successfully with password");
                            return Ok(keyshare);
                        }
                        Err(e) => {
                            if attempt < MAX_RETRIES {
                                println!("❌ Incorrect password. Please try again. ({})", e);
                            } else {
                                return Err(anyhow::anyhow!("Failed to load keyshare after {} attempts: {}", MAX_RETRIES, e));
                            }
                        }
                    }
                }
                Ok(_) => {
                    // Empty password, try without password again
                    match VultKeyshare::load_from_file(keyshare_file, None) {
                        Ok(keyshare) => {
                            println!("✅ Keyshare loaded successfully (no password)");
                            return Ok(keyshare);
                        }
                        Err(e) => {
                            if attempt < MAX_RETRIES {
                                println!("❌ Still unable to load keyshare. Please enter the correct password.");
                            } else {
                                return Err(anyhow::anyhow!("Failed to load keyshare: {}", e));
                            }
                        }
                    }
                }
                Err(e) => {
                    return Err(anyhow::anyhow!("Failed to read password: {}", e));
                }
            }
        }
    }
    
    Err(anyhow::anyhow!("Keyshare is encrypted but no password provided and not running interactively. Use --password option."))
}

/// Find the first .vult file in the keyshares directory
fn find_first_vault_file() -> Result<String> {
    let keyshares_dir = "./keyshares";
    
    if !std::path::Path::new(keyshares_dir).exists() {
        return Err(anyhow::anyhow!("Keyshares directory not found: {}\nPlease create the directory and add your .vult keyshare files.", keyshares_dir));
    }
    
    let entries = fs::read_dir(keyshares_dir)?;
    let mut vault_files = Vec::new();
    
    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        if let Some(extension) = path.extension() {
            if extension == "vult" {
                if let Some(filename) = path.file_name() {
                    vault_files.push(filename.to_string_lossy().to_string());
                }
            }
        }
    }
    
    if vault_files.is_empty() {
        return Err(anyhow::anyhow!("No .vult files found in {}\nPlease copy your keyshare files to this directory.", keyshares_dir));
    }
    
    // Sort to ensure consistent selection of "first" file
    vault_files.sort();
    println!("📁 Found {} keyshare file(s) in {}", vault_files.len(), keyshares_dir);
    println!("🔑 Using keyshare: {}", vault_files[0]);
    
    // Return full path
    Ok(format!("{}/{}", keyshares_dir, vault_files[0]))
}

#[derive(Parser)]
#[command(author, version, about = "Vultisig - Local MPC signing for multi-blockchain wallets", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the MPC signing daemon
    Run {
        /// Specific .vult keyshare file
        #[arg(long)]
        vault: Option<String>,
        
        /// Password for encrypted keyshares
        #[arg(long)]
        password: Option<String>,
        
        /// Custom config file
        #[arg(long)]
        config: Option<String>,
        
        /// Signing mode (local or relay)
        #[arg(long, default_value = "relay")]
        mode: SigningModeArg,
        
        /// Session ID for relay mode
        #[arg(long)]
        session_id: Option<String>,
        
        /// Network for signing session
        #[arg(long)]
        network: Option<String>,
        
        /// Message type for signing session
        #[arg(long)]
        message_type: Option<String>,
        
        /// Relay server URL
        #[arg(long)]
        relay_server: Option<String>,
        
        /// Session timeout in seconds
        #[arg(long)]
        timeout: Option<u64>,
        
        /// Payload file path
        #[arg(long)]
        payload_file: Option<String>,
    },
    
    /// Show wallet addresses for supported networks
    Address {
        /// Specific .vult keyshare file
        #[arg(long)]
        vault: Option<String>,
        
        /// Password for encrypted keyshares
        #[arg(long)]
        password: Option<String>,
        
        /// Networks to show (all, or specific like btc,eth,sol)
        #[arg(long, default_value = "all")]
        network: String,
    },
    
    /// List available keyshare files
    List,
    
    /// Check daemon status
    Status,
    
    /// Initialize keyshares directory and config
    Init,
    
    /// Gracefully shut down the daemon
    Quit,
    
    /// Sign a transaction
    Sign {
        /// Blockchain network
        #[arg(long)]
        network: String,
        
        /// Signing mode (local or relay)
        #[arg(long, default_value = "relay")]
        mode: String,
        
        /// Session ID for relay mode
        #[arg(long)]
        session_id: Option<String>,
        
        /// Payload file path
        #[arg(long)]
        payload_file: Option<String>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    
    // Initialize logging - for run command, ensure we show INFO level logs by default
    let env_filter = match cli.command {
        Commands::Run { .. } => {
            // For run command, default to INFO level to show daemon logs
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"))
        }
        _ => {
            // For other commands, use default or WARN level to keep output clean
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn"))
        }
    };
    
    tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .init();
    
    match cli.command {
        Commands::Run { vault, password, config, mode, session_id, network, message_type, relay_server, timeout, payload_file } => {
            run_daemon(vault, password, config, mode, session_id, network, message_type, relay_server, timeout, payload_file).await
        }
        Commands::Address { vault, password, network } => {
            handle_address(vault, password, &network).await
        }
        Commands::List => {
            handle_list()
        }
        Commands::Status => {
            handle_status().await
        }
        Commands::Init => {
            handle_init()
        }
        Commands::Sign { network, mode, session_id, payload_file } => {
            handle_sign(network, mode, session_id, payload_file).await
        }
        Commands::Quit => {
            handle_quit().await
        }
    }
}

async fn run_daemon(
    vault: Option<String>,
    password: Option<String>,
    config: Option<String>,
    mode: SigningModeArg,
    session_id: Option<String>,
    network: Option<String>,
    message_type: Option<String>,
    relay_server: Option<String>,
    timeout: Option<u64>,
    payload_file: Option<String>,
) -> Result<()> {
    println!("🚀 Starting unified Vultisig daemon...");
    
    // Load configuration
    let config_file = if let Some(config_path) = config {
        let content = fs::read_to_string(&config_path)?;
        serde_yaml::from_str(&content)?
    } else {
        ConfigFile::default()
    };
    
    // Determine keyshare file
    let keyshare_file = if let Some(vault_file) = vault {
        if vault_file.starts_with('/') {
            vault_file
        } else if vault_file.starts_with("keyshares/") || vault_file.starts_with("./keyshares/") {
            vault_file
        } else {
            format!("./keyshares/{}", vault_file)
        }
    } else {
        find_first_vault_file()?
    };
    
    // Load keyshare with smart password handling
    let keyshare = load_keyshare_with_smart_password(&keyshare_file, password.clone())?;
    
    // Show successful load info
    println!("\n🎯 Vault: {}", keyshare.vault_name);
    println!("🔑 ECDSA Public Key: {}", keyshare.public_key_ecdsa());
    println!("🔑 EdDSA Public Key: {}", keyshare.public_key_eddsa());
    
    println!("\n🚀 Starting daemon...");
    println!("📋 The daemon is now running. All logs will be printed here. To use it, open a new terminal and use your CLI with vultisig commands");
    println!("💡 Use Ctrl+C to stop the daemon\n");
    
    run_server_with_keyshare(keyshare, config_file, mode.into()).await
}

async fn handle_address(vault: Option<String>, password: Option<String>, network: &str) -> Result<()> {
    // Try to connect to the running daemon first
    match try_daemon_request(network).await {
        Ok(()) => return Ok(()),
        Err(_) => {
            // Daemon not running - inform user to start daemon instead of falling back
            println!("❌ Daemon is not running");
            println!("💡 The 'address' command requires a running daemon with your keyshare already loaded.");
            println!("💡 Start the daemon first with: vultisig run --vault your-vault.vult --password yourpassword");
            println!("💡 Then run: vultisig address");
            return Err(anyhow::anyhow!("Daemon not running. Start daemon first to avoid re-entering passwords."));
        }
    }
}

fn handle_list() -> Result<()> {
    let keyshares_dir = "./keyshares";
    
    if !std::path::Path::new(keyshares_dir).exists() {
        println!("❌ Keyshares directory not found: {}", keyshares_dir);
        println!("💡 Run 'vultisig init' to create the directory");
        return Ok(());
    }
    
    let entries = fs::read_dir(keyshares_dir)?;
    let mut vault_files = Vec::new();
    
    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        if let Some(extension) = path.extension() {
            if extension == "vult" {
                if let Some(filename) = path.file_name() {
                    vault_files.push(filename.to_string_lossy().to_string());
                }
            }
        }
    }
    
    if vault_files.is_empty() {
        println!("📁 No .vult files found in {}", keyshares_dir);
        println!("💡 Copy your keyshare files to this directory");
    } else {
        vault_files.sort();
        println!("📁 Found {} keyshare file(s) in {}:", vault_files.len(), keyshares_dir);
        for file in vault_files {
            println!("  📄 {}", file);
        }
    }
    
    Ok(())
}

async fn handle_status() -> Result<()> {
    println!("🔍 Checking daemon status...");
    
    // Try to connect to WebSocket
    match tokio_tungstenite::connect_async("ws://localhost:8787/ws").await {
        Ok(_) => {
            println!("✅ Daemon is running and WebSocket is accessible on port 8787");
        }
        Err(_) => {
            println!("❌ Daemon is not running or WebSocket is not accessible");
        }
    }
    
    // Try to connect to HTTP relay
    match reqwest::get("http://localhost:18080/health").await {
        Ok(response) if response.status().is_success() => {
            println!("✅ Relay server is accessible on port 18080");
        }
        Ok(_) | Err(_) => {
            println!("❌ Relay server is not accessible on port 18080");
        }
    }
    
    Ok(())
}

async fn handle_sign(
    network: String,
    mode: String,
    session_id: Option<String>,
    payload_file: Option<String>,
) -> Result<()> {
    println!("🔐 Starting {} transaction signing in {} mode...", network.to_uppercase(), mode);
    
    // Try to connect to the running daemon first
    match try_daemon_sign(&network, &mode, session_id.as_deref(), payload_file.as_deref()).await {
        Ok(()) => return Ok(()),
        Err(_) => {
            // Daemon not running - inform user to start daemon instead of falling back
            println!("❌ Daemon is not running");
            println!("💡 The 'sign' command requires a running daemon with your keyshare already loaded.");
            println!("💡 Start the daemon first with: vultisig run --vault your-vault.vult --password yourpassword");
            println!("💡 Then run: vultisig sign --network {} --payload-file your-transaction.json", network.to_uppercase());
            return Err(anyhow::anyhow!("Daemon not running. Start daemon first to avoid re-entering passwords."));
        }
    }
}

fn handle_init() -> Result<()> {
    let keyshares_dir = "./keyshares";
    
    if std::path::Path::new(keyshares_dir).exists() {
        println!("✅ Keyshares directory already exists: {}", keyshares_dir);
    } else {
        fs::create_dir_all(keyshares_dir)?;
        println!("✅ Created keyshares directory: {}", keyshares_dir);
    }
    
    let config_file = "./vultisig-config.yaml";
    if !std::path::Path::new(config_file).exists() {
        let default_config = ConfigFile::default();
        let config_content = serde_yaml::to_string(&default_config)?;
        fs::write(config_file, config_content)?;
        println!("✅ Created default config file: {}", config_file);
    } else {
        println!("✅ Config file already exists: {}", config_file);
    }
    
    println!("\n📋 Next steps:");
    println!("1. Copy your .vult keyshare files to {}", keyshares_dir);
    println!("2. Start the daemon with: vultisig run");
    println!("3. View addresses with: vultisig addr");
    
    Ok(())
}

/// Try to get address from running daemon via Unix socket
async fn try_daemon_request(network: &str) -> Result<()> {
    let socket_path = "/tmp/vultisig.sock";
    
    // Try to connect to daemon
    let stream = UnixStream::connect(socket_path).await
        .map_err(|_| anyhow::anyhow!("Could not connect to daemon"))?;
    
    // Split stream for reading and writing
    let (reader, mut writer) = stream.into_split();
    let mut buf_reader = BufReader::new(reader);
    
    if network.to_lowercase() == "all" {
        // Request all addresses with public keys
        let request = json!({
            "id": 1,
            "method": "get_addresses_with_pubkeys",
            "params": {}
        });
        
        let request_str = format!("{}\n", request.to_string());
        writer.write_all(request_str.as_bytes()).await?;
        
        // Read response
        let mut response_line = String::new();
        buf_reader.read_line(&mut response_line).await?;
        
        let response: Value = serde_json::from_str(&response_line)?;
        
        if let Some(result) = response.get("result") {
            if let Some(data) = result.as_object() {
                for (network_name, info) in data {
                    if let Some(info_array) = info.as_array() {
                        if info_array.len() == 2 {
                            if let (Some(pubkey), Some(address)) = (info_array[0].as_str(), info_array[1].as_str()) {
                                println!("{}: {}", network_name, pubkey);
                                println!("{}", address);
                                println!(); // Empty line between networks
                            }
                        }
                    }
                }
            }
        } else if let Some(error) = response.get("error") {
            return Err(anyhow::anyhow!("Daemon error: {}", error));
        }
    } else {
        // Handle comma-separated networks using single persistent connection
        let networks: Vec<&str> = network.split(',').map(|s| s.trim()).collect();
        println!("📍 Network Addresses:");
        
        for (i, net) in networks.iter().enumerate() {
            let request = json!({
                "id": i + 1,
                "method": "get_address",
                "params": {
                    "network": net.to_lowercase()
                }
            });
            
            let request_str = format!("{}\n", request.to_string());
            writer.write_all(request_str.as_bytes()).await?;
            
            // Read response
            let mut response_line = String::new();
            buf_reader.read_line(&mut response_line).await?;
            
            let response: Value = serde_json::from_str(&response_line)?;
            
            if let Some(result) = response.get("result") {
                if let Some(address) = result.get("address").and_then(|a| a.as_str()) {
                    println!("{}: {}", net.to_uppercase(), address);
                }
            } else if let Some(error) = response.get("error") {
                println!("{}: ❌ {}", net.to_uppercase(), error);
            }
        }
    }
    
    Ok(())
}

/// Try to sign transaction via daemon Unix socket
async fn try_daemon_sign(
    network: &str, 
    mode: &str,
    session_id: Option<&str>,
    payload_file: Option<&str>
) -> Result<()> {
    let socket_path = "/tmp/vultisig.sock";
    
    // Load transaction payload
    let payload_content = if let Some(file_path) = payload_file {
        fs::read_to_string(&file_path)
            .map_err(|e| anyhow::anyhow!("Failed to read payload file '{}': {}", file_path, e))?
    } else {
        // If no file provided, read from stdin
        use std::io::Read;
        let mut buffer = String::new();
        std::io::stdin().read_to_string(&mut buffer)?;
        buffer
    };
    
    if payload_content.trim().is_empty() {
        return Err(anyhow::anyhow!("No transaction payload provided. Use --payload-file or pipe JSON to stdin"));
    }
    
    // Parse payload as JSON
    let payload_json: serde_json::Value = serde_json::from_str(&payload_content)
        .map_err(|e| anyhow::anyhow!("Invalid JSON payload: {}", e))?;
    
    println!("📦 Transaction payload loaded: {}", serde_json::to_string_pretty(&payload_json).unwrap_or_else(|_| payload_content));
    
    // Try to connect to daemon
    let stream = UnixStream::connect(socket_path).await
        .map_err(|_| anyhow::anyhow!("Could not connect to daemon"))?;
    
    let (reader, mut writer) = stream.into_split();
    let mut buf_reader = BufReader::new(reader);
    
    // Generate session ID if not provided
    use uuid::Uuid;
    let session_id = session_id.map(|s| s.to_string())
        .unwrap_or_else(|| format!("cli-{}", Uuid::new_v4().to_string()[0..8].to_string()));
    
    let request = json!({
        "id": 1,
        "method": "sign",
        "params": {
            "network": network.to_lowercase(),
            "mode": mode.to_lowercase(),
            "session_id": session_id,
            "payload": payload_json,
            "broadcast": false
        }
    });
    
    println!("🚀 Starting signing session: {}", session_id);
    println!("📡 Mode: {}", mode.to_uppercase());
    println!("🔗 Sending transaction to daemon for signing...");
    
    let request_str = format!("{}\n", request.to_string());
    writer.write_all(request_str.as_bytes()).await?;
    
    // Read response
    let mut response_line = String::new();
    buf_reader.read_line(&mut response_line).await?;
    
    let response: Value = serde_json::from_str(&response_line)?;
    
    if let Some(result) = response.get("result") {
        println!("✅ Transaction signing initiated successfully!");
        println!("📋 Session ID: {}", session_id);
        
        if let Some(signature) = result.get("signature") {
            println!("🔐 Signature: {}", signature);
        }
        
        if let Some(tx_hash) = result.get("transaction_hash") {
            println!("📄 Transaction Hash: {}", tx_hash);
        }
        
        println!("📱 Complete the signing process on your mobile device");
        
    } else if let Some(error) = response.get("error") {
        return Err(anyhow::anyhow!("Daemon signing error: {}", error));
    }
    
    Ok(())
}

/// Send quit command to daemon via Unix socket  
async fn handle_quit() -> Result<()> {
    println!("🛑 Sending shutdown signal to daemon...");
    
    let socket_path = "/tmp/vultisig.sock";
    
    match UnixStream::connect(socket_path).await {
        Ok(stream) => {
            let (_, mut writer) = stream.into_split();
            
            let request = json!({
                "id": 1,
                "method": "shutdown",
                "params": {}
            });
            
            let request_str = format!("{}\n", request.to_string());
            writer.write_all(request_str.as_bytes()).await?;
            
            println!("✅ Shutdown signal sent successfully");
            
            // Give daemon time to shutdown gracefully
            tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
            
            // Verify daemon is no longer running
            match UnixStream::connect(socket_path).await {
                Ok(_) => {
                    println!("⚠️  Daemon may still be running");
                }
                Err(_) => {
                    println!("✅ Daemon has shut down");
                }
            }
        }
        Err(_) => {
            println!("❌ Could not connect to daemon - it may not be running");
            return Err(anyhow::anyhow!("Daemon not accessible"));
        }
    }
    
    Ok(())
}

// Helper trait for checking if stdin is a TTY
trait IsAtty {
    fn is_atty(self) -> bool;
}

impl IsAtty for std::io::Stdin {
    fn is_atty(self) -> bool {
        use is_terminal::IsTerminal;
        std::io::stdin().is_terminal()
    }
}