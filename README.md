# Vultisig CLI

A Rust-based command-line tool that provides MPC (Multi-Party Computation) signing capabilities for multi-blockchain wallets. The CLI wraps TrustWallet's wallet-core library and advanced MPC signing engines to enable secure 2-of-2 threshold signatures with mobile app co-signing support.

## Architecture

Vultisig CLI consists of several key components:

- **Rust CLI Binary (`vultisig`)**: Main command-line interface and daemon
- **TrustWallet Core Integration**: Blockchain address derivation and transaction handling for 6 supported networks
- **MPC Engines**: 
  - DKLS23 for ECDSA signatures (Bitcoin, Ethereum, etc.)
  - Multi-party Schnorr for EdDSA signatures (Solana, etc.)
- **TypeScript Signer Packages**: Easy integration libraries for web applications
- **Mobile App Integration**: Secure co-signing via WebSocket connections

The system enables developers to:
1. Load a keyshare file (`.vult`) containing their MPC key material
2. Start a daemon that can derive addresses and coordinate signing sessions
3. Integrate with applications via TypeScript libraries or direct CLI commands
4. Co-sign transactions with the Vultisig mobile app holding the other keyshare

## Quick Start

```bash
# Build the project
./build.sh

# Initialize keyshares directory
vultisig init

# Copy your keyshare files to ./keyshares/
cp your-vault.vult ./keyshares/

# Terminal 1: Start the daemon (loads keyshare once with password)
vultisig run --vault your-vault.vult --password yourpassword

# Terminal 2: Interact with the daemon (no password needed)
vultisig status                           # Check daemon is running
vultisig address                          # View all wallet addresses
vultisig address --network btc,eth,sol    # View specific networks
vultisig sign --network ETH --payload-file tx.json  # Sign transactions

# Gracefully shutdown when done
vultisig quit
```

## How It Works: 2-of-2 MPC Signing

Vultisig implements **2-of-2 threshold signatures** where two keyshares are required to sign any transaction:

1. **Your Keyshare**: Stored in a `.vult` file on your computer
2. **Mobile Keyshare**: Stored securely in the Vultisig mobile app

### Prerequisites
- A `.vult` keyshare file from your Vultisig vault creation
- Vultisig mobile app installed with the corresponding keyshare
- Both devices on the same network (for local mode) or internet access (for relay mode)

### Workflow Overview

#### Step 1: Start the Daemon
The CLI daemon loads your keyshare and starts listening for signing requests:
```bash
# Start with specific vault and password
vultisig run --vault TestVault.vult --password mypassword

# Or auto-discover first keyshare (will prompt for password if needed)
vultisig run
```

The daemon will:
- 🔓 Load and decrypt your keyshare
- 📍 Derive and display addresses for all supported networks
- 🚀 Start WebSocket server (port 8787) for mobile app connections
- 🔄 Start relay server (port 18080) for MPC message coordination

#### Step 2: Initiate Signing
Signing can be triggered in multiple ways:

**Via CLI Commands (uses daemon's loaded keyshare):**
```bash
# Check daemon status
vultisig status

# View addresses for all networks (no password needed)
# Shows public keys and addresses for all supported networks
vultisig address

# View specific network addresses (shows addresses only)
vultisig address --network btc,eth,sol

# Sign a transaction (no password needed)
vultisig sign --network ETH --payload-file transaction.json

# Gracefully shutdown daemon
vultisig quit
```

**Via TypeScript Integration:**
```typescript
import { VultisigSigner } from "vultisig-eth-signer";

const signer = new VultisigSigner(provider);
const tx = await signer.sendTransaction({
  to: "0x...",
  value: ethers.parseEther("0.1")
});
```

#### Step 3: Mobile App Co-signing
When a signing request is initiated:
1. The CLI daemon coordinates the MPC protocol
2. Your mobile app receives a signing notification
3. You approve the transaction on your mobile device
4. Both keyshares participate in the MPC signing ceremony
5. The final signature is generated and the transaction is ready for broadcast

## Commands Reference

### `vultisig run` - Start Daemon
Start the MPC signing daemon in the background.

**Options:**
- `--vault <FILE>` - Specific `.vult` keyshare file (auto-discovers if omitted)
- `--password <PASS>` - Password for encrypted keyshares (prompts if omitted)
- `--config <FILE>` - Custom config file (uses default if omitted)
- `--mode <MODE>` - Signing mode: `local` (default) or `relay`

**Examples:**
```bash
vultisig run                                    # Auto-discover keyshare
vultisig run --vault my-wallet.vult             # Specific keyshare
vultisig run --vault my-wallet.vult --password secret  # With password
vultisig run --mode relay                       # Use relay mode
```

### `vultisig address` - View Addresses
Show wallet addresses and public keys for supported networks. Requires a running daemon with loaded keyshare.

**Options:**
- `--network <NETWORKS>` - Networks to show: `all` (default) or comma-separated list

**Output Format:**
- **All networks**: Shows public key and address for each supported network
- **Specific networks**: Shows only addresses for requested networks

**Examples:**
```bash
vultisig address                           # All networks (shows pubkey + address)
vultisig address --network btc,eth,sol     # Bitcoin, Ethereum, Solana only
```

**Sample Output:**
```
ETH: 03ac0f333fc5d22f929e013be80988f57a56837db64d968c126ca4c943984744fd
0x8c4E1C2D3b9F88bBa6162F6Bd8dB05840Ca24F8c

BTC: 03ac0f333fc5d22f929e013be80988f57a56837db64d968c126ca4c943984744fd
bc1qsef7rshf0jwm53rnkttpry5rpveqcd6dyj6pn9
```

### `vultisig status` - Check Daemon
Check if the daemon is running and accessible.

**Output:**
- ✅ WebSocket server status (port 8787)
- ✅ Relay server status (port 18080)

### `vultisig list` - List Keyshares
List all `.vult` files in the `./keyshares/` directory.

### `vultisig init` - Initialize
Create the keyshares directory and default config file.

## Supported Networks

Vultisig supports address derivation and signing for the following blockchain networks:

| Network | Symbol | Curve | Example Address |
|---------|--------|-------|-----------------|
| **Bitcoin** | BTC | secp256k1 | `bc1qsef7rshf0jwm53rnkttpry5rpveqcd6dyj6pn9` |
| **Ethereum** | ETH | secp256k1 | `0x8c4E1C2D3b9F88bBa6162F6Bd8dB05840Ca24F8c` |
| **Solana** | SOL | ed25519 | `G5Jm9g1NH1xprPz3ZpnNmF8Wkz2F6YUhkxpf432mRefR` |
| **Cosmos** | ATOM | secp256k1 | `cosmos1axf2e8w0k73gp7zmfqcx7zssma34haxhcphy9r` |
| **THORChain** | RUNE | secp256k1 | `thor1nuwfr59wyn6da6v5ktxsa32v2t6u2q4veg9awu` |
| **BNB Smart Chain** | BNB | secp256k1 | `0x8c4E1C2D3b9F88bBa6162F6Bd8dB05840Ca24F8c` |

## TypeScript Integration

Vultisig provides TypeScript packages for easy integration with web applications:

### Available Packages

| Package | Purpose | Usage |
|---------|---------|-------|
| `vultisig-eth-signer` | Ethereum integration | Ethers.js compatible signer |
| `vultisig-btc-signer` | Bitcoin integration | Bitcoin transaction signing |
| `vultisig-sol-signer` | Solana integration | Solana transaction signing |

### Ethereum Example

```typescript
import { JsonRpcProvider } from "ethers";
import { VultisigSigner } from "vultisig-eth-signer";

// Connect to your Ethereum RPC
const provider = new JsonRpcProvider("https://eth.llamarpc.com");

// Create Vultisig signer (connects to daemon via Unix socket)
const signer = new VultisigSigner(provider, "/tmp/vultisig.sock");

// Use like any ethers.js signer
const address = await signer.getAddress();
const tx = await signer.sendTransaction({
  to: "0x742d35Cc6634C0532925a3b8D6Ac6E2b8c2C5E00",
  value: ethers.parseEther("0.1")
});
```

### Direct CLI Usage

For custom integrations, interact directly with the CLI daemon:

```bash
# Get address for any supported network
vultisig address --network btc

# Sign transaction with payload file
vultisig sign --network ETH --payload-file transaction.json
```

### Communication Protocol

The TypeScript packages communicate with the Rust daemon via:
- **Unix Socket**: `/tmp/vultisig.sock` for JSON-RPC requests
- **WebSocket**: `ws://localhost:8787/ws` for real-time signing coordination
- **HTTP**: `http://localhost:18080` for relay server and health checks

This architecture allows the TypeScript applications to trigger signing requests while the Rust daemon handles the heavy lifting of MPC coordination and blockchain integration.

## Signing Modes

### Local Mode (Default)
Direct peer-to-peer communication via local network:
- WebSocket server (port 8787) for mobile app connections
- Embedded relay server (port 18080) for MPC message routing
- mDNS discovery for automatic mobile pairing

### Relay Mode  
Remote signing via `api.vultisig.com`:
```bash
vultisig run --mode relay --vault vault.vult
```

## Keyshare Format

Vultisig `.vult` files contain:
```
Base64 → VaultContainer (protobuf) → Vault
├── public_key_ecdsa: hex (66 chars) - secp256k1 public key
├── public_key_eddsa: hex (64 chars) - Ed25519 public key  
├── hex_chain_code: hex (64 chars) - BIP32 chain code
├── key_shares: []KeyShare - MPC threshold shares (base64)
└── signers: []string - participant identifiers
```

## Configuration

Default config (`./vultisig-config.yaml`):
```yaml
websocketPort: 8787
httpPort: 18080
enableMobileSigning: true
useVultisigRelay: false
logLevel: "info"
```

### Directory Structure
```
your-project/
├── keyshares/              # Your .vult keyshare files
│   ├── vault1.vult
│   └── vault2.vult
├── vultisig-config.yaml    # Configuration file
└── target/release/         # Built binary
    └── vultisig            # Main CLI binary
```

## Examples and Integration Patterns

The `examples/` directory contains practical integration examples:

### Hardhat Integration
```bash
cd examples/hardhat
npm install

# Get address using Vultisig signer
npx ts-node scripts/address.ts

# Deploy contracts with MPC signing
npx ts-node scripts/deploy.ts
```

### Package Examples
Each TypeScript package includes usage examples:
- `packages/vultisig-eth-signer/` - Ethereum/EVM integration  
- `packages/vultisig-btc-signer/` - Bitcoin UTXO signing
- `packages/vultisig-sol-signer/` - Solana transaction signing

See the [examples README](examples/README.md) for detailed integration patterns and testing workflows.

## Development

### Build Requirements
- Rust 1.70+
- CMake 3.15+ (for wallet-core)
- Git (for submodules)

### Development Commands
```bash
./build.sh              # Full build with wallet-core
./dev.sh dev-build       # Fast build without wallet-core
./dev.sh run             # Run with debug logging
./dev.sh test            # Run test suite
./dev.sh fmt             # Format code
```

### Project Structure
```
vultisig-cli/
├── crates/app/           # Main Rust application (builds to 'vultisig' binary)
├── packages/             # TypeScript integration packages
│   ├── vultisig-eth-signer/  # Ethereum signer
│   ├── vultisig-btc-signer/  # Bitcoin signer
│   └── vultisig-sol-signer/  # Solana signer
├── examples/             # Integration examples and patterns
├── third_party/          # External dependencies
│   ├── dkls23/          # ECDSA MPC library
│   ├── multi-party-schnorr/  # EdDSA MPC library
│   └── wallet-core/     # TrustWallet core library
└── scripts/             # Utility scripts
```

## Troubleshooting

### Common Commands
```bash
# Check daemon status
vultisig status

# List available keyshares
vultisig list

# View addresses for specific networks  
vultisig address --network btc,eth,atom

# Start daemon with debug logging
RUST_LOG=debug vultisig run

# Verify services manually
curl http://localhost:8787/health      # WebSocket health
curl http://localhost:18080/health     # Relay health
```

### Common Issues

**"Command not found: vultisig"**
- Ensure the binary is built: `./build.sh`
- Add to PATH: `export PATH=$PWD/target/release:$PATH`
- Note: The binary is named `vultisig` (not `vultisigd`)

**"No .vult files found"**
```bash
vultisig init                    # Create keyshares directory
cp your-vault.vult ./keyshares/  # Copy keyshare files
vultisig list         # Verify files are detected
```

**"Daemon is not running"**
- Make sure Terminal 1 has `vultisig run` running
- Check for port conflicts (8787, 18080)
- Verify keyshare password is correct

**"Address already in use"**
- Another vultisig instance may be running
- Kill existing processes: `pkill vultisig`
- Or use different ports in config file

**"Cannot connect to daemon"**
- Ensure daemon started successfully in Terminal 1
- Check `vultisig status` output
- Verify no firewall blocking ports 8787/18080

## License

MIT License - See [LICENSE](LICENSE) for details.