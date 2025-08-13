# Vultisig CLI Examples

This directory contains examples and documentation for running and testing the Vultisig daemon with various client applications.

## Key Learnings from Testing

### Building and Running the Daemon

1. **Binary Naming**: The main binary is named `vultisig` (not `vultisigd`). Build with:
   ```bash
   cargo build --release
   ./target/release/vultisig run --vault <keyshare-path>
   ```

2. **Keyshare Paths**: Use absolute paths to avoid path resolution issues:
   ```bash
   # Good
   ./target/release/vultisig run --vault /full/path/to/keyshare.vult
   
   # Problematic
   ./target/release/vultisig run --vault ./relative/path/keyshare.vult
   ```

3. **Password Handling**: 
   - For encrypted keyshares, always provide `--password` flag when running non-interactively
   - Unencrypted keyshares (like `TestSecureVault-cfa0-share2of2-Nopassword.vult`) can run without password

### RPC Communication

4. **Unix Socket**: The daemon uses Unix socket at `/tmp/vultisig.sock` for RPC communication
   - JSON-RPC format over Unix socket
   - Connection established via WebSocket protocol

5. **get_address Method**: Successfully implemented in `network.rs:477-500`
   - Accepts network parameter (ETH, BTC, SOL, etc.)
   - Returns proper JSON-RPC response with address and public key
   - Network names are case-insensitive (converted to uppercase internally)

### CLI Integration

6. **Direct CLI Usage**: Use the main binary directly for address generation and signing:
   ```bash
   # Get address for a specific network
   vultisig address --network ETH
   
   # Sign a transaction
   vultisig sign --network ETH --payload-file transaction.json
   ```

7. **Network Support**: Successfully tested address generation for:
   - **Ethereum**: `0x3B47C2D0678F92ECd8f54192D14d541f28DDbE97`
   - **Bitcoin**: `bc1qg7gldwlccw9qeyzpew37hetu2ys042wnu2n3l4`  
   - **Solana**: `5knhKqfmWuf6QJb4kwcUP47K9QpUheaxBbvDpNLVqCZz`

### MPC Coordinator Functionality

8. **Address Generation**: The MPC coordinator correctly:
   - Loads keyshares from vault files
   - Derives appropriate BIP32 paths for different networks
   - Generates network-specific addresses using the proper derivation methods
   - Handles different cryptographic curves (ECDSA for ETH/BTC, EdDSA for SOL)

### Common Issues and Solutions

9. **Port Conflicts**: If port 18080 is in use, the daemon will still function correctly - this is just the web UI port

10. **Build Dependencies**: Ensure all submodules are initialized and wallet-core is built:
    ```bash
    git submodule update --init --recursive
    ./scripts/build-wallet-core.sh
    ```

## Quick Start Guide

1. **Build the project**:
   ```bash
   cargo build --release
   ```

2. **Start daemon with test keyshare**:
   ```bash
   ./target/release/vultisig run --vault keyshares/TestSecureVault-cfa0-share2of2-Nopassword.vult
   ```

3. **Test address generation**:
   ```bash
   vultisig address --network ETH
   ```

## Directory Structure

- `hardhat/` - Hardhat project with TypeScript examples for blockchain interaction
- `../keyshares/` - Sample keyshare files for testing
- `../packages/vultisig-*-signer/` - TypeScript integration packages

The integration between Rust daemon and TypeScript packages demonstrates successful multi-language interoperability for blockchain signing operations.