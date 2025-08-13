#!/bin/bash
set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}🔧 Building Vultisig CLI${NC}"

# Check dependencies
check_deps() {
    echo -e "${YELLOW}📋 Checking build dependencies...${NC}"
    
    # Check Rust
    if ! command -v cargo &> /dev/null; then
        echo -e "${RED}❌ Rust not found. Install from https://rustup.rs/${NC}"
        exit 1
    fi
    
    # Check CMake (required for wallet-core)
    if ! command -v cmake &> /dev/null; then
        echo -e "${RED}❌ CMake not found${NC}"
        echo "Install CMake:"
        echo "  macOS: brew install cmake"
        echo "  Ubuntu/Debian: sudo apt install cmake build-essential"
        exit 1
    fi
    
    echo -e "${GREEN}✅ All dependencies found${NC}"
}

# Initialize submodules
init_submodules() {
    echo -e "${YELLOW}🔄 Initializing git submodules...${NC}"
    git submodule update --init --recursive
    echo -e "${GREEN}✅ Submodules initialized${NC}"
}

# Build project
build_project() {
    echo -e "${YELLOW}🔨 Building vultisig...${NC}"
    
    # Clean previous builds for fresh start
    cargo clean
    
    # Build with optimizations
    RUST_LOG=info cargo build --release --features wallet-core
    
    echo -e "${GREEN}✅ Build completed successfully${NC}"
    echo -e "${GREEN}📍 Binary location: $(pwd)/target/release/vultisig${NC}"
}

# Run tests
run_tests() {
    echo -e "${YELLOW}🧪 Running tests...${NC}"
    cargo test --release --features wallet-core
    echo -e "${GREEN}✅ Tests passed${NC}"
}

# Add binary to PATH
add_to_path() {
    echo -e "${YELLOW}🔗 Adding vultisig to PATH...${NC}"
    
    local binary_path="$(pwd)/target/release"
    local shell_config=""
    
    # Detect shell and set appropriate config file
    if [[ "$SHELL" == *"zsh"* ]]; then
        shell_config="$HOME/.zshrc"
    elif [[ "$SHELL" == *"bash"* ]]; then
        shell_config="$HOME/.bashrc"
        # On macOS, also check .bash_profile
        if [[ "$OSTYPE" == "darwin"* ]] && [[ -f "$HOME/.bash_profile" ]]; then
            shell_config="$HOME/.bash_profile"
        fi
    else
        echo -e "${YELLOW}⚠️  Unknown shell: $SHELL${NC}"
        echo -e "${YELLOW}   Please manually add to your shell config:${NC}"
        echo -e "${YELLOW}   export PATH=\"$binary_path:\$PATH\"${NC}"
        return 0
    fi
    
    # Check if PATH entry already exists
    if [[ -f "$shell_config" ]] && grep -q "vultisig-cli/target/release" "$shell_config"; then
        echo -e "${GREEN}✅ PATH already configured in $shell_config${NC}"
        return 0
    fi
    
    # Add PATH export to shell config
    echo "" >> "$shell_config"
    echo "# Vultisig CLI - Added by build script" >> "$shell_config"
    echo "export PATH=\"$binary_path:\$PATH\"" >> "$shell_config"
    
    echo -e "${GREEN}✅ Added vultisig to PATH in $shell_config${NC}"
    echo -e "${YELLOW}💡 Run 'source $shell_config' or restart your terminal to use 'vultisig' command${NC}"
    
    # Also export for current session
    export PATH="$binary_path:$PATH"
    echo -e "${GREEN}✅ vultisig command available in current session${NC}"
}

# Main execution
main() {
    echo "Build mode: ${1:-full}"
    
    case "${1:-full}" in
        "deps")
            check_deps
            ;;
        "submodules")
            init_submodules
            ;;
        "build")
            build_project
            ;;
        "test")
            run_tests
            ;;
        "path")
            add_to_path
            ;;
        "full")
            check_deps
            init_submodules
            build_project
            run_tests
            add_to_path
            echo -e "${GREEN}🎉 Full build completed successfully!${NC}"
            echo -e "${GREEN}🚀 You can now use 'vultisig' command from anywhere!${NC}"
            ;;
        *)
            echo "Usage: $0 [deps|submodules|build|test|path|full]"
            exit 1
            ;;
    esac
}

main "$@"