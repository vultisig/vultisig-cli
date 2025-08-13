# Wallet-Core build configuration for Vultisig integration
cmake_minimum_required(VERSION 3.18)

project(VultisigWalletCore)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Set build type
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

# Platform-specific settings
if(APPLE)
    set(CMAKE_OSX_DEPLOYMENT_TARGET "10.14")
endif()

# Wallet Core source directory
set(WALLET_CORE_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/../wallet-core)

# Include directories
include_directories(
    ${WALLET_CORE_ROOT}/include
    ${WALLET_CORE_ROOT}/src
    ${WALLET_CORE_ROOT}/trezor-crypto/src
)

# Define source files for core functionality needed by Vultisig
set(VULTISIG_WALLET_CORE_SOURCES
    # Core wallet functionality
    ${WALLET_CORE_ROOT}/src/HDWallet.cpp
    ${WALLET_CORE_ROOT}/src/Mnemonic.cpp
    ${WALLET_CORE_ROOT}/src/PrivateKey.cpp
    ${WALLET_CORE_ROOT}/src/PublicKey.cpp
    ${WALLET_CORE_ROOT}/src/DerivationPath.cpp
    ${WALLET_CORE_ROOT}/src/AnyAddress.cpp
    
    # Address derivation
    ${WALLET_CORE_ROOT}/src/Bech32.cpp
    ${WALLET_CORE_ROOT}/src/Bech32Address.cpp
    ${WALLET_CORE_ROOT}/src/Base58Address.cpp
    ${WALLET_CORE_ROOT}/src/Bitcoin/SegwitAddress.cpp
    ${WALLET_CORE_ROOT}/src/Ethereum/Address.cpp
    ${WALLET_CORE_ROOT}/src/Solana/Address.cpp
    
    # Cryptography
    ${WALLET_CORE_ROOT}/src/Hash.cpp
    ${WALLET_CORE_ROOT}/src/Data.cpp
    ${WALLET_CORE_ROOT}/src/HexCoding.h
    ${WALLET_CORE_ROOT}/src/BinaryCoding.cpp
    
    # Coin-specific implementations
    ${WALLET_CORE_ROOT}/src/Bitcoin/Address.h
    ${WALLET_CORE_ROOT}/src/Ethereum/AddressChecksum.cpp
    ${WALLET_CORE_ROOT}/src/Cosmos/Address.h
    
    # Entry points for supported chains
    ${WALLET_CORE_ROOT}/src/Bitcoin/Entry.cpp
    ${WALLET_CORE_ROOT}/src/Ethereum/Entry.cpp
    ${WALLET_CORE_ROOT}/src/Solana/Entry.cpp
    ${WALLET_CORE_ROOT}/src/Cosmos/Entry.cpp
)

# Find and include protobuf
find_package(Protobuf REQUIRED)
if(Protobuf_FOUND)
    include_directories(${Protobuf_INCLUDE_DIRS})
endif()

# Create a static library for Vultisig wallet-core integration
add_library(vultisig_wallet_core STATIC ${VULTISIG_WALLET_CORE_SOURCES})

# Link against required libraries
if(APPLE)
    find_library(FOUNDATION_LIB Foundation)
    find_library(SECURITY_LIB Security)
    target_link_libraries(vultisig_wallet_core ${FOUNDATION_LIB} ${SECURITY_LIB})
elseif(UNIX)
    target_link_libraries(vultisig_wallet_core pthread dl)
endif()

# Set compiler flags
target_compile_definitions(vultisig_wallet_core PRIVATE 
    HAVE_CONFIG_H=1
    PIC=1
    VULTISIG_BUILD=1
)

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_definitions(vultisig_wallet_core PRIVATE DEBUG=1)
endif()

# Installation
install(TARGETS vultisig_wallet_core
    ARCHIVE DESTINATION lib
    LIBRARY DESTINATION lib
    RUNTIME DESTINATION bin
)

# Install headers
install(DIRECTORY ${WALLET_CORE_ROOT}/include/TrustWalletCore/
    DESTINATION include/TrustWalletCore
    FILES_MATCHING PATTERN "*.h"
)