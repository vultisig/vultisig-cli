use std::env;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    
    // Generate protobuf code (existing + commondata integration)
    prost_build::compile_protos(&[
        "proto/commondata.proto",
        "proto/keyshare.proto", 
        "proto/vultisig_extensions.proto",
        // Commondata protobuf files
        "../../third_party/commondata/proto/vultisig/vault/v1/vault.proto",
        "../../third_party/commondata/proto/vultisig/vault/v1/vault_container.proto",
        "../../third_party/commondata/proto/vultisig/keysign/v1/coin.proto",
        "../../third_party/commondata/proto/vultisig/keysign/v1/keysign_message.proto",
        "../../third_party/commondata/proto/vultisig/keysign/v1/custom_message_payload.proto",
        "../../third_party/commondata/proto/vultisig/keysign/v1/blockchain_specific.proto",
        "../../third_party/commondata/proto/vultisig/keysign/v1/utxo_info.proto",
        "../../third_party/commondata/proto/vultisig/keysign/v1/erc20_approve_payload.proto",
        "../../third_party/commondata/proto/vultisig/keysign/v1/1inch_swap_payload.proto",
        "../../third_party/commondata/proto/vultisig/keysign/v1/kyberswap_swap_payload.proto",
        "../../third_party/commondata/proto/vultisig/keysign/v1/thorchain_swap_payload.proto",
        "../../third_party/commondata/proto/vultisig/keysign/v1/wasm_execute_contract_payload.proto",
        "../../third_party/commondata/proto/vultisig/keygen/v1/keygen_message.proto",
        "../../third_party/commondata/proto/vultisig/keygen/v1/reshare_message.proto",
        "../../third_party/commondata/proto/vultisig/keygen/v1/lib_type_message.proto",
    ], &[
        "proto/", 
        "../../third_party/commondata/proto/"
    ])
    .expect("Failed to compile protobuf files");
    
    // Tell cargo to invalidate when files change
    println!("cargo:rerun-if-changed=proto/commondata.proto");
    println!("cargo:rerun-if-changed=proto/keyshare.proto");
    println!("cargo:rerun-if-changed=proto/vultisig_extensions.proto");
    
    // Commondata proto files
    println!("cargo:rerun-if-changed=../../third_party/commondata/proto/vultisig/vault/v1/vault.proto");
    println!("cargo:rerun-if-changed=../../third_party/commondata/proto/vultisig/vault/v1/vault_container.proto");
    println!("cargo:rerun-if-changed=../../third_party/commondata/proto/vultisig/keysign/v1/coin.proto");
    println!("cargo:rerun-if-changed=../../third_party/commondata/proto/vultisig/keysign/v1/keysign_message.proto");
    println!("cargo:rerun-if-changed=../../third_party/commondata/proto/vultisig/keysign/v1/custom_message_payload.proto");
    println!("cargo:rerun-if-changed=../../third_party/commondata/proto/vultisig/keysign/v1/blockchain_specific.proto");
    println!("cargo:rerun-if-changed=../../third_party/commondata/proto/vultisig/keysign/v1/utxo_info.proto");
    println!("cargo:rerun-if-changed=../../third_party/commondata/proto/vultisig/keysign/v1/erc20_approve_payload.proto");
    println!("cargo:rerun-if-changed=../../third_party/commondata/proto/vultisig/keysign/v1/1inch_swap_payload.proto");
    println!("cargo:rerun-if-changed=../../third_party/commondata/proto/vultisig/keysign/v1/kyberswap_swap_payload.proto");
    println!("cargo:rerun-if-changed=../../third_party/commondata/proto/vultisig/keysign/v1/thorchain_swap_payload.proto");
    println!("cargo:rerun-if-changed=../../third_party/commondata/proto/vultisig/keysign/v1/wasm_execute_contract_payload.proto");
    println!("cargo:rerun-if-changed=../../third_party/commondata/proto/vultisig/keygen/v1/keygen_message.proto");
    println!("cargo:rerun-if-changed=../../third_party/commondata/proto/vultisig/keygen/v1/reshare_message.proto");
    println!("cargo:rerun-if-changed=../../third_party/commondata/proto/vultisig/keygen/v1/lib_type_message.proto");
}