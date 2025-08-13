use anyhow::{anyhow, Result};
use secp256k1::{ecdsa::RecoverableSignature, Message, Secp256k1, SecretKey};
use sha3::{Digest, Keccak256};
use rlp::RlpStream;
use hex::{FromHex, ToHex};
use ed25519_dalek::{SigningKey as Ed25519SigningKey, VerifyingKey as Ed25519VerifyingKey, Signature as Ed25519Signature, Signer};
use num_bigint::BigUint;

pub fn derive_eth_address() -> Result<(String, SecretKey)> {
    let sk = load_dev_secp256k1_key()?;
    let secp = Secp256k1::new();
    let pk = secp256k1::PublicKey::from_secret_key(&secp, &sk);
    let uncompressed = pk.serialize_uncompressed();
    let mut hasher = Keccak256::new();
    hasher.update(&uncompressed[1..]);
    let hash = hasher.finalize();
    let addr_bytes = &hash[12..];
    let mut s = String::from("0x");
    s.push_str(&addr_bytes.encode_hex::<String>());
    Ok((s, sk))
}

pub fn derive_solana_pubkey_b58() -> Result<(String, Ed25519SigningKey)> {
    let sk = load_dev_ed25519_key()?;
    let vk: Ed25519VerifyingKey = sk.verifying_key();
    let b58 = bs58::encode(vk.to_bytes()).into_string();
    Ok((b58, sk))
}

pub fn sign_eth_eip1559_tx(payload: &serde_json::Value) -> Result<String> {
    let chain_id = payload.get("chainId").and_then(|v| v.as_u64()).ok_or_else(|| anyhow!("chainId"))?;
    let nonce = payload.get("nonce").and_then(|v| v.as_u64()).ok_or_else(|| anyhow!("nonce"))?;
    let max_priority_fee = payload.get("maxPriorityFeePerGas").and_then(|v| v.as_str()).ok_or_else(|| anyhow!("maxPriorityFeePerGas"))?;
    let max_fee = payload.get("maxFeePerGas").and_then(|v| v.as_str()).ok_or_else(|| anyhow!("maxFeePerGas"))?;
    let gas_limit = payload.get("gasLimit").and_then(|v| v.as_str()).ok_or_else(|| anyhow!("gasLimit"))?;
    let to = payload.get("to").and_then(|v| v.as_str()).unwrap_or("");
    let value = payload.get("value").and_then(|v| v.as_str()).unwrap_or("0");
    let data = payload.get("data").and_then(|v| v.as_str()).unwrap_or("0x");

    let parse_u256 = |s: &str| -> Result<Vec<u8>> {
        if s.starts_with("0x") { 
            Ok(strip_leading_zeroes(&<Vec<u8>>::from_hex(s.trim_start_matches("0x")).map_err(|e| anyhow!(e))?)) 
        } else {
            let n = BigUint::parse_bytes(s.as_bytes(), 10).ok_or_else(|| anyhow!("parse"))?;
            Ok(strip_leading_zeroes(&n.to_bytes_be()))
        }
    };
    let to_bytes = if to.is_empty() { Vec::new() } else { <Vec<u8>>::from_hex(to.trim_start_matches("0x")).map_err(|e| anyhow!(e))? };
    let value_bytes = parse_u256(value)?;
    let data_bytes: Vec<u8> = if data == "0x" { Vec::new() } else { <Vec<u8>>::from_hex(data.trim_start_matches("0x")).map_err(|e| anyhow!(e))? };
    let gas_limit_bytes = parse_u256(gas_limit)?;
    let max_fee_bytes = parse_u256(max_fee)?;
    let max_priority_bytes = parse_u256(max_priority_fee)?;

    // RLP encode signing payload
    let mut rlp = RlpStream::new_list(9);
    rlp.append(&chain_id);
    rlp.append(&nonce);
    rlp.append(&max_priority_bytes);
    rlp.append(&max_fee_bytes);
    rlp.append(&gas_limit_bytes);
    if to_bytes.is_empty() { rlp.append_empty_data(); } else { rlp.append(&to_bytes.as_slice()); }
    rlp.append(&value_bytes);
    rlp.append(&data_bytes);
    rlp.begin_list(0); // accessList []
    let sighash = keccak256(&[&[0x02u8], rlp.as_raw()].concat());

    // Sign
    let sk = load_dev_secp256k1_key()?;
    let msg = Message::from_digest(sighash);
    let secp = Secp256k1::new();
    let sig: RecoverableSignature = secp.sign_ecdsa_recoverable(&msg, &sk);
    let (rid, rsig) = sig.serialize_compact();
    let y_parity: u8 = rid.to_i32() as u8; // 0 or 1
    let r = &rsig[0..32];
    let s = &rsig[32..64];

    // RLP assemble signed
    let mut rlp_signed = RlpStream::new_list(12);
    rlp_signed.append(&chain_id);
    rlp_signed.append(&nonce);
    rlp_signed.append(&max_priority_bytes);
    rlp_signed.append(&max_fee_bytes);
    rlp_signed.append(&gas_limit_bytes);
    if to_bytes.is_empty() { rlp_signed.append_empty_data(); } else { rlp_signed.append(&to_bytes.as_slice()); }
    rlp_signed.append(&value_bytes);
    rlp_signed.append(&data_bytes);
    rlp_signed.begin_list(0);
    rlp_signed.append(&y_parity);
    rlp_signed.append(&r);
    rlp_signed.append(&s);
    let mut out = Vec::with_capacity(1 + rlp_signed.as_raw().len());
    out.push(0x02u8);
    out.extend_from_slice(rlp_signed.as_raw());
    let mut shex = String::from("0x");
    shex.push_str(&out.encode_hex::<String>());
    Ok(shex)
}

pub fn compute_eip712_digest(payload: &serde_json::Value) -> Result<[u8; 32]> {
    // Simplified EIP-712 hash - real implementation would parse types and domain
    let domain = payload.get("domain").ok_or_else(|| anyhow!("missing domain"))?;
    let message = payload.get("message").ok_or_else(|| anyhow!("missing message"))?;
    
    // Mock digest for now
    let mut hasher = Keccak256::new();
    hasher.update(b"eip712-mock");
    hasher.update(serde_json::to_string(domain)?.as_bytes());
    hasher.update(serde_json::to_string(message)?.as_bytes());
    let hash = hasher.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&hash);
    Ok(arr)
}

pub fn sign_eth_digest(digest: &[u8; 32]) -> Result<String> {
    let msg = Message::from_digest(*digest);
    let sk = load_dev_secp256k1_key()?;
    let secp = Secp256k1::new();
    let sig: RecoverableSignature = secp.sign_ecdsa_recoverable(&msg, &sk);
    let (rid, rsig) = sig.serialize_compact();
    let v: u8 = 27 + rid.to_i32() as u8; // 27/28
    let mut out = String::from("0x");
    out.push_str(&rsig.encode_hex::<String>());
    out.push_str(&format!("{:02x}", v));
    Ok(out)
}

pub fn sign_sol_bytes(message: &[u8]) -> Result<String> {
    let sk = load_dev_ed25519_key()?;
    let sig: Ed25519Signature = sk.sign(message);
    Ok(bs58::encode(sig.to_bytes()).into_string())
}

fn load_dev_secp256k1_key() -> Result<SecretKey> {
    if let Ok(hex_sk) = std::env::var("VULTISIG_DEV_ECDSA_SK") {
        let bytes = <[u8; 32]>::from_hex(hex_sk.trim_start_matches("0x")).map_err(|e| anyhow!(e))?;
        return SecretKey::from_slice(&bytes).map_err(|e| anyhow!(e));
    }
    // Derive from keccak("vultisig-dev-ecdsa")
    let mut hasher = Keccak256::new();
    hasher.update(b"vultisig-dev-ecdsa");
    let seed = hasher.finalize();
    let mut sk_bytes = [0u8; 32];
    sk_bytes.copy_from_slice(&seed[..32]);
    SecretKey::from_slice(&sk_bytes).map_err(|e| anyhow!(e))
}

fn load_dev_ed25519_key() -> Result<Ed25519SigningKey> {
    if let Ok(hex_sk) = std::env::var("VULTISIG_DEV_ED25519_SK") {
        let bytes = <[u8; 32]>::from_hex(hex_sk.trim_start_matches("0x")).map_err(|e| anyhow!(e))?;
        return Ok(Ed25519SigningKey::from_bytes(&bytes));
    }
    // Derive from keccak("vultisig-dev-ed25519")
    let mut hasher = Keccak256::new();
    hasher.update(b"vultisig-dev-ed25519");
    let seed = hasher.finalize();
    let mut sk_bytes = [0u8; 32];
    sk_bytes.copy_from_slice(&seed[..32]);
    Ok(Ed25519SigningKey::from_bytes(&sk_bytes))
}

fn strip_leading_zeroes(bytes: &[u8]) -> Vec<u8> {
    let mut i = 0;
    while i < bytes.len() && bytes[i] == 0 { i += 1; }
    bytes[i..].to_vec()
}

fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(data);
    let out = hasher.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&out);
    arr
}
