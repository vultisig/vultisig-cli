#!/usr/bin/env node
/**
 * Vultisig Keyshare Inspector
 * 
 * A Node.js tool to inspect and analyze .vult keyshare files
 * This script reads, decodes, and analyzes the structure of Vultisig keyshare files
 */

const fs = require('fs');
const path = require('path');

function main() {
    const args = process.argv.slice(2);
    
    if (args.length === 0 || args[0] === '--help') {
        printHelp();
        return;
    }
    
    const keyshareFile = args[0];
    const password = args[1];
    
    console.log('🔍 Vultisig Keyshare Inspector');
    console.log('================================');
    console.log(`File: ${keyshareFile}`);
    
    if (!fs.existsSync(keyshareFile)) {
        console.error(`❌ Keyshare file not found: ${keyshareFile}`);
        process.exit(1);
    }
    
    try {
        const content = fs.readFileSync(keyshareFile, 'utf8');
        analyzeKeyshareFile(content, password);
        generateDocumentation();
    } catch (error) {
        console.error(`❌ Error reading file: ${error.message}`);
        process.exit(1);
    }
}

function printHelp() {
    console.log(`
Vultisig Keyshare Inspector
===========================

This tool inspects .vult keyshare files and explains their structure.

USAGE:
  node inspect_keyshare.js <file.vult>           # Inspect unencrypted keyshare
  node inspect_keyshare.js <file.vult> password  # Inspect encrypted keyshare

EXAMPLES:
  node inspect_keyshare.js ~/.vultisig/keyshares/my_vault.vult
  node inspect_keyshare.js encrypted.vult mypassword123

OUTPUT:
  - File format analysis
  - Keyshare structure breakdown  
  - Public key information
  - Supported blockchain networks
  - JSON schema documentation
`);
}

function analyzeKeyshareFile(content, password) {
    console.log('\\n📋 Raw Content Analysis:');
    console.log(`  Content length: ${content.length} characters`);
    
    const trimmed = content.trim();
    console.log(`  Trimmed length: ${trimmed.length} characters`);
    
    // Check if it looks like base64
    const base64Regex = /^[A-Za-z0-9+/]*={0,2}$/;
    const cleanContent = trimmed.replace(/\\s/g, '');
    const isBase64 = base64Regex.test(cleanContent);
    
    console.log(`  Base64 format: ${isBase64 ? '✅ Valid' : '❌ Invalid'}`);
    
    if (isBase64) {
        try {
            const decoded = Buffer.from(cleanContent, 'base64');
            console.log(`  ✅ Valid base64, decoded to ${decoded.length} bytes`);
            
            analyzeDecodedData(decoded, password);
        } catch (error) {
            console.log(`  ❌ Base64 decode error: ${error.message}`);
        }
    }
}

function analyzeDecodedData(decodedData, password) {
    console.log('\\n📦 Decoded Data Analysis:');
    console.log(`  Binary data length: ${decodedData.length} bytes`);
    
    // Check if it looks like protobuf (starts with small field numbers)
    if (decodedData.length > 0) {
        const firstByte = decodedData[0];
        console.log(`  First byte: 0x${firstByte.toString(16).padStart(2, '0')} (${firstByte})`);
        
        if (firstByte < 32) {
            console.log('  💡 Appears to be binary protobuf data');
            analyzeProtobufStructure(decodedData, password);
        } else {
            console.log('  💡 Appears to be text data');
            try {
                const textData = decodedData.toString('utf8');
                console.log(`  Text preview: ${textData.substring(0, 100)}...`);
            } catch (e) {
                console.log('  ❌ Cannot decode as UTF-8 text');
            }
        }
    }
}

function analyzeProtobufStructure(data, password) {
    console.log('\\n🔍 Protobuf Structure Analysis:');
    
    // Try to identify protobuf field patterns
    const fields = extractProtobufFields(data);
    console.log(`  Detected ${fields.length} protobuf fields:`);
    
    fields.forEach((field, index) => {
        console.log(`    Field ${field.number}: ${field.type} (${field.length} bytes)`);
        if (field.type === 'string' && field.data.length < 200) {
            try {
                const str = field.data.toString('utf8');
                if (str.length > 0 && str.length < 100) {
                    console.log(`      Value: "${str}"`);
                }
            } catch (e) {
                // Not valid UTF-8
            }
        }
    });
    
    // Analyze based on expected VaultContainer structure
    analyzeVaultContainer(fields, password);
}

function extractProtobufFields(data) {
    const fields = [];
    let offset = 0;
    
    while (offset < data.length) {
        try {
            const { tag, type, length, fieldData, nextOffset } = readProtobufField(data, offset);
            fields.push({
                number: tag >> 3,
                wireType: type,
                type: getWireTypeName(type),
                length: length,
                data: fieldData
            });
            offset = nextOffset;
        } catch (e) {
            break; // Stop parsing if we hit invalid data
        }
    }
    
    return fields;
}

function readProtobufField(data, offset) {
    // Read varint tag
    const { value: tag, nextOffset: tagEnd } = readVarint(data, offset);
    const wireType = tag & 0x07;
    
    let fieldData, nextOffset, length;
    
    switch (wireType) {
        case 0: // Varint
            const { value, nextOffset: varintEnd } = readVarint(data, tagEnd);
            fieldData = Buffer.from([value]);
            nextOffset = varintEnd;
            length = varintEnd - tagEnd;
            break;
            
        case 2: // Length-delimited
            const { value: len, nextOffset: lenEnd } = readVarint(data, tagEnd);
            fieldData = data.slice(lenEnd, lenEnd + len);
            nextOffset = lenEnd + len;
            length = len;
            break;
            
        default:
            throw new Error(`Unsupported wire type: ${wireType}`);
    }
    
    return { tag, type: wireType, length, fieldData, nextOffset };
}

function readVarint(data, offset) {
    let value = 0;
    let shift = 0;
    let nextOffset = offset;
    
    while (nextOffset < data.length) {
        const byte = data[nextOffset++];
        value |= (byte & 0x7F) << shift;
        if ((byte & 0x80) === 0) break;
        shift += 7;
    }
    
    return { value, nextOffset };
}

function getWireTypeName(wireType) {
    const types = {
        0: 'varint',
        1: 'fixed64', 
        2: 'string/bytes',
        3: 'start_group',
        4: 'end_group',
        5: 'fixed32'
    };
    return types[wireType] || 'unknown';
}

function analyzeVaultContainer(fields, password) {
    console.log('\\n📦 VaultContainer Analysis:');
    
    // Expected fields: version (1), vault (2), is_encrypted (3)
    const versionField = fields.find(f => f.number === 1);
    const vaultField = fields.find(f => f.number === 2);
    const encryptedField = fields.find(f => f.number === 3);
    
    if (versionField) {
        console.log(`  ✅ Version: ${versionField.data[0] || 0}`);
    }
    
    if (encryptedField) {
        const isEncrypted = encryptedField.data[0] === 1;
        console.log(`  🔒 Is Encrypted: ${isEncrypted}`);
        
        if (isEncrypted && !password) {
            console.log('  ⚠️  File is encrypted but no password provided');
        }
    }
    
    if (vaultField) {
        console.log(`  📄 Vault Data: ${vaultField.length} bytes`);
        
        try {
            const vaultData = vaultField.data.toString('utf8');
            console.log(`  💡 Vault appears to be base64 encoded`);
            
            // Try to decode the inner vault
            if (vaultData.match(/^[A-Za-z0-9+/]*={0,2}$/)) {
                try {
                    const innerVault = Buffer.from(vaultData, 'base64');
                    console.log(`  📊 Inner vault: ${innerVault.length} bytes`);
                    analyzeInnerVault(innerVault);
                } catch (e) {
                    console.log(`  ❌ Failed to decode inner vault: ${e.message}`);
                }
            }
        } catch (e) {
            console.log(`  ❌ Vault data is not valid UTF-8 (likely encrypted)`);
        }
    }
}

function analyzeInnerVault(vaultData) {
    console.log('\\n🏛️  Inner Vault Analysis:');
    
    const fields = extractProtobufFields(vaultData);
    console.log(`  Fields detected: ${fields.length}`);
    
    // Expected Vault fields based on protobuf definition
    const fieldMap = {
        1: 'name',
        2: 'public_key_ecdsa', 
        3: 'public_key_eddsa',
        4: 'signers',
        5: 'created_at',
        6: 'hex_chain_code',
        7: 'key_shares',
        8: 'local_party_id',
        9: 'reshare_prefix',
        10: 'lib_type'
    };
    
    fields.forEach(field => {
        const fieldName = fieldMap[field.number] || `unknown_${field.number}`;
        console.log(`  ${fieldName} (field ${field.number}): ${field.type}, ${field.length} bytes`);
        
        if (field.type === 'string/bytes' && field.length < 200) {
            try {
                const str = field.data.toString('utf8');
                if (str.length > 0 && fieldName !== 'key_shares') {
                    console.log(`    Value: "${str}"`);
                }
            } catch (e) {
                // Not valid UTF-8, probably binary data
                if (field.length <= 64) {
                    console.log(`    Hex: ${field.data.toString('hex')}`);
                }
            }
        }
    });
    
    // Analyze specific fields
    analyzeVaultFields(fields, fieldMap);
}

function analyzeVaultFields(fields, fieldMap) {
    console.log('\\n🔑 Keyshare Analysis:');
    
    const ecdsaField = fields.find(f => f.number === 2); // public_key_ecdsa
    const eddsaField = fields.find(f => f.number === 3); // public_key_eddsa
    const chainCodeField = fields.find(f => f.number === 6); // hex_chain_code
    
    if (ecdsaField && ecdsaField.data.length > 0) {
        try {
            const ecdsaKey = ecdsaField.data.toString('utf8');
            console.log(`  📈 ECDSA Public Key: ${ecdsaKey}`);
            console.log(`    🌐 Supports: Ethereum, Bitcoin, THORChain, Cosmos, BSC`);
            console.log(`    📏 Length: ${ecdsaKey.length} chars (should be 66 for compressed key)`);
        } catch (e) {
            console.log(`  📈 ECDSA Public Key: ${ecdsaField.data.length} bytes (binary)`);
        }
    } else {
        console.log(`  ❌ No ECDSA public key found`);
    }
    
    if (eddsaField && eddsaField.data.length > 0) {
        try {
            const eddsaKey = eddsaField.data.toString('utf8');
            console.log(`  📊 EdDSA Public Key: ${eddsaKey}`);
            console.log(`    🌐 Supports: Solana`);
            console.log(`    📏 Length: ${eddsaKey.length} chars (should be 64 for Ed25519 key)`);
        } catch (e) {
            console.log(`  📊 EdDSA Public Key: ${eddsaField.data.length} bytes (binary)`);
        }
    } else {
        console.log(`  ❌ No EdDSA public key found`);
    }
    
    if (chainCodeField && chainCodeField.data.length > 0) {
        try {
            const chainCode = chainCodeField.data.toString('utf8');
            console.log(`  🔗 Chain Code: ${chainCode}`);
            console.log(`    📏 Length: ${chainCode.length} chars (should be 64 for 32-byte hex)`);
        } catch (e) {
            console.log(`  🔗 Chain Code: ${chainCodeField.data.length} bytes (binary)`);
        }
    }
}

function generateDocumentation() {
    console.log('\\n📚 Vultisig Keyshare Structure Documentation');
    console.log('==============================================\\n');
    
    const schema = {
        "VultisigKeyshareFormat": {
            "description": "Vultisig keyshare files (.vult) use a layered structure with base64 encoding and protobuf serialization",
            "layers": [
                "1. Base64 encoding of the entire file content",
                "2. Protobuf VaultContainer message", 
                "3. Inner base64-encoded vault data (if unencrypted) or AES-256-GCM encrypted data",
                "4. Protobuf Vault message containing the actual keyshare data"
            ]
        },
        "VaultContainer": {
            "description": "Top-level protobuf message wrapping the vault data",
            "fields": {
                "version": {
                    "field_number": 1,
                    "type": "uint64",
                    "description": "Data format version number"
                },
                "vault": {
                    "field_number": 2, 
                    "type": "string",
                    "description": "Base64-encoded vault data (plain) or AES-256-GCM encrypted data"
                },
                "is_encrypted": {
                    "field_number": 3,
                    "type": "bool", 
                    "description": "Whether the vault data is password-encrypted"
                }
            }
        },
        "Vault": {
            "description": "Inner protobuf message containing the actual keyshare and metadata",
            "fields": {
                "name": {
                    "field_number": 1,
                    "type": "string",
                    "description": "Human-readable vault name"
                },
                "public_key_ecdsa": {
                    "field_number": 2,
                    "type": "string", 
                    "description": "Hex-encoded compressed secp256k1 public key (66 chars)"
                },
                "public_key_eddsa": {
                    "field_number": 3,
                    "type": "string",
                    "description": "Hex-encoded Ed25519 public key (64 chars)" 
                },
                "signers": {
                    "field_number": 4,
                    "type": "repeated string",
                    "description": "List of MPC participant identifiers"
                },
                "created_at": {
                    "field_number": 5,
                    "type": "google.protobuf.Timestamp",
                    "description": "Vault creation timestamp"
                },
                "hex_chain_code": {
                    "field_number": 6,
                    "type": "string",
                    "description": "Hex-encoded BIP32 chain code for HD derivation (64 chars)"
                },
                "key_shares": {
                    "field_number": 7,
                    "type": "repeated KeyShare",
                    "description": "MPC threshold signature key shares"
                },
                "local_party_id": {
                    "field_number": 8,
                    "type": "string",
                    "description": "Local participant ID in MPC protocol"
                },
                "reshare_prefix": {
                    "field_number": 9,
                    "type": "string", 
                    "description": "Prefix for key resharing operations"
                },
                "lib_type": {
                    "field_number": 10,
                    "type": "LibType",
                    "description": "MPC library type (e.g., GG20 = 0)"
                }
            }
        },
        "KeyShare": {
            "description": "Individual MPC key share",
            "fields": {
                "public_key": {
                    "field_number": 1,
                    "type": "string",
                    "description": "Public key component for this share"
                },
                "keyshare": {
                    "field_number": 2,
                    "type": "string",
                    "description": "Encrypted private key share data"
                }
            }
        },
        "SupportedNetworks": {
            "ECDSA": [
                { "name": "Ethereum", "symbol": "ETH", "path": "m/44'/60'/0'/0/0" },
                { "name": "Bitcoin", "symbol": "BTC", "path": "m/84'/0'/0'/0/0" },
                { "name": "THORChain", "symbol": "RUNE", "path": "m/44'/931'/0'/0/0" },
                { "name": "Cosmos", "symbol": "ATOM", "path": "m/44'/118'/0'/0/0" },
                { "name": "Binance Smart Chain", "symbol": "BSC", "path": "m/44'/60'/0'/0/0" }
            ],
            "EdDSA": [
                { "name": "Solana", "symbol": "SOL", "path": "m/44'/501'/0'/0'" }
            ]
        },
        "EncryptionDetails": {
            "algorithm": "AES-256-GCM",
            "key_derivation": "SHA256(password)",
            "nonce": "First 12 bytes of encrypted data",
            "ciphertext": "Remaining bytes after nonce"
        }
    };
    
    console.log(JSON.stringify(schema, null, 2));
    
    console.log('\\n🔧 Usage Examples:');
    console.log('==================');
    console.log('');
    console.log('// Read and parse a keyshare file in Node.js:');
    console.log('const fs = require("fs");');
    console.log('const content = fs.readFileSync("vault.vult", "utf8");');
    console.log('const decoded = Buffer.from(content.trim(), "base64");');
    console.log('// Parse as VaultContainer protobuf...');
    console.log('');
    console.log('// In Rust using vultisig:');
    console.log('use vultisig::keyshare::VultKeyshare;');
    console.log('let keyshare = VultKeyshare::from_base64_with_password(&content, password)?;');
    console.log('let eth_addr = keyshare.derive_eth_address()?;');
}

if (require.main === module) {
    main();
}

module.exports = {
    analyzeKeyshareFile,
    generateDocumentation
};
