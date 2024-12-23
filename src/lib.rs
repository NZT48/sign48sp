use secp256k1::{Secp256k1, SecretKey, Message};
use sha3::{Digest, Keccak256};
use hex;

/// Generates a signature for concatenated Keccak256 transaction hashes using the provided private key.
/// 
/// # Arguments
/// * `txn_hashes` - A vector of transaction hashes as strings (hex format, starting with "0x").
/// * `private_key_hex` - The private key in hexadecimal format as a string.
///
/// # Returns
/// A `String` containing the generated signature (hex format with 0x prefix).
pub fn generate_48sp_signature(txn_hashes: Vec<String>, private_key_hex: &str) -> String {
    // Hash each transaction hash using Keccak256
    let tx_hashes_bytes: Vec<Vec<u8>> = txn_hashes
        .iter()
        .map(|hash| {
            let hash_bytes = hex::decode(hash.trim_start_matches("0x")).expect("Invalid hash format");
            let mut hasher = Keccak256::new();
            hasher.update(&hash_bytes);
            hasher.finalize().to_vec()
        })
        .collect();

    // Concatenate all the transaction hashes
    let concatenated_hashes: Vec<u8> = tx_hashes_bytes.iter().flatten().cloned().collect();

    // Compute the final Keccak256 hash of concatenated transaction hashes
    let combined_hash = {
        let mut hasher = Keccak256::new();
        hasher.update(&concatenated_hashes);
        hasher.finalize()
    };

    // Create a Secp256k1 context and private key
    let secp = Secp256k1::new();
    let private_key = SecretKey::from_slice(&hex::decode(private_key_hex.trim_start_matches("0x")).unwrap())
        .expect("Invalid private key");

    // Create a recoverable ECDSA signature
    let message = Message::from_digest_slice(&combined_hash).expect("Invalid message hash");
    let signature = secp.sign_ecdsa_recoverable(&message, &private_key);

    // Serialize the signature and append recovery ID
    let (recovery_id, signature_bytes) = signature.serialize_compact();
    let mut full_signature = signature_bytes.to_vec();
    full_signature.push(recovery_id as u8);

    // Return the signature as a hex string
    format!("0x{}", hex::encode(full_signature))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_signature() {
        let txn_hashes = vec![
            String::from("0xf8ad82e69c85012a05f200830329189455d398326f99059ff775485246999027b319795580b844a9059cbb0000000000000000000000006df68f71f19081751850160118fc755bfeb036120000000000000000000000000000000000000000000000056bc75e2d631000008193a0ade014e655a2d1645efb5f37a142c2369ab96d2d962861dd353fa33fe15b76cda041b291fb742d07c0d475cb2611e9dd6010bbd052c79f99e73c7f9e3653afb6f7"),
            String::from("0xf8ec8307f58584b8c6fe72830927c094bddbcbaa9cf9603b7055aad963506ede71692f1280b8830000000300000000000000000000000000000000000000000000000087250559b9145f9000000000000000000000000000000000000000000000011f35cc4934f0b52a80bb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c55d398326f99059ff775485246999027b319795500006400000000000000000af935e000000000000000008193a0f63bed83d054bdecfb6852f980ed62f35922fe5b68296b603b290a3eff41fabea04b73872c7e68f541bc97eba52abf956eac4a0e198b762e1f9a872336f6748eed"),
        ];

        let private_key = "48acf19375e8a27309fe5394728abc2eb6d5a0a4feb6b6c53207ca1c256a6739";

        let signature = generate_48sp_signature(txn_hashes, private_key);

        // Ensure the signature is a valid hex string with 0x prefix
        assert!(signature.starts_with("0x"));
        assert_eq!(signature.len(), 132); // 64 bytes (R + S) + 1 byte recovery ID + 0x prefix
        assert_eq!(signature, "0x83e4b3a6af20e58315554b5bc38a8398cfca44a75d42973a4454378b0dc9cae63c229b52341d1ddfc4e3ad4360e518c1f1363e2d21fcba507e8e2e10e266edd201");
    }
}