# BNB 48 SoulPoint Signature Generator

## Overview

This project provides a utility for generating 48SoulPoint (48sp) signatures required for submitting transaction bundles to the BNB48 Builders system. The generated signature ensures proper validation and prioritization within the puissant-builder v2 framework, enabling enhanced transaction sorting and auction performance.

## Prerequisites

- **Rust**: Ensure you have Rust installed. You can install it via [rustup](https://rustup.rs/).
- **Dependencies**:
  - `secp256k1`: For ECDSA signing.
  - `sha3`: For Keccak256 hashing.
  - `hex`: For encoding andExample Code decoding hexadecimal strings.


## Usage

Here’s how you can use the library to generate a 48 SoulPoint signature:

```rust
use sign48sp::generate_48sp_signature;

fn main() {
    let txn_hashes = vec![
        String::from("0xf8ad82e69c85012a05f200830329189455d398326f99059ff775485246999027b3197955"),
        String::from("0xf8ec8307f58584b8c6fe72830927c094bddbcbaa9cf9603b7055aad963506ede71692f12"),
    ];

    let private_key = "48acf19375e8a27309fe5394728abc2eb6d5a0a4feb6b6c53207ca1c256a6739";

    let signature = generate_48sp_signature(txn_hashes, private_key);

    println!("Generated Signature: {}", signature);
}
```

## Function Details

`generate_48sp_signature`

* Description
    * Generates a cryptographic signature for a concatenated Keccak256 hash of transaction hashes.
* Arguments
    * txn_hashes:
        * Type: Vec<String>
        * Description: A vector of transaction hashes in hexadecimal format (starting with 0x).
    * private_key_hex:
        * Type: &str
        * Description: A private key in hexadecimal format.
* Returns
    * A String containing the generated signature in hexadecimal format (prefixed with 0x).

## Testing

Run the unit tests included in the project to verify the implementation:
```sh
cargo test
```