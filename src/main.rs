use sign48sp::generate_48sp_signature;

fn main() {
    // Example inputs
    let txn_hashes = vec![
        String::from("0xf8ad82e69c85012a05f200830329189455d398326f99059ff775485246999027b3197955"),
        String::from("0xf8ec8307f58584b8c6fe72830927c094bddbcbaa9cf9603b7055aad963506ede71692f12"),
    ];
    let private_key = "48acf19375e8a27309fe5394728abc2eb6d5a0a4feb6b6c53207ca1c256a6739";

    let signature = generate_48sp_signature(txn_hashes, private_key);

    println!("Generated Signature: {}", signature);
}
