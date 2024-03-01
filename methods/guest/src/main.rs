#![no_main]

use bincode::deserialize;
use ed25519_dalek::{Signature, VerifyingKey};
use risc0_zkvm::guest::env;

risc0_zkvm::guest::entry!(main);

fn main() {
    let (encoded_verifying_key, message, encoded_signature): (Vec<u8>, String, Vec<u8>) =
        env::read();

    let decoded_verifying_key: VerifyingKey = deserialize(&encoded_verifying_key).unwrap();
    let decoded_signature: Signature = deserialize(&encoded_signature).unwrap();

    decoded_verifying_key
        .verify_strict(message.as_bytes(), &decoded_signature)
        .expect("Verification failed");

    env::commit(&(encoded_verifying_key, message, encoded_signature));
}
