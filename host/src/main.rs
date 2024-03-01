use bincode::{deserialize, serialize};
use ed25519_dalek::{Signature, VerifyingKey};
use methods::{VERIFY_ELF, VERIFY_ID};
use risc0_zkvm::{default_prover, ExecutorEnv};

fn main() {
    let message = "The quick brown fox jumps over the lazy dog".to_string();
    let hex_signature = "544074E0654A9B180B485203F53A383F49174DD90EB49EA96BD5A7C851E5975328FFA5B27BB1F06DA8EC8F1DABD3436F969E49D20B76B5321034EE9EE4D65B0D";
    let hex_verifying_key = "C3FC486135465114DF709877FAEF46909DF90838BFB322571F21CAE13673D45D";

    let verifying_key_bytes: [u8; 32] = hex::decode(hex_verifying_key).unwrap().try_into().unwrap();
    let signature_bytes: [u8; 64] = hex::decode(hex_signature).unwrap().try_into().unwrap();

    let verifying_key = VerifyingKey::from_bytes(&verifying_key_bytes).unwrap();
    let signature = Signature::try_from(&signature_bytes).unwrap();

    let encoded_verifying_key: Vec<u8> = serialize(&verifying_key).unwrap();
    let encoded_signature: Vec<u8> = serialize(&signature).unwrap();

    let input: (Vec<u8>, String, Vec<u8>) = (encoded_verifying_key, message, encoded_signature);

    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::filter::EnvFilter::from_default_env())
        .init();

    let env = ExecutorEnv::builder()
        .write(&input)
        .unwrap()
        .build()
        .unwrap();

    let prover = default_prover();

    let receipt = prover.prove(env, VERIFY_ELF).unwrap();

    let (proven_verifying_key, proven_message, proven_signature): (Vec<u8>, String, Vec<u8>) =
        receipt.journal.decode().unwrap();

    let proven_verifying_key: VerifyingKey = deserialize(&proven_verifying_key).unwrap();

    let proven_signature: Signature = deserialize(&proven_signature).unwrap();

    receipt.verify(VERIFY_ID).unwrap();

    println!(
        "Successfully verified the ed25519 signature over message {:?} with verifying key {:?} and signature {:?}",
        proven_message,
        hex::encode(proven_verifying_key.to_bytes()),
        hex::encode(proven_signature.to_bytes())
    );
}
