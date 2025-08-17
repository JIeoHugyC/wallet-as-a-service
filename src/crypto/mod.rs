use alloy::{network::TxSignerSync, signers::local::PrivateKeySigner};
use anyhow::{Context, Result, bail};
use base64::{Engine, engine::general_purpose};
use p256::{
    PublicKey,
    ecdsa::{Signature, VerifyingKey, signature::Verifier},
    pkcs8::DecodePublicKey,
};
use solana_sdk::{signature::Keypair, signer::Signer};

pub fn verify_signature(public_key_pem: &str, message: &str, signature_base64: &str) -> Result<()> {
    // Parse PEM public key
    let public_key =
        PublicKey::from_public_key_pem(public_key_pem).context("Invalid PEM public key")?;

    let verifying_key = VerifyingKey::from(&public_key);

    let signature_bytes = general_purpose::STANDARD
        .decode(signature_base64)
        .context("Invalid base64 signature")?;

    let signature =
        Signature::try_from(signature_bytes.as_slice()).context("Invalid signature format")?;

    // Verify
    verifying_key
        .verify(message.as_bytes(), &signature)
        .map_err(|_| anyhow::anyhow!("Signature verification failed"))?;

    Ok(())
}

pub fn private_key_to_evm_address(private_key_bytes: &[u8]) -> Result<String> {
    let signer = PrivateKeySigner::from_bytes(private_key_bytes.into())
        .context("Invalid EVM private key")?;

    Ok(format!("0x{:x}", signer.address()))
}

pub fn private_key_to_solana_pubkey(private_key_bytes: &[u8]) -> Result<String> {
    if private_key_bytes.len() != 64 {
        bail!("Invalid Solana private key length");
    }

    let keypair = Keypair::try_from(private_key_bytes).context("Invalid Solana private key")?;

    Ok(keypair.pubkey().to_string())
}
