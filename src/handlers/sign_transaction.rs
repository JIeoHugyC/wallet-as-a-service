use crate::{AppState, crypto, storage::Network};
use anyhow::{Context, Result, bail};
use axum::{Json, extract::State, http::StatusCode};
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
pub struct SignTransactionRequest {
    pub wallet_id: String,
    pub network: Network,
    pub transaction_data: String, // hex-encoded transaction to sign
    pub public_key_pem: String,
    pub signature: String, // signature of the auth message
    pub timestamp: u64,
}

#[derive(Serialize)]
pub struct SignTransactionResponse {
    pub signature: String,                // hex-encoded signature
    pub transaction_hash: Option<String>, // optional, for some networks
}

#[derive(Serialize)]
pub struct ErrorResponse {
    pub error: String,
}

pub async fn sign_transaction(
    State(state): State<AppState>,
    Json(request): Json<SignTransactionRequest>,
) -> Result<Json<SignTransactionResponse>, (StatusCode, Json<ErrorResponse>)> {
    match sign_transaction_inner(state, request).await {
        Ok(response) => Ok(Json(response)),
        Err(e) => {
            log::error!("Sign transaction failed: {}", e);
            Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: e.to_string(),
                }),
            ))
        }
    }
}

async fn sign_transaction_inner(
    state: AppState,
    request: SignTransactionRequest,
) -> Result<SignTransactionResponse> {
    // Validate timestamp
    let current_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();

    if request.timestamp < current_time.saturating_sub(300) || request.timestamp > current_time + 60
    {
        bail!("Invalid timestamp");
    }

    // Verify wallet ownership
    if !state
        .storage
        .verify_wallet_owner(&request.wallet_id, &request.public_key_pem)?
    {
        bail!("Access denied: not wallet owner");
    }

    // Create auth message and verify signature
    let auth_message = format!(
        "sign_transaction:{}:{}:{}",
        request.wallet_id, request.transaction_data, request.timestamp
    );

    crypto::verify_signature(&request.public_key_pem, &auth_message, &request.signature)
        .context("Invalid authentication signature")?;

    // Get wallet private key
    let private_key = state.storage.get_private_key(
        &request.wallet_id,
        request.network,
        &request.public_key_pem,
    )?;

    // Decode transaction data
    let transaction_bytes =
        hex::decode(&request.transaction_data).context("Invalid hex transaction data")?;

    // Sign transaction based on network
    let (signature, transaction_hash) = match request.network {
        Network::Evm => {
            let (sig, hash) = crypto::sign_evm_transaction(&private_key, &transaction_bytes)?;
            (hex::encode(sig), Some(hex::encode(hash)))
        }
        Network::Solana => {
            let sig = crypto::sign_solana_transaction(&private_key, &transaction_bytes)?;
            (hex::encode(sig), None)
        }
    };

    log::info!(
        "Signed transaction for wallet {} on network {:?}",
        request.wallet_id,
        request.network
    );

    Ok(SignTransactionResponse {
        signature,
        transaction_hash,
    })
}
