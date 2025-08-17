use crate::{AppState, crypto};
use anyhow::{Context, Result, bail};
use axum::{Json, extract::State, http::StatusCode};
use log::error;
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
pub struct CreateWalletRequest {
    pub public_key_pem: String,
    pub signature: String,
    pub timestamp: u64,
}

#[derive(Serialize)]
pub struct CreateWalletResponse {
    pub wallet_id: String,
    pub public_keys: WalletPublicKeys,
}

#[derive(Serialize)]
pub struct WalletPublicKeys {
    pub evm: String,
    pub solana: String,
}

#[derive(Serialize)]
pub struct ErrorResponse {
    pub error: String,
}

pub async fn create_wallet(
    State(state): State<AppState>,
    Json(request): Json<CreateWalletRequest>,
) -> Result<Json<CreateWalletResponse>, (StatusCode, Json<ErrorResponse>)> {
    match create_wallet_inner(state, request).await {
        Ok(response) => Ok(Json(response)),
        Err(e) => {
            error!("Create wallet failed: {}", e);
            Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: e.to_string(),
                }),
            ))
        }
    }
}

async fn create_wallet_inner(
    state: AppState,
    request: CreateWalletRequest,
) -> Result<CreateWalletResponse> {
    // Validate timestamp (prevent replay attacks)
    let current_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();

    if request.timestamp < current_time.saturating_sub(300) || request.timestamp > current_time + 60
    {
        bail!("Invalid timestamp");
    }

    // Create message to verify
    let message = format!("create_wallet:{}", request.timestamp);

    // Verify signature
    crypto::verify_signature(&request.public_key_pem, &message, &request.signature)
        .context("Invalid signature")?;

    // Create wallet
    let wallet_data = state.storage.create_wallet(&request.public_key_pem)?;

    // Extract public keys for response
    let evm_private = state.storage.get_private_key(
        &wallet_data.wallet_id,
        crate::storage::Network::Evm,
        &request.public_key_pem,
    )?;

    let solana_private = state.storage.get_private_key(
        &wallet_data.wallet_id,
        crate::storage::Network::Solana,
        &request.public_key_pem,
    )?;

    let public_keys = WalletPublicKeys {
        evm: crypto::private_key_to_evm_address(&evm_private)?,
        solana: crypto::private_key_to_solana_pubkey(&solana_private)?,
    };

    Ok(CreateWalletResponse {
        wallet_id: wallet_data.wallet_id,
        public_keys,
    })
}
