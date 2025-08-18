use crate::{AppState, crypto, handlers::validate_timestamp};
use anyhow::{Context, Result, bail};
use axum::{Json, extract::State, http::StatusCode};
use log::{error, info};
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
pub struct DeleteWalletRequest {
    pub wallet_id: String,
    pub public_key_pem: String,
    pub signature: String,
    pub timestamp: u64,
}

#[derive(Serialize)]
pub struct DeleteWalletResponse {
    pub wallet_id: String,
}

#[derive(Serialize)]
pub struct ErrorResponse {
    pub error: String,
}

pub async fn delete_wallet(
    State(state): State<AppState>,
    Json(request): Json<DeleteWalletRequest>,
) -> Result<Json<DeleteWalletResponse>, (StatusCode, Json<ErrorResponse>)> {
    match delete_wallet_inner(state, request).await {
        Ok(response) => Ok(Json(response)),
        Err(e) => {
            error!("Delete wallet failed: {}", e);
            Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: e.to_string(),
                }),
            ))
        }
    }
}

async fn delete_wallet_inner(
    state: AppState,
    request: DeleteWalletRequest,
) -> Result<DeleteWalletResponse> {
    validate_timestamp(request.timestamp)?;

    if !state
        .storage
        .verify_wallet_owner(&request.wallet_id, &request.public_key_pem)?
    {
        bail!("Access denied: not wallet owner");
    }

    let message = format!("delete_wallet:{}:{}", request.wallet_id, request.timestamp);

    crypto::verify_signature(&request.public_key_pem, &message, &request.signature)
        .context("Invalid signature")?;

    state
        .storage
        .delete_wallet(&request.wallet_id, &request.public_key_pem)?;

    info!("Deleted wallet {} by owner", request.wallet_id);

    Ok(DeleteWalletResponse {
        wallet_id: request.wallet_id,
    })
}
