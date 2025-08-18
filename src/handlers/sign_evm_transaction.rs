use crate::{AppState, crypto, handlers::validate_timestamp, storage::Network};
use alloy::{
    consensus::{SignableTransaction, TxEnvelope},
    eips::Encodable2718,
    network::{TransactionBuilder, TxSignerSync},
    rpc::types::TransactionRequest,
    signers::local::PrivateKeySigner,
};
use anyhow::{Context, Result, bail};
use axum::{Json, extract::State, http::StatusCode};
use log::{error, info};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    hash::Hash,
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Debug, Deserialize, Serialize)]
pub struct TxParams {
    pub to: Option<String>,
    #[serde(default)]
    pub value: Option<String>,
    #[serde(default)]
    pub data: Option<String>,
    #[serde(default)]
    pub gas_limit: Option<u64>,
    #[serde(default)]
    pub gas_price: Option<String>,
    #[serde(default)]
    pub max_fee_per_gas: Option<String>,
    #[serde(default)]
    pub max_priority_fee_per_gas: Option<String>,
    #[serde(default)]
    pub nonce: Option<u64>,
    pub chain_id: u64,
}

#[derive(Deserialize)]
pub struct SignTransactionRequest {
    pub wallet_id: String,
    pub tx_params: TxParams,
    pub public_key_pem: String,
    pub signature: String,
    pub timestamp: u64,
}

#[derive(Serialize)]
pub struct SignTransactionResponse {
    pub signed_transaction: String,
    pub transaction_hash: String,
}

#[derive(Serialize)]
pub struct ErrorResponse {
    pub error: String,
}

impl TxParams {
    pub fn validate(&self) -> Result<()> {
        if self.chain_id == 0 {
            bail!("Chain ID cannot be 0");
        }

        if let Some(to) = &self.to {
            if !to.starts_with("0x") || to.len() != 42 {
                bail!("Invalid 'to' address format");
            }
        }

        if let Some(value) = &self.value {
            value
                .parse::<u128>()
                .context("Invalid value format - must be a valid number in wei")?;
        }

        if let Some(gas_price) = &self.gas_price {
            gas_price
                .parse::<u128>()
                .context("Invalid gas_price format")?;
        }

        if let Some(max_fee) = &self.max_fee_per_gas {
            max_fee
                .parse::<u128>()
                .context("Invalid max_fee_per_gas format")?;
        }

        if let Some(max_priority) = &self.max_priority_fee_per_gas {
            max_priority
                .parse::<u128>()
                .context("Invalid max_priority_fee_per_gas format")?;
        }

        if self.max_fee_per_gas.is_some() && self.gas_price.is_some() {
            bail!("Cannot specify both gas_price and max_fee_per_gas");
        }

        if self.max_fee_per_gas.is_some() && self.max_priority_fee_per_gas.is_none() {
            bail!("max_priority_fee_per_gas required when using max_fee_per_gas");
        }

        if let Some(data) = &self.data {
            let data_hex = data.strip_prefix("0x").unwrap_or(data);
            hex::decode(data_hex).context("Invalid hex data")?;
        }

        Ok(())
    }

    pub fn to_alloy_transaction_request(&self) -> Result<TransactionRequest> {
        use alloy::primitives::{Address, ChainId, TxKind, U256};

        let mut tx = TransactionRequest::default();

        if let Some(to_str) = &self.to {
            let to_address: Address = to_str.parse().context("Failed to parse 'to' address")?;
            tx.to = Some(TxKind::Call(to_address));
        }

        if let Some(value_str) = &self.value {
            let value: u128 = value_str.parse().context("Failed to parse value")?;
            tx.value = Some(U256::from(value));
        }

        if let Some(data_str) = &self.data {
            let data_hex = data_str.strip_prefix("0x").unwrap_or(data_str);
            let data_bytes = hex::decode(data_hex).context("Failed to decode data hex")?;
            tx.input = alloy::rpc::types::TransactionInput::new(data_bytes.into());
        }

        if let Some(gas_limit) = self.gas_limit {
            tx.gas = Some(gas_limit);
        }

        if let Some(gas_price_str) = &self.gas_price {
            let gas_price: u128 = gas_price_str.parse().context("Failed to parse gas_price")?;
            tx.gas_price = Some(gas_price);
        }

        if let Some(max_fee_str) = &self.max_fee_per_gas {
            let max_fee: u128 = max_fee_str
                .parse()
                .context("Failed to parse max_fee_per_gas")?;
            tx.max_fee_per_gas = Some(max_fee);
        }

        if let Some(max_priority_str) = &self.max_priority_fee_per_gas {
            let max_priority: u128 = max_priority_str
                .parse()
                .context("Failed to parse max_priority_fee_per_gas")?;
            tx.max_priority_fee_per_gas = Some(max_priority);
        }

        if let Some(nonce) = self.nonce {
            tx.nonce = Some(nonce);
        }

        tx.chain_id = Some(ChainId::from(self.chain_id));

        Ok(tx)
    }

    pub fn to_canonical_string(&self, wallet_id: &str, timestamp: u64) -> String {
        let data = self
            .data
            .as_deref()
            .map_or("", |data| data.strip_prefix("0x").unwrap_or(data));

        format!(
            "{}|{}|{}|{}|{}|{}|{}|{}|{}",
            wallet_id,
            timestamp,
            self.to.as_deref().unwrap_or(""),
            self.value.as_deref().unwrap_or("0"),
            data,
            self.gas_limit.unwrap_or(0),
            self.gas_price.as_deref().unwrap_or("0"),
            self.chain_id,
            self.nonce.unwrap_or(0)
        )
    }
}

pub async fn sign_transaction(
    State(state): State<AppState>,
    Json(request): Json<SignTransactionRequest>,
) -> Result<Json<SignTransactionResponse>, (StatusCode, Json<ErrorResponse>)> {
    match sign_transaction_inner(state, request).await {
        Ok(response) => Ok(Json(response)),
        Err(e) => {
            error!("Sign transaction failed: {}", e);
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
    validate_timestamp(request.timestamp)?;

    request
        .tx_params
        .validate()
        .context("Invalid transaction request")?;

    if !state
        .storage
        .verify_wallet_owner(&request.wallet_id, &request.public_key_pem)?
    {
        bail!("Access denied: not wallet owner");
    }

    let canonical_data = request
        .tx_params
        .to_canonical_string(&request.wallet_id, request.timestamp);
    let auth_hash = Sha256::digest(canonical_data.as_bytes());
    let auth_message = hex::encode(auth_hash);

    crypto::verify_signature(&request.public_key_pem, &auth_message, &request.signature)
        .context("Invalid authentication signature")?;

    let private_key =
        state
            .storage
            .get_private_key(&request.wallet_id, Network::Evm, &request.public_key_pem)?;

    let alloy_tx_request = request.tx_params.to_alloy_transaction_request()?;

    let signer =
        PrivateKeySigner::from_bytes(&private_key.into()).context("Invalid private key")?;

    let tx = alloy_tx_request
        .build_unsigned()
        .context("Failed to build unsigned transaction")?;

    let signature = signer
        .sign_transaction_sync(&tx)
        .map_err(|e| anyhow::anyhow!("Failed to sign transaction: {}", e))?;

    let signed = tx.into_signed(signature);
    let encoded = signed.encoded_2718();

    info!(
        "Signed EVM transaction for wallet {} on chain {}",
        request.wallet_id, request.tx_params.chain_id
    );

    Ok(SignTransactionResponse {
        signed_transaction: format!("0x{}", hex::encode(encoded)),
        transaction_hash: format!("0x{}", hex::encode(signed.hash())),
    })
}
