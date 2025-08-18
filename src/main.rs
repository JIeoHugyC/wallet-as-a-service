use anyhow::Result;
use axum::{Router, routing::post};
use tokio::net::TcpListener;

mod crypto;
mod handlers;
mod storage;

use storage::WalletStorage;

#[derive(Clone)]
pub struct AppState {
    pub storage: WalletStorage,
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    let storage = WalletStorage::new("./wallet_data")?;

    let state = AppState { storage };

    let app = Router::new()
        .route(
            "/api/v1/create_wallet",
            post(handlers::create_wallet::create_wallet),
        )
        .route(
            "/api/v1/sign_transaction",
            post(handlers::sign_evm_transaction::sign_transaction),
        )
        .route(
            "/api/v1/delete_wallet",
            post(handlers::delete_wallet::delete_wallet),
        )
        .with_state(state);

    let listener = TcpListener::bind("127.0.0.1:3000").await?;
    log::info!("Wallet service listening on http://127.0.0.1:3000");

    axum::serve(listener, app).await?;

    Ok(())
}
