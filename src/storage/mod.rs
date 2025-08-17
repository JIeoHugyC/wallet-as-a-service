use aes_gcm::{
    Aes256Gcm, Key, Nonce,
    aead::{Aead, KeyInit},
};
use alloy::signers::{
    k256::{ecdsa::signature::Keypair, elliptic_curve::rand_core::OsRng},
    local::PrivateKeySigner,
};
use anyhow::{Context, Result, anyhow, bail};
use hkdf::Hkdf;
use log::info;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use solana_sdk::signature::Signer;
use std::{
    collections::HashMap,
    env, fs,
    path::{Path, PathBuf},
};
use uuid::Uuid;

const MIN_SALT_LENGTH: usize = 32;
const HASH_PREFIX_LENGTH: usize = 8;
const NONCE_SIZE: usize = 12;
const ENCRYPTION_KEY_SIZE: usize = 32;

#[derive(Clone)]
pub struct WalletStorage {
    data_dir: PathBuf,
    server_salt: Vec<u8>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum Network {
    Evm,
    Solana,
}

impl Network {
    pub fn all() -> Vec<Network> {
        vec![Network::Evm, Network::Solana]
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct EncryptedKey {
    pub ciphertext: Vec<u8>,
    pub nonce: Vec<u8>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct WalletData {
    pub wallet_id: String,
    pub owner_public_key_hash: String,
    pub encrypted_keys: HashMap<Network, EncryptedKey>,
    pub created_at: u64,
}

#[derive(Clone)]
pub struct NetworkKeyPair {
    pub network: Network,
    pub private_key: Vec<u8>,
    pub public_key: Vec<u8>,
}

impl WalletStorage {
    pub fn new<P: AsRef<Path>>(data_dir: P) -> Result<Self> {
        let data_dir = data_dir.as_ref().to_path_buf();

        if !data_dir.exists() {
            fs::create_dir_all(&data_dir).context("Failed to create data directory")?;
        }

        let server_salt = env::var("WALLET_ENCRYPTION_SALT")
            .context("WALLET_ENCRYPTION_SALT environment variable not set")?
            .into_bytes();

        if server_salt.len() < MIN_SALT_LENGTH {
            return bail!(
                "WALLET_ENCRYPTION_SALT must be at least {} bytes, got {}",
                MIN_SALT_LENGTH,
                server_salt.len()
            );
        }

        Ok(Self {
            data_dir,
            server_salt,
        })
    }

    pub fn create_wallet(&self, owner_public_key_pem: &str) -> Result<WalletData> {
        let wallet_id = Uuid::new_v4().to_string();
        let owner_public_key_hash = hash_public_key(owner_public_key_pem);

        let mut encrypted_keys = HashMap::new();

        for network in Network::all() {
            let key_pair = self.generate_network_key_pair(network)?;
            let encrypted_key =
                self.encrypt_private_key(&key_pair.private_key, owner_public_key_pem)?;
            encrypted_keys.insert(network, encrypted_key);
        }

        let wallet_data = WalletData {
            wallet_id: wallet_id.clone(),
            owner_public_key_hash,
            encrypted_keys,
            created_at: current_timestamp(),
        };

        self.store_wallet(&wallet_data)?;

        Ok(wallet_data)
    }

    pub fn get_private_key(
        &self,
        wallet_id: &str,
        network: Network,
        owner_public_key_pem: &str,
    ) -> Result<Vec<u8>> {
        let wallet_data = self.get_wallet(wallet_id)?;
        let owner_hash = hash_public_key(owner_public_key_pem);

        if wallet_data.owner_public_key_hash != owner_hash {
            return bail!("Access denied: not wallet owner");
        }

        let encrypted_key = wallet_data.encrypted_keys.get(&network).context(format!(
            "Network key not found for {:?} in wallet {}",
            network, wallet_id
        ))?;

        self.decrypt_private_key(encrypted_key, owner_public_key_pem)
    }

    fn generate_network_key_pair(&self, network: Network) -> Result<NetworkKeyPair> {
        match network {
            Network::Evm => self.generate_evm_key_pair(),
            Network::Solana => self.generate_solana_key_pair(),
        }
    }

    fn generate_evm_key_pair(&self) -> Result<NetworkKeyPair> {
        let signer = PrivateKeySigner::random();
        let private_key_bytes = signer.to_bytes();
        let public_key_bytes = signer
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();

        Ok(NetworkKeyPair {
            network: Network::Evm,
            private_key: private_key_bytes.to_vec(),
            public_key: public_key_bytes,
        })
    }

    fn generate_solana_key_pair(&self) -> Result<NetworkKeyPair> {
        let keypair = solana_sdk::signer::keypair::Keypair::new();
        let private_key_bytes = keypair.secret_bytes();
        let public_key_bytes = keypair.pubkey().to_bytes();

        Ok(NetworkKeyPair {
            network: Network::Solana,
            private_key: private_key_bytes.to_vec(),
            public_key: public_key_bytes.to_vec(),
        })
    }

    fn derive_encryption_key(
        &self,
        user_public_key_pem: &str,
    ) -> Result<[u8; ENCRYPTION_KEY_SIZE]> {
        let hk = Hkdf::<Sha256>::new(Some(&self.server_salt), user_public_key_pem.as_bytes());
        let mut okm = [0u8; ENCRYPTION_KEY_SIZE];
        hk.expand(b"wallet-encryption", &mut okm)
            .context("Failed to derive encryption key")?;

        Ok(okm)
    }

    fn encrypt_private_key(
        &self,
        private_key: &[u8],
        user_public_key_pem: &str,
    ) -> Result<EncryptedKey> {
        let key_bytes = self.derive_encryption_key(user_public_key_pem)?;
        let key = Key::<Aes256Gcm>::try_from(&key_bytes)?;
        let cipher = Aes256Gcm::new(&key);

        let mut nonce_bytes = [0u8; NONCE_SIZE];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::try_from(&nonce_bytes)?;

        let ciphertext = cipher
            .encrypt(&nonce, private_key)
            .context("Encryption failed")?;

        Ok(EncryptedKey {
            ciphertext,
            nonce: nonce_bytes.to_vec(),
        })
    }

    fn decrypt_private_key(
        &self,
        encrypted_key: &EncryptedKey,
        user_public_key_pem: &str,
    ) -> Result<Vec<u8>> {
        let key_bytes = self.derive_encryption_key(user_public_key_pem)?;
        let key = Key::<Aes256Gcm>::try_from(&key_bytes)?;
        let cipher = Aes256Gcm::new(&key);

        let nonce = Nonce::try_from(&encrypted_key.nonce)?;

        cipher
            .decrypt(&nonce, encrypted_key.ciphertext.as_ref())
            .context("Decryption failed")
    }

    pub fn store_wallet(&self, wallet_data: &WalletData) -> Result<()> {
        let wallet_file = self
            .data_dir
            .join(format!("{}.json", wallet_data.wallet_id));
        let json_data =
            serde_json::to_string_pretty(wallet_data).context("Failed to serialize wallet data")?;
        fs::write(wallet_file, json_data).context("Failed to write wallet file")?;

        info!("Stored wallet: {}", wallet_data.wallet_id);

        Ok(())
    }

    pub fn get_wallet(&self, wallet_id: &str) -> Result<WalletData> {
        let wallet_file = self.data_dir.join(format!("{}.json", wallet_id));

        if !wallet_file.exists() {
            return bail!("Wallet not found: {}", wallet_id);
        }

        let json_data = fs::read_to_string(wallet_file).context("Failed to read wallet file")?;
        let wallet_data: WalletData =
            serde_json::from_str(&json_data).context("Failed to parse wallet data")?;

        Ok(wallet_data)
    }

    pub fn delete_wallet(&self, wallet_id: &str, owner_public_key_pem: &str) -> Result<()> {
        let wallet_data = self.get_wallet(wallet_id)?;
        let owner_hash = hash_public_key(owner_public_key_pem);

        if wallet_data.owner_public_key_hash != owner_hash {
            return bail!("Access denied: not wallet owner");
        }

        let wallet_file = self.data_dir.join(format!("{}.json", wallet_id));
        fs::remove_file(wallet_file).context("Failed to delete wallet file")?;

        info!("Deleted wallet: {}", wallet_id);

        Ok(())
    }

    pub fn verify_wallet_owner(&self, wallet_id: &str, owner_public_key_pem: &str) -> Result<bool> {
        let wallet_data = self.get_wallet(wallet_id)?;
        let owner_hash = hash_public_key(owner_public_key_pem);
        Ok(wallet_data.owner_public_key_hash == owner_hash)
    }
}

pub fn hash_public_key(public_key_pem: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(public_key_pem.as_bytes());
    let result = hasher.finalize();

    hex::encode(&result[..HASH_PREFIX_LENGTH])
}

fn current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
