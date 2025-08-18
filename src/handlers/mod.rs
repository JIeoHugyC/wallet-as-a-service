use anyhow::{Result, bail};
use std::time::{Duration, SystemTime};

pub(crate) mod create_wallet;
pub(crate) mod delete_wallet;
pub(crate) mod sign_evm_transaction;

const SIGNATURE_VALID_WINDOW_PAST: Duration = Duration::from_secs(300); // 5 minutes back
const SIGNATURE_VALID_WINDOW_FUTURE: Duration = Duration::from_secs(60); // 1 minute ahead

fn validate_timestamp(timestamp: u64) -> Result<()> {
    let now = SystemTime::now();
    let request_time = SystemTime::UNIX_EPOCH + Duration::from_secs(timestamp);

    if let Ok(elapsed) = request_time.elapsed() {
        if elapsed > SIGNATURE_VALID_WINDOW_PAST {
            bail!("Timestamp too old");
        }
    }

    if let Ok(duration_until) = request_time.duration_since(now) {
        if duration_until > SIGNATURE_VALID_WINDOW_FUTURE {
            bail!("Timestamp too far in future");
        }
    }

    Ok(())
}
