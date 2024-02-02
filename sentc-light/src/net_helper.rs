use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::SentcError;

pub(crate) fn get_time() -> Result<u64, SentcError>
{
	let time = SystemTime::now()
		.duration_since(UNIX_EPOCH)
		.map_err(|_| SentcError::TimeError)?;

	Ok(time.as_secs())
}
