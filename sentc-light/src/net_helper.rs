use std::time::{SystemTime, UNIX_EPOCH};

use sentc_crypto_light::util_req_full::decode_jwt;

use crate::error::SentcError;

pub(crate) fn get_time() -> Result<u64, SentcError>
{
	let time = SystemTime::now()
		.duration_since(UNIX_EPOCH)
		.map_err(|_| SentcError::TimeError)?;

	Ok(time.as_secs())
}

pub(crate) fn check_jwt(jwt: &str) -> Result<(), SentcError>
{
	//internal fn to get and check the jwt internally.
	// in a struct fn we can't use get jwt together if immutable borrow because get_jwt is mut borrow

	let jwt_data = decode_jwt(jwt)?;

	//return 30 sec earlier
	if jwt_data.exp > (get_time()? + 30) as usize {
		return Ok(());
	}

	Ok(())
}
