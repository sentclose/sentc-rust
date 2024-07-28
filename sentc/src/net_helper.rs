use std::time::{SystemTime, UNIX_EPOCH};

use sentc_crypto::util_req_full::decode_jwt;

use crate::crypto_common::crypto::EncryptedHead;
use crate::crypto_common::user::{UserPublicKeyData, UserVerifyKeyData};
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
	let jwt_data = decode_jwt(jwt)?;

	//return 30 sec earlier
	if jwt_data.exp + 30 < get_time()? as usize {
		return Err(SentcError::JwtExpired);
	}

	Ok(())
}

pub async fn get_user_public_key_data(base_url: String, app_token: &str, user_id: &str) -> Result<UserPublicKeyData, SentcError>
{
	Ok(sentc_crypto::util_req_full::user::fetch_user_public_key(base_url, app_token, user_id).await?)
}

pub async fn get_group_public_key(base_url: String, app_token: &str, group_id: &str) -> Result<UserPublicKeyData, SentcError>
{
	Ok(sentc_crypto::util_req_full::group::get_public_key_data(base_url.to_string(), app_token, group_id).await?)
}

pub async fn get_user_verify_key_data(base_url: String, app_token: &str, user_id: &str, verify_key_id: &str)
	-> Result<UserVerifyKeyData, SentcError>
{
	Ok(sentc_crypto::util_req_full::user::fetch_user_verify_key_by_id(base_url, app_token, user_id, verify_key_id).await?)
}

pub async fn get_verify_key_internally_for_decrypt(
	head: &EncryptedHead,
	base_url: String,
	app_token: &str,
	verify: bool,
	user_id: Option<&str>,
) -> Result<Option<UserVerifyKeyData>, SentcError>
{
	let verify_key = match (verify, user_id, &head.sign) {
		(true, Some(id), Some(sh)) => {
			let k = get_user_verify_key_data(base_url, app_token, id, &sh.id).await?;

			Some(k)
		},
		_ => None,
	};

	Ok(verify_key)
}
