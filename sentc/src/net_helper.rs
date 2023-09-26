use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use sentc_crypto::sdk_common::crypto::EncryptedHead;
use sentc_crypto::sdk_common::user::{UserPublicKeyData, UserVerifyKeyData};

use crate::cache::l_one::L1Cache;
use crate::error::SentcError;

pub(crate) fn get_time() -> Result<u64, SentcError>
{
	let time = SystemTime::now()
		.duration_since(UNIX_EPOCH)
		.map_err(|_| SentcError::TimeError)?;

	Ok(time.as_secs())
}

pub(crate) async fn get_user_public_key_data(
	base_url: &str,
	app_token: &str,
	user_id: &str,
	c: &L1Cache,
) -> Result<Arc<UserPublicKeyData>, SentcError>
{
	let key = if let Some(k) = c.get_user_public_key(user_id).await {
		k
	} else {
		let fetched_key = sentc_crypto_full::user::fetch_user_public_key(base_url.to_string(), app_token, user_id).await?;
		c.insert_user_public_key(user_id, fetched_key).await?;

		c.get_user_public_key(user_id)
			.await
			.ok_or(SentcError::KeyNotFound)?
	};

	Ok(key)
}

pub(crate) async fn get_group_public_key(base_url: &str, app_token: &str, group_id: &str, c: &L1Cache) -> Result<Arc<UserPublicKeyData>, SentcError>
{
	let key = if let Some(k) = c.get_group_public_key(group_id).await {
		k
	} else {
		let fetched_key = sentc_crypto_full::group::get_public_key_data(base_url.to_string(), app_token, group_id).await?;
		c.insert_group_public_key(group_id, fetched_key).await?;

		c.get_group_public_key(group_id)
			.await
			.ok_or(SentcError::KeyNotFound)?
	};

	Ok(key)
}

pub(crate) async fn get_user_verify_key_data(
	base_url: &str,
	app_token: &str,
	user_id: &str,
	verify_key_id: &str,
	c: &L1Cache,
) -> Result<Arc<UserVerifyKeyData>, SentcError>
{
	let key = if let Some(k) = c.get_user_verify_key(user_id, verify_key_id).await {
		k
	} else {
		let fetched_key = sentc_crypto_full::user::fetch_user_verify_key_by_id(base_url.to_string(), app_token, user_id, verify_key_id).await?;
		c.insert_user_verify_key(user_id, fetched_key).await?;

		c.get_user_verify_key(user_id, verify_key_id)
			.await
			.ok_or(SentcError::KeyNotFound)?
	};

	Ok(key)
}

pub(crate) async fn get_verify_key_internally_for_decrypt(
	head: &EncryptedHead,
	base_url: &str,
	app_token: &str,
	verify: bool,
	user_id: Option<&str>,
	c: &L1Cache,
) -> Result<Option<Arc<UserVerifyKeyData>>, SentcError>
{
	let verify_key = match (verify, user_id, &head.sign) {
		(true, Some(id), Some(sh)) => {
			let k = get_user_verify_key_data(base_url, app_token, id, &sh.id, c).await?;

			Some(k)
		},
		_ => None,
	};

	Ok(verify_key)
}
