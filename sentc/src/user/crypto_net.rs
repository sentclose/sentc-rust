use sentc_crypto::crypto::{done_fetch_sym_key_by_private_key, split_head_and_encrypted_data, split_head_and_encrypted_string};
use sentc_crypto::entities::keys::{PublicKey, SymmetricKey};
use sentc_crypto::sdk_common::crypto::EncryptedHead;

use crate::cache::l_one::L1Cache;
use crate::error::SentcError;
use crate::net_helper::{get_user_public_key_data, get_verify_key_internally_for_decrypt};
use crate::user::User;

macro_rules! get_user_key {
	($self:expr, $key_id:expr, $c:expr) => {
		match $self.get_user_keys($key_id) {
			Some(k) => k,
			None => {
				$self.fetch_user_key_internally($key_id, false, $c).await?;

				$self
					.get_user_keys($key_id)
					.ok_or(SentcError::KeyNotFound)?
			},
		}
	};
}

impl User
{
	pub async fn encrypt_raw(&self, data: &[u8], reply_id: &str, sign: bool, c: &L1Cache) -> Result<(EncryptedHead, Vec<u8>), SentcError>
	{
		let sign_key = if sign { self.get_newest_sign_key() } else { None };

		let reply_key = get_user_public_key_data(&self.base_url, &self.app_token, reply_id, c).await?;

		Ok(PublicKey::encrypt_raw_with_user_key(&reply_key, data, sign_key)?)
	}

	pub async fn decrypt_raw(
		&mut self,
		head: &EncryptedHead,
		encrypted_data: &[u8],
		verify: bool,
		user_id: Option<&str>,
		c: &L1Cache,
	) -> Result<Vec<u8>, SentcError>
	{
		let verify_key = get_verify_key_internally_for_decrypt(head, &self.base_url, &self.app_token, verify, user_id, c).await?;

		let key = get_user_key!(self, &head.id, c);

		Ok(key
			.private_key
			.decrypt_raw(encrypted_data, head, verify_key.as_deref())?)
	}

	//______________________________________________________________________________________________
	//encrypt

	pub async fn encrypt(&self, data: &[u8], reply_id: &str, sign: bool, c: &L1Cache) -> Result<Vec<u8>, SentcError>
	{
		let sign_key = if sign { self.get_newest_sign_key() } else { None };
		let reply_key = get_user_public_key_data(&self.base_url, &self.app_token, reply_id, c).await?;

		Ok(PublicKey::encrypt_with_user_key(&reply_key, data, sign_key)?)
	}

	pub async fn decrypt(&mut self, data: &[u8], verify: bool, user_id: Option<&str>, c: &L1Cache) -> Result<Vec<u8>, SentcError>
	{
		let (head, data) = split_head_and_encrypted_data(data)?;

		self.decrypt_raw(&head, data, verify, user_id, c).await
	}

	//______________________________________________________________________________________________
	//encrypt string

	pub async fn encrypt_string(&self, data: &str, reply_id: &str, sign: bool, c: &L1Cache) -> Result<String, SentcError>
	{
		let sign_key = if sign { self.get_newest_sign_key() } else { None };
		let reply_key = get_user_public_key_data(&self.base_url, &self.app_token, reply_id, c).await?;

		Ok(PublicKey::encrypt_string_with_user_key(&reply_key, data, sign_key)?)
	}

	pub async fn decrypt_string(&mut self, data: &str, verify: bool, user_id: Option<&str>, c: &L1Cache) -> Result<String, SentcError>
	{
		let head = split_head_and_encrypted_string(data)?;

		let verify_key = get_verify_key_internally_for_decrypt(&head, &self.base_url, &self.app_token, verify, user_id, c).await?;

		let key = get_user_key!(self, &head.id, c);

		Ok(key
			.private_key
			.decrypt_string(data, verify_key.as_deref())?)
	}

	//==============================================================================================
	//sym key

	pub async fn get_non_registered_key(&mut self, master_key_id: &str, server_output: &str, c: &L1Cache) -> Result<SymmetricKey, SentcError>
	{
		let key = get_user_key!(self, master_key_id, c);

		Ok(done_fetch_sym_key_by_private_key(
			&key.private_key,
			server_output,
			true,
		)?)
	}
}
