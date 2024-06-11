use sentc_crypto::crypto::{done_fetch_sym_key, split_head_and_encrypted_data, split_head_and_encrypted_string};
use sentc_crypto::entities::keys::SymmetricKey;
use sentc_crypto::sdk_common::crypto::EncryptedHead;

use crate::cache::l_one::L1Cache;
use crate::error::SentcError;
use crate::group::Group;
use crate::net_helper::get_verify_key_internally_for_decrypt;

macro_rules! opt_sign {
	($self:expr, $c:expr, $sign:expr, |$sign_key:ident| $scope:block) => {
		if $sign {
			let user = $c
				.get_user(&$self.used_user_id)
				.await
				.ok_or(SentcError::UserNotFound)?;

			let user = user.read().await;

			let $sign_key = Some(user.get_newest_sign_key().ok_or(SentcError::KeyNotFound)?);
			$scope
		} else {
			let $sign_key = None;
			$scope
		}
	};
}

macro_rules! user_to_group_key {
	($self:expr, $c:expr, $key_id:expr) => {{
		let user = $c
			.get_user(&$self.used_user_id)
			.await
			.ok_or(SentcError::UserNotFound)?;

		let mut user = user.write().await;

		$crate::group::net::group_key_internally!($self, $key_id, &mut user, $c)
	}};
}

impl Group
{
	//raw encrypt

	pub async fn encrypt_raw(&self, data: &[u8], sign: bool, c: &L1Cache) -> Result<(EncryptedHead, Vec<u8>), SentcError>
	{
		opt_sign!(self, c, sign, |sign_key| {
			let key = self.get_newest_key().ok_or(SentcError::KeyNotFound)?;

			Ok(key.group_key.encrypt_raw(data, sign_key)?)
		})
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
		let key = user_to_group_key!(self, c, &head.id)?;

		let verify_key = get_verify_key_internally_for_decrypt(head, &self.base_url, &self.app_token, verify, user_id, c).await?;

		Ok(key
			.group_key
			.decrypt_raw(encrypted_data, head, verify_key.as_deref())?)
	}

	//______________________________________________________________________________________________
	//encrypt with aad

	pub async fn encrypt_raw_with_aad(&self, data: &[u8], aad: &[u8], sign: bool, c: &L1Cache) -> Result<(EncryptedHead, Vec<u8>), SentcError>
	{
		opt_sign!(self, c, sign, |sign_key| {
			let key = self.get_newest_key().ok_or(SentcError::KeyNotFound)?;

			Ok(key.group_key.encrypt_raw_with_aad(data, aad, sign_key)?)
		})
	}

	pub async fn decrypt_raw_with_aad(
		&mut self,
		head: &EncryptedHead,
		encrypted_data: &[u8],
		aad: &[u8],
		verify: bool,
		user_id: Option<&str>,
		c: &L1Cache,
	) -> Result<Vec<u8>, SentcError>
	{
		let key = user_to_group_key!(self, c, &head.id)?;

		let verify_key = get_verify_key_internally_for_decrypt(head, &self.base_url, &self.app_token, verify, user_id, c).await?;

		Ok(key
			.group_key
			.decrypt_raw_with_aad(encrypted_data, aad, head, verify_key.as_deref())?)
	}

	//______________________________________________________________________________________________

	pub async fn encrypt(&self, data: &[u8], sign: bool, c: &L1Cache) -> Result<Vec<u8>, SentcError>
	{
		opt_sign!(self, c, sign, |sign_key| {
			let key = self.get_newest_key().ok_or(SentcError::KeyNotFound)?;

			Ok(key.group_key.encrypt(data, sign_key)?)
		})
	}

	pub async fn decrypt(&mut self, data: &[u8], verify: bool, user_id: Option<&str>, c: &L1Cache) -> Result<Vec<u8>, SentcError>
	{
		let (head, data) = split_head_and_encrypted_data(data)?;

		self.decrypt_raw(&head, data, verify, user_id, c).await
	}

	//______________________________________________________________________________________________

	pub async fn encrypt_with_aad(&self, data: &[u8], aad: &[u8], sign: bool, c: &L1Cache) -> Result<Vec<u8>, SentcError>
	{
		opt_sign!(self, c, sign, |sign_key| {
			let key = self.get_newest_key().ok_or(SentcError::KeyNotFound)?;

			Ok(key.group_key.encrypt_with_aad(data, aad, sign_key)?)
		})
	}

	pub async fn decrypt_with_aad(&mut self, data: &[u8], aad: &[u8], verify: bool, user_id: Option<&str>, c: &L1Cache)
		-> Result<Vec<u8>, SentcError>
	{
		let (head, data) = split_head_and_encrypted_data(data)?;

		self.decrypt_raw_with_aad(&head, data, aad, verify, user_id, c)
			.await
	}

	//______________________________________________________________________________________________
	//encrypt string

	pub async fn encrypt_string(&self, data: &str, sign: bool, c: &L1Cache) -> Result<String, SentcError>
	{
		opt_sign!(self, c, sign, |sign_key| {
			let key = self.get_newest_key().ok_or(SentcError::KeyNotFound)?;

			Ok(key.group_key.encrypt_string(data, sign_key)?)
		})
	}

	pub async fn decrypt_string(&mut self, data: &str, verify: bool, user_id: Option<&str>, c: &L1Cache) -> Result<String, SentcError>
	{
		let head = split_head_and_encrypted_string(data)?;

		let key = user_to_group_key!(self, c, &head.id)?;

		let verify_key = get_verify_key_internally_for_decrypt(&head, &self.base_url, &self.app_token, verify, user_id, c).await?;

		Ok(key.group_key.decrypt_string(data, verify_key.as_deref())?)
	}

	//______________________________________________________________________________________________
	//encrypt string with aad

	pub async fn encrypt_string_with_aad(&self, data: &str, aad: &str, sign: bool, c: &L1Cache) -> Result<String, SentcError>
	{
		opt_sign!(self, c, sign, |sign_key| {
			let key = self.get_newest_key().ok_or(SentcError::KeyNotFound)?;

			Ok(key.group_key.encrypt_string_with_aad(data, aad, sign_key)?)
		})
	}

	pub async fn decrypt_string_with_aad(
		&mut self,
		data: &str,
		aad: &str,
		verify: bool,
		user_id: Option<&str>,
		c: &L1Cache,
	) -> Result<String, SentcError>
	{
		let head = split_head_and_encrypted_string(data)?;

		let key = user_to_group_key!(self, c, &head.id)?;

		let verify_key = get_verify_key_internally_for_decrypt(&head, &self.base_url, &self.app_token, verify, user_id, c).await?;

		Ok(key
			.group_key
			.decrypt_string_with_aad(data, aad, verify_key.as_deref())?)
	}

	//==============================================================================================
	//sym key

	pub async fn get_non_registered_key(&mut self, master_key_id: &str, server_output: &str, c: &L1Cache) -> Result<SymmetricKey, SentcError>
	{
		let key = user_to_group_key!(self, c, master_key_id)?;

		Ok(done_fetch_sym_key(&key.group_key, server_output, true)?)
	}
}
