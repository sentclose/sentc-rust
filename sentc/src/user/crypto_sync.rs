use sentc_crypto::crypto::{
	decrypt_raw_asymmetric,
	decrypt_string_asymmetric,
	done_fetch_sym_key_by_private_key,
	encrypt_asymmetric,
	encrypt_raw_asymmetric,
	encrypt_string_asymmetric,
	generate_non_register_sym_key_by_public_key,
	split_head_and_encrypted_data,
	split_head_and_encrypted_string,
};
use sentc_crypto::entities::keys::SymKeyFormatInt;
use sentc_crypto::sdk_common::crypto::EncryptedHead;
use sentc_crypto::sdk_common::user::{UserPublicKeyData, UserVerifyKeyData};

use crate::error::SentcError;
use crate::user::User;

impl User
{
	//raw encrypt

	pub fn encrypt_raw_sync(&self, data: &[u8], reply_key: &UserPublicKeyData, sign: bool) -> Result<(EncryptedHead, Vec<u8>), SentcError>
	{
		let sign_key = if sign { self.get_newest_sign_key() } else { None };

		Ok(encrypt_raw_asymmetric(reply_key, data, sign_key)?)
	}

	pub fn decrypt_raw_sync(&self, head: &EncryptedHead, encrypted_data: &[u8], verify_key: Option<&UserVerifyKeyData>)
		-> Result<Vec<u8>, SentcError>
	{
		let key = self
			.get_user_keys(&head.id)
			.ok_or(SentcError::KeyNotFound)?;

		Ok(decrypt_raw_asymmetric(
			&key.private_key,
			encrypted_data,
			head,
			verify_key,
		)?)
	}

	//______________________________________________________________________________________________
	//encrypt

	pub fn encrypt_sync(&self, data: &[u8], reply_key: &UserPublicKeyData, sign: bool) -> Result<Vec<u8>, SentcError>
	{
		let sign_key = if sign { self.get_newest_sign_key() } else { None };

		Ok(encrypt_asymmetric(reply_key, data, sign_key)?)
	}

	pub fn decrypt_sync(&self, data: &[u8], verify_key: Option<&UserVerifyKeyData>) -> Result<Vec<u8>, SentcError>
	{
		let (head, data) = split_head_and_encrypted_data(data)?;

		self.decrypt_raw_sync(&head, data, verify_key)
	}

	//______________________________________________________________________________________________
	//encrypt string

	pub fn encrypt_string_sync(&self, data: &str, reply_key: &UserPublicKeyData, sign: bool) -> Result<String, SentcError>
	{
		let sign_key = if sign { self.get_newest_sign_key() } else { None };

		Ok(encrypt_string_asymmetric(reply_key, data, sign_key)?)
	}

	pub fn decrypt_string_sync(&self, data: &str, verify_key: Option<&UserVerifyKeyData>) -> Result<String, SentcError>
	{
		let head = split_head_and_encrypted_string(data)?;

		let key = self
			.get_user_keys(&head.id)
			.ok_or(SentcError::KeyNotFound)?;

		Ok(decrypt_string_asymmetric(&key.private_key, data, verify_key)?)
	}

	//==============================================================================================
	//sym key

	pub fn generate_non_registered_key(&self, reply_key: &UserPublicKeyData) -> Result<(SymKeyFormatInt, String), SentcError>
	{
		let (raw_key, key_out) = generate_non_register_sym_key_by_public_key(reply_key)?;

		Ok((
			raw_key,
			key_out
				.to_string()
				.map_err(|_| SentcError::JsonToStringFailed)?,
		))
	}

	pub fn get_non_registered_key_sync(&self, master_key_id: &str, server_out: &str) -> Result<SymKeyFormatInt, SentcError>
	{
		let key = self
			.get_user_keys(master_key_id)
			.ok_or(SentcError::KeyNotFound)?;

		Ok(done_fetch_sym_key_by_private_key(&key.private_key, server_out, true)?)
	}
}
