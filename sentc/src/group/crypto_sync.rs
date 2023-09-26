use sentc_crypto::crypto::{
	decrypt_raw_symmetric,
	decrypt_raw_symmetric_with_aad,
	decrypt_string_symmetric,
	decrypt_string_symmetric_with_aad,
	done_fetch_sym_key,
	encrypt_raw_symmetric,
	encrypt_raw_symmetric_with_aad,
	encrypt_string_symmetric,
	encrypt_string_symmetric_with_aad,
	encrypt_symmetric,
	encrypt_symmetric_with_aad,
	generate_non_register_sym_key,
	split_head_and_encrypted_data,
	split_head_and_encrypted_string,
};
use sentc_crypto::entities::keys::{SignKeyFormatInt, SymKeyFormatInt};
use sentc_crypto::sdk_common::crypto::EncryptedHead;
use sentc_crypto::sdk_common::user::UserVerifyKeyData;

use crate::error::SentcError;
use crate::group::Group;

impl Group
{
	//raw encrypt

	pub fn encrypt_raw_sync(&self, data: &[u8], sign_key: Option<&SignKeyFormatInt>) -> Result<(EncryptedHead, Vec<u8>), SentcError>
	{
		let key = self.get_newest_key().ok_or(SentcError::KeyNotFound)?;

		Ok(encrypt_raw_symmetric(&key.group_key, data, sign_key)?)
	}

	pub fn decrypt_raw_sync(&self, head: &EncryptedHead, encrypted_data: &[u8], verify_key: Option<&UserVerifyKeyData>)
		-> Result<Vec<u8>, SentcError>
	{
		let key = self
			.get_group_key(&head.id)
			.ok_or(SentcError::KeyNotFound)?;

		Ok(decrypt_raw_symmetric(
			&key.group_key,
			encrypted_data,
			head,
			verify_key,
		)?)
	}

	//______________________________________________________________________________________________
	//raw encrypt with aad

	pub fn encrypt_raw_with_aad_sync(
		&self,
		data: &[u8],
		aad: &[u8],
		sign_key: Option<&SignKeyFormatInt>,
	) -> Result<(EncryptedHead, Vec<u8>), SentcError>
	{
		let key = self.get_newest_key().ok_or(SentcError::KeyNotFound)?;

		Ok(encrypt_raw_symmetric_with_aad(&key.group_key, data, aad, sign_key)?)
	}

	pub fn decrypt_raw_with_aad_sync(
		&self,
		head: &EncryptedHead,
		encrypted_data: &[u8],
		aad: &[u8],
		verify_key: Option<&UserVerifyKeyData>,
	) -> Result<Vec<u8>, SentcError>
	{
		let key = self
			.get_group_key(&head.id)
			.ok_or(SentcError::KeyNotFound)?;

		Ok(decrypt_raw_symmetric_with_aad(
			&key.group_key,
			encrypted_data,
			head,
			aad,
			verify_key,
		)?)
	}

	//______________________________________________________________________________________________
	//encrypt

	pub fn encrypt_sync(&self, data: &[u8], sign_key: Option<&SignKeyFormatInt>) -> Result<Vec<u8>, SentcError>
	{
		let key = self.get_newest_key().ok_or(SentcError::KeyNotFound)?;

		Ok(encrypt_symmetric(&key.group_key, data, sign_key)?)
	}

	pub fn decrypt_sync(&self, data: &[u8], verify_key: Option<&UserVerifyKeyData>) -> Result<Vec<u8>, SentcError>
	{
		let (head, data) = split_head_and_encrypted_data(data)?;

		self.decrypt_raw_sync(&head, data, verify_key)
	}

	//______________________________________________________________________________________________
	//encrypt with aad

	pub fn encrypt_with_aad_sync(&self, data: &[u8], aad: &[u8], sign_key: Option<&SignKeyFormatInt>) -> Result<Vec<u8>, SentcError>
	{
		let key = self.get_newest_key().ok_or(SentcError::KeyNotFound)?;

		Ok(encrypt_symmetric_with_aad(&key.group_key, data, aad, sign_key)?)
	}

	pub fn decrypt_with_aad_sync(&self, data: &[u8], aad: &[u8], verify_key: Option<&UserVerifyKeyData>) -> Result<Vec<u8>, SentcError>
	{
		let (head, data) = split_head_and_encrypted_data(data)?;

		self.decrypt_raw_with_aad_sync(&head, data, aad, verify_key)
	}

	//______________________________________________________________________________________________
	//encrypt string

	pub fn encrypt_string_sync(&self, data: &str, sign_key: Option<&SignKeyFormatInt>) -> Result<String, SentcError>
	{
		let key = self.get_newest_key().ok_or(SentcError::KeyNotFound)?;

		Ok(encrypt_string_symmetric(&key.group_key, data, sign_key)?)
	}

	pub fn decrypt_string_sync(&self, data: &str, verify_key: Option<&UserVerifyKeyData>) -> Result<String, SentcError>
	{
		let head = split_head_and_encrypted_string(data)?;

		let key = self
			.get_group_key(&head.id)
			.ok_or(SentcError::KeyNotFound)?;

		Ok(decrypt_string_symmetric(&key.group_key, data, verify_key)?)
	}

	//______________________________________________________________________________________________
	//encrypt string with aad

	pub fn encrypt_string_with_aad_sync(&self, data: &str, aad: &str, sign_key: Option<&SignKeyFormatInt>) -> Result<String, SentcError>
	{
		let key = self.get_newest_key().ok_or(SentcError::KeyNotFound)?;

		Ok(encrypt_string_symmetric_with_aad(
			&key.group_key,
			data,
			aad,
			sign_key,
		)?)
	}

	pub fn decrypt_string_with_aad_sync(&self, data: &str, aad: &str, verify_key: Option<&UserVerifyKeyData>) -> Result<String, SentcError>
	{
		let head = split_head_and_encrypted_string(data)?;

		let key = self
			.get_group_key(&head.id)
			.ok_or(SentcError::KeyNotFound)?;

		Ok(decrypt_string_symmetric_with_aad(
			&key.group_key,
			data,
			aad,
			verify_key,
		)?)
	}

	//==============================================================================================
	//sym key

	pub fn generate_non_registered_key(&self) -> Result<(SymKeyFormatInt, String), SentcError>
	{
		let key = self.get_newest_key().ok_or(SentcError::KeyNotFound)?;

		let (raw_key, key_out) = generate_non_register_sym_key(&key.group_key)?;

		Ok((
			raw_key,
			key_out
				.to_string()
				.map_err(|_| SentcError::JsonToStringFailed)?,
		))
	}

	pub fn get_non_registered_key_sync(&self, master_key_id: &str, server_output: &str) -> Result<SymKeyFormatInt, SentcError>
	{
		let key = self
			.get_group_key(master_key_id)
			.ok_or(SentcError::KeyNotFound)?;

		Ok(done_fetch_sym_key(&key.group_key, server_output, true)?)
	}
}
