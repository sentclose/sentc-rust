use sentc_crypto::crypto::{split_head_and_encrypted_data, split_head_and_encrypted_string, KeyGenerator};
use sentc_crypto::sdk_common::crypto::EncryptedHead;
use sentc_crypto::sdk_common::user::{UserPublicKeyData, UserVerifyKeyData};
use sentc_crypto::sdk_core::cryptomat::{PwHash, SearchableKeyGen, SortableKeyGen};
use sentc_crypto::sdk_utils::cryptomat::{
	PkFromUserKeyWrapper,
	SearchableKeyComposerWrapper,
	SignComposerWrapper,
	SignKeyPairWrapper,
	SkCryptoWrapper,
	SortableKeyComposerWrapper,
	StaticKeyComposerWrapper,
	StaticKeyPairWrapper,
	SymKeyComposerWrapper,
	SymKeyGenWrapper,
	VerifyKFromUserKeyWrapper,
};

use crate::crypto_common::crypto::GeneratedSymKeyHeadServerOutput;
use crate::error::SentcError;
use crate::user::User;

impl<SGen, StGen, SignGen, SearchGen, SortGen, SC, StC, SignC, SearchC, SortC, PC, VC, PwH>
	User<SGen, StGen, SignGen, SearchGen, SortGen, SC, StC, SignC, SearchC, SortC, PC, VC, PwH>
where
	SGen: SymKeyGenWrapper,
	StGen: StaticKeyPairWrapper,
	SignGen: SignKeyPairWrapper,
	SearchGen: SearchableKeyGen,
	SortGen: SortableKeyGen,
	SC: SymKeyComposerWrapper,
	StC: StaticKeyComposerWrapper,
	SignC: SignComposerWrapper,
	SearchC: SearchableKeyComposerWrapper,
	SortC: SortableKeyComposerWrapper,
	PC: PkFromUserKeyWrapper,
	VC: VerifyKFromUserKeyWrapper,
	PwH: PwHash,
{
	//raw encrypt

	pub fn encrypt_raw_sync(&self, data: &[u8], reply_key: &UserPublicKeyData, sign: bool) -> Result<(EncryptedHead, Vec<u8>), SentcError>
	{
		if sign {
			let sign_key = self.get_newest_sign_key().ok_or(SentcError::KeyNotFound)?;

			Ok(PC::encrypt_raw_with_user_key_with_sign(reply_key, data, sign_key)?)
		} else {
			Ok(PC::encrypt_raw_with_user_key(reply_key, data)?)
		}
	}

	pub fn decrypt_raw_sync(&self, head: &EncryptedHead, encrypted_data: &[u8], verify_key: Option<&UserVerifyKeyData>)
		-> Result<Vec<u8>, SentcError>
	{
		let key = self
			.get_user_keys(&head.id)
			.ok_or(SentcError::KeyNotFound)?;

		Ok(key
			.private_key
			.decrypt_raw(encrypted_data, head, verify_key)?)
	}

	//______________________________________________________________________________________________
	//encrypt

	pub fn encrypt_sync(&self, data: &[u8], reply_key: &UserPublicKeyData, sign: bool) -> Result<Vec<u8>, SentcError>
	{
		if sign {
			let sign_key = self.get_newest_sign_key().ok_or(SentcError::KeyNotFound)?;

			Ok(PC::encrypt_with_user_key_with_sign(reply_key, data, sign_key)?)
		} else {
			Ok(PC::encrypt_with_user_key(reply_key, data)?)
		}
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
		if sign {
			let sign_key = self.get_newest_sign_key().ok_or(SentcError::KeyNotFound)?;

			Ok(PC::encrypt_string_with_user_key_with_sign(reply_key, data, sign_key)?)
		} else {
			Ok(PC::encrypt_string_with_user_key(reply_key, data)?)
		}
	}

	pub fn decrypt_string_sync(&self, data: &str, verify_key: Option<&UserVerifyKeyData>) -> Result<String, SentcError>
	{
		let head = split_head_and_encrypted_string(data)?;

		let key = self
			.get_user_keys(&head.id)
			.ok_or(SentcError::KeyNotFound)?;

		Ok(key.private_key.decrypt_string(data, verify_key)?)
	}

	//==============================================================================================
	//sym key

	pub fn generate_non_registered_key(
		&self,
		reply_key: &UserPublicKeyData,
	) -> Result<(SGen::SymmetricKeyWrapper, GeneratedSymKeyHeadServerOutput), SentcError>
	{
		let (raw_key, key_out) = KeyGenerator::<SGen, SC, PC>::generate_non_register_sym_key_by_public_key(reply_key)?;

		Ok((raw_key, key_out))
	}

	pub fn get_non_registered_key_sync(&self, master_key_id: &str, server_out: &str) -> Result<SC::SymmetricKeyWrapper, SentcError>
	{
		let key = self
			.get_user_keys(master_key_id)
			.ok_or(SentcError::KeyNotFound)?;

		Ok(KeyGenerator::<SGen, SC, PC>::done_fetch_sym_key_by_private_key(
			&key.private_key,
			server_out,
			true,
		)?)
	}
}
