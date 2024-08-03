use sentc_crypto::crypto::{split_head_and_encrypted_data, split_head_and_encrypted_string, KeyGenerator};
use sentc_crypto::sdk_common::crypto::{EncryptedHead, GeneratedSymKeyHeadServerOutput};
use sentc_crypto::sdk_common::user::UserVerifyKeyData;
use sentc_crypto::sdk_core::cryptomat::{PwHash, SearchableKeyGen, SortableKeyGen};
use sentc_crypto::sdk_utils::cryptomat::{
	PkFromUserKeyWrapper,
	SearchableKeyComposerWrapper,
	SignComposerWrapper,
	SignKWrapper,
	SignKeyPairWrapper,
	SortableKeyComposerWrapper,
	StaticKeyComposerWrapper,
	StaticKeyPairWrapper,
	SymKeyComposerWrapper,
	SymKeyCrypto,
	SymKeyGenWrapper,
	VerifyKFromUserKeyWrapper,
};

use crate::error::SentcError;
use crate::group::Group;

impl<SGen, StGen, SignGen, SearchGen, SortGen, SC, StC, SignC, SearchC, SortC, PC, VC, PwH>
	Group<SGen, StGen, SignGen, SearchGen, SortGen, SC, StC, SignC, SearchC, SortC, PC, VC, PwH>
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

	pub fn encrypt_raw_sync(&self, data: &[u8]) -> Result<(EncryptedHead, Vec<u8>), SentcError>
	{
		let key = self.get_newest_key().ok_or(SentcError::KeyNotFound)?;

		Ok(key.group_key.encrypt_raw(data)?)
	}

	pub fn encrypt_raw_with_sign_sync(&self, data: &[u8], sign_key: &impl SignKWrapper) -> Result<(EncryptedHead, Vec<u8>), SentcError>
	{
		let key = self.get_newest_key().ok_or(SentcError::KeyNotFound)?;

		Ok(key.group_key.encrypt_raw_with_sign(data, sign_key)?)
	}

	pub fn decrypt_raw_sync(&self, head: &EncryptedHead, encrypted_data: &[u8], verify_key: Option<&UserVerifyKeyData>)
		-> Result<Vec<u8>, SentcError>
	{
		let key = self
			.get_group_key(&head.id)
			.ok_or(SentcError::KeyRequired(head.id.to_string()))?;

		Ok(key
			.group_key
			.decrypt_raw(encrypted_data, head, verify_key)?)
	}

	//______________________________________________________________________________________________
	//raw encrypt with aad

	pub fn encrypt_raw_with_aad_sync(&self, data: &[u8], aad: &[u8]) -> Result<(EncryptedHead, Vec<u8>), SentcError>
	{
		let key = self.get_newest_key().ok_or(SentcError::KeyNotFound)?;

		Ok(key.group_key.encrypt_raw_with_aad(data, aad)?)
	}

	pub fn encrypt_raw_with_aad_with_sign_sync(
		&self,
		data: &[u8],
		aad: &[u8],
		sign_key: &impl SignKWrapper,
	) -> Result<(EncryptedHead, Vec<u8>), SentcError>
	{
		let key = self.get_newest_key().ok_or(SentcError::KeyNotFound)?;

		Ok(key
			.group_key
			.encrypt_raw_with_aad_with_sign(data, aad, sign_key)?)
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
			.ok_or(SentcError::KeyRequired(head.id.to_string()))?;

		Ok(key
			.group_key
			.decrypt_raw_with_aad(encrypted_data, aad, head, verify_key)?)
	}

	//______________________________________________________________________________________________
	//encrypt

	pub fn encrypt_sync(&self, data: &[u8]) -> Result<Vec<u8>, SentcError>
	{
		let key = self.get_newest_key().ok_or(SentcError::KeyNotFound)?;

		Ok(key.group_key.encrypt(data)?)
	}

	pub fn encrypt_with_sign_sync(&self, data: &[u8], sign_key: &impl SignKWrapper) -> Result<Vec<u8>, SentcError>
	{
		let key = self.get_newest_key().ok_or(SentcError::KeyNotFound)?;

		Ok(key.group_key.encrypt_with_sign(data, sign_key)?)
	}

	pub fn decrypt_sync(&self, data: &[u8], verify_key: Option<&UserVerifyKeyData>) -> Result<Vec<u8>, SentcError>
	{
		let (head, data) = split_head_and_encrypted_data(data)?;

		self.decrypt_raw_sync(&head, data, verify_key)
	}

	//______________________________________________________________________________________________
	//encrypt with aad

	pub fn encrypt_with_aad_sync(&self, data: &[u8], aad: &[u8]) -> Result<Vec<u8>, SentcError>
	{
		let key = self.get_newest_key().ok_or(SentcError::KeyNotFound)?;

		Ok(key.group_key.encrypt_with_aad(data, aad)?)
	}

	pub fn encrypt_with_aad_with_sign_sync(&self, data: &[u8], aad: &[u8], sign_key: &impl SignKWrapper) -> Result<Vec<u8>, SentcError>
	{
		let key = self.get_newest_key().ok_or(SentcError::KeyNotFound)?;

		Ok(key
			.group_key
			.encrypt_with_aad_with_sign(data, aad, sign_key)?)
	}

	pub fn decrypt_with_aad_sync(&self, data: &[u8], aad: &[u8], verify_key: Option<&UserVerifyKeyData>) -> Result<Vec<u8>, SentcError>
	{
		let (head, data) = split_head_and_encrypted_data(data)?;

		self.decrypt_raw_with_aad_sync(&head, data, aad, verify_key)
	}

	//______________________________________________________________________________________________
	//encrypt string

	pub fn encrypt_string_sync(&self, data: &str) -> Result<String, SentcError>
	{
		let key = self.get_newest_key().ok_or(SentcError::KeyNotFound)?;

		Ok(key.group_key.encrypt_string(data)?)
	}

	pub fn encrypt_string_with_sign_sync(&self, data: &str, sign_key: &impl SignKWrapper) -> Result<String, SentcError>
	{
		let key = self.get_newest_key().ok_or(SentcError::KeyNotFound)?;

		Ok(key.group_key.encrypt_string_with_sign(data, sign_key)?)
	}

	pub fn decrypt_string_sync(&self, data: &str, verify_key: Option<&UserVerifyKeyData>) -> Result<String, SentcError>
	{
		let head = split_head_and_encrypted_string(data)?;

		let key = self
			.get_group_key(&head.id)
			.ok_or(SentcError::KeyRequired(head.id.to_string()))?;

		Ok(key.group_key.decrypt_string(data, verify_key)?)
	}

	//______________________________________________________________________________________________
	//encrypt string with aad

	pub fn encrypt_string_with_aad_sync(&self, data: &str, aad: &str) -> Result<String, SentcError>
	{
		let key = self.get_newest_key().ok_or(SentcError::KeyNotFound)?;

		Ok(key.group_key.encrypt_string_with_aad(data, aad)?)
	}

	pub fn encrypt_string_with_aad_with_sign_sync(&self, data: &str, aad: &str, sign_key: &impl SignKWrapper) -> Result<String, SentcError>
	{
		let key = self.get_newest_key().ok_or(SentcError::KeyNotFound)?;

		Ok(key
			.group_key
			.encrypt_string_with_aad_with_sign(data, aad, sign_key)?)
	}

	pub fn decrypt_string_with_aad_sync(&self, data: &str, aad: &str, verify_key: Option<&UserVerifyKeyData>) -> Result<String, SentcError>
	{
		let head = split_head_and_encrypted_string(data)?;

		let key = self
			.get_group_key(&head.id)
			.ok_or(SentcError::KeyRequired(head.id.to_string()))?;

		Ok(key
			.group_key
			.decrypt_string_with_aad(data, aad, verify_key)?)
	}

	//==============================================================================================
	//sym key

	pub fn generate_non_registered_key(&self) -> Result<(SGen::SymmetricKeyWrapper, GeneratedSymKeyHeadServerOutput), SentcError>
	{
		let key = self.get_newest_key().ok_or(SentcError::KeyNotFound)?;

		let (raw_key, key_out) = KeyGenerator::<SGen, SC, PC>::generate_non_register_sym_key(&key.group_key)?;

		Ok((raw_key, key_out))
	}

	pub fn get_non_registered_key_sync(&self, master_key_id: &str, server_output: &str) -> Result<SC::SymmetricKeyWrapper, SentcError>
	{
		let key = self
			.get_group_key(master_key_id)
			.ok_or(SentcError::KeyRequired(master_key_id.to_string()))?;

		Ok(KeyGenerator::<SGen, SC, PC>::done_fetch_sym_key(
			&key.group_key,
			server_output,
			true,
		)?)
	}
}
