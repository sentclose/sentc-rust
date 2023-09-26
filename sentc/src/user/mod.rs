pub mod crypto_sync;
#[cfg(feature = "network")]
pub mod net;

use sentc_crypto::entities::keys::{
	HmacKeyFormatInt,
	PrivateKeyFormatInt,
	PublicKeyFormatInt,
	SignKeyFormatInt,
	SymKeyFormatInt,
	VerifyKeyFormatInt,
};
use sentc_crypto::entities::user::{UserDataInt, UserKeyDataInt};
use sentc_crypto::group::prepare_create;
use sentc_crypto::sdk_common::group::GroupHmacData;
use sentc_crypto::sdk_common::user::{UserPublicKeyData, UserVerifyKeyData};
use sentc_crypto::sdk_common::{DeviceId, SymKeyId, UserId};
use sentc_crypto::user::prepare_register_device;

use crate::error::SentcError;
use crate::group::prepare_group_keys_ref;
use crate::{decrypt_hmac_key, KeyMap};

pub struct User
{
	user_id: UserId,
	user_identifier: String,
	device_id: DeviceId,

	jwt: String,
	refresh_token: String,

	mfa: bool,

	//device keys
	private_device_key: PrivateKeyFormatInt,
	public_device_key: PublicKeyFormatInt,
	sign_device_key: SignKeyFormatInt,
	verify_device_key: VerifyKeyFormatInt,
	exported_verify_device_key: UserVerifyKeyData,
	exported_public_device_key: UserPublicKeyData,

	//user keys
	user_keys: Vec<UserKeyDataInt>,
	key_map: KeyMap,
	newest_key_id: SymKeyId,
	hmac_keys: Vec<HmacKeyFormatInt>,

	base_url: String,
	app_token: String,
}

impl User
{
	fn new_user(
		base_url: String,
		app_token: String,
		user_identifier: String,
		data: UserDataInt,
		mfa: bool,
	) -> Result<(Self, Vec<GroupHmacData>), SentcError>
	{
		let newest_key_id = data
			.user_keys
			.get(0)
			.ok_or(SentcError::KeyNotFound)?
			.group_key
			.key_id
			.clone();

		let mut key_map: KeyMap = Default::default();

		for (i, key) in data.user_keys.iter().enumerate() {
			key_map.insert(key.group_key.key_id.clone(), i);
		}

		Ok((
			Self {
				user_id: data.user_id,
				user_identifier,
				device_id: data.device_id,
				jwt: data.jwt,
				refresh_token: data.refresh_token,
				mfa,
				private_device_key: data.device_keys.private_key,
				public_device_key: data.device_keys.public_key,
				sign_device_key: data.device_keys.sign_key,
				verify_device_key: data.device_keys.verify_key,
				exported_verify_device_key: data.device_keys.exported_verify_key,
				exported_public_device_key: data.device_keys.exported_public_key,
				user_keys: data.user_keys,
				key_map,
				newest_key_id,
				hmac_keys: Vec::with_capacity(data.hmac_keys.len()),
				base_url,
				app_token,
			},
			data.hmac_keys,
		))
	}

	#[cfg(not(feature = "network"))]
	#[allow(clippy::too_many_arguments)]
	pub fn new(base_url: String, app_token: String, user_identifier: String, data: UserDataInt, mfa: bool) -> Result<Self, SentcError>
	{
		let (mut u, hmac_keys) = Self::new_user(base_url, app_token, user_identifier, data, mfa)?;

		u.decrypt_hmac_keys_sync(hmac_keys)?;

		Ok(u)
	}

	pub fn get_user_id(&self) -> &str
	{
		&self.user_id
	}

	pub fn get_identifier(&self) -> &str
	{
		&self.user_identifier
	}

	pub fn get_device_id(&self) -> &str
	{
		&self.device_id
	}

	pub fn get_jwt_sync(&self) -> &str
	{
		&self.jwt
	}

	pub fn get_refresh_token(&self) -> &str
	{
		&self.refresh_token
	}

	pub fn get_newest_key(&self) -> Option<&UserKeyDataInt>
	{
		let index = self.key_map.get(&self.newest_key_id).unwrap_or(&0);

		self.user_keys.get(*index)
	}

	pub fn get_newest_public_key(&self) -> Option<&PublicKeyFormatInt>
	{
		self.get_newest_key().map(|k| &k.public_key)
	}

	pub fn get_newest_sign_key(&self) -> Option<&SignKeyFormatInt>
	{
		self.get_newest_key().map(|k| &k.sign_key)
	}

	pub fn set_jwt(&mut self, jwt: String)
	{
		self.jwt = jwt;
	}

	pub fn set_refresh_token(&mut self, refresh_token: String)
	{
		self.refresh_token = refresh_token;
	}

	pub fn get_user_keys(&self, key_id: &str) -> Option<&UserKeyDataInt>
	{
		self.key_map
			.get(key_id)
			.and_then(|k| self.user_keys.get(*k))
	}

	pub fn prepare_register_device_keys(&self, sever_output: &str) -> Result<(String, UserPublicKeyData), SentcError>
	{
		let (keys, _) = self.prepare_group_keys_ref(0);

		let key_session = self.user_keys.len() > 50;

		Ok(prepare_register_device(sever_output, &keys, key_session)?)
	}

	pub fn get_mfa(&self) -> bool
	{
		self.mfa
	}

	pub(crate) fn prepare_group_keys_ref(&self, page: usize) -> (Vec<&SymKeyFormatInt>, bool)
	{
		prepare_group_keys_ref!(self.user_keys, page, 50)
	}

	pub fn get_private_device_key(&self) -> &PrivateKeyFormatInt
	{
		&self.private_device_key
	}

	pub fn get_public_device_key(&self) -> &PublicKeyFormatInt
	{
		&self.public_device_key
	}

	pub fn get_verify_device_key(&self) -> &VerifyKeyFormatInt
	{
		&self.verify_device_key
	}

	pub fn get_exported_verify_device_key(&self) -> &UserVerifyKeyData
	{
		&self.exported_verify_device_key
	}

	pub fn get_exported_public_device_key(&self) -> &UserPublicKeyData
	{
		&self.exported_public_device_key
	}

	#[cfg(not(feature = "network"))]
	fn decrypt_hmac_keys_sync(&mut self, hmac_keys: Vec<GroupHmacData>) -> Result<(), SentcError>
	{
		for hmac_key in hmac_keys {
			let key = self
				.get_user_keys(&hmac_key.encrypted_hmac_encryption_key_id)
				.ok_or(SentcError::KeyNotFound)?;

			decrypt_hmac_key!(&key.group_key, self, hmac_key);
		}

		Ok(())
	}

	pub fn set_hmac_key(&mut self, user_key: &UserKeyDataInt, hmac_key: GroupHmacData) -> Result<(), SentcError>
	{
		decrypt_hmac_key!(&user_key.group_key, self, hmac_key);

		Ok(())
	}

	pub fn prepare_create_group(&self) -> Result<String, SentcError>
	{
		Ok(prepare_create(
			self.get_newest_public_key()
				.ok_or(SentcError::KeyNotFound)?,
		)?)
	}

	fn set_newest_key_id(&mut self, id: SymKeyId)
	{
		self.newest_key_id = id;
	}

	fn extend_user_key(&mut self, user_keys: UserKeyDataInt)
	{
		//keys are already decrypted from the sentc full sdk and the private device key
		self.key_map
			.insert(user_keys.group_key.key_id.clone(), self.user_keys.len());
		self.user_keys.push(user_keys);
	}
}
