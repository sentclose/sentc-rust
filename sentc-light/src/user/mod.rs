#[cfg(feature = "network")]
pub mod net;

use sentc_crypto_light::sdk_common::user::{UserPublicKeyData, UserVerifyKeyData};
use sentc_crypto_light::sdk_common::{DeviceId, UserId};
use sentc_crypto_light::sdk_keys::util::{PublicKey, SecretKey, SignKey, VerifyKey};
use sentc_crypto_light::user::{generate_user_register_data, prepare_register_device};
use sentc_crypto_light::UserDataInt;

use crate::error::SentcError;

pub struct User
{
	user_id: UserId,
	user_identifier: String,
	device_id: DeviceId,

	jwt: String,
	refresh_token: String,

	mfa: bool,

	//device keys
	private_device_key: SecretKey,
	public_device_key: PublicKey,
	sign_device_key: SignKey,
	verify_device_key: VerifyKey,
	exported_verify_device_key: UserVerifyKeyData,
	exported_public_device_key: UserPublicKeyData,

	base_url: String,
	app_token: String,
}

impl User
{
	fn new_user(base_url: String, app_token: String, user_identifier: String, data: UserDataInt, mfa: bool) -> Result<Self, SentcError>
	{
		Ok(Self {
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

			base_url,
			app_token,
		})
	}

	#[cfg(not(feature = "network"))]
	pub fn new(base_url: String, app_token: String, user_identifier: String, data: UserDataInt, mfa: bool) -> Result<Self, SentcError>
	{
		Self::new_user(base_url, app_token, user_identifier, data, mfa)
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

	pub fn set_jwt(&mut self, jwt: String)
	{
		self.jwt = jwt;
	}

	pub fn set_refresh_token(&mut self, refresh_token: String)
	{
		self.refresh_token = refresh_token;
	}

	pub fn prepare_register_device_keys(&self, sever_output: &str) -> Result<String, SentcError>
	{
		Ok(prepare_register_device(sever_output)?)
	}

	pub fn get_mfa(&self) -> bool
	{
		self.mfa
	}

	pub fn get_private_device_key(&self) -> &SecretKey
	{
		&self.private_device_key
	}

	pub fn get_public_device_key(&self) -> &PublicKey
	{
		&self.public_device_key
	}

	pub fn get_verify_device_key(&self) -> &VerifyKey
	{
		&self.verify_device_key
	}

	pub fn get_sign_device_key(&self) -> &SignKey
	{
		&self.sign_device_key
	}

	pub fn get_exported_verify_device_key(&self) -> &UserVerifyKeyData
	{
		&self.exported_verify_device_key
	}

	pub fn get_exported_public_device_key(&self) -> &UserPublicKeyData
	{
		&self.exported_public_device_key
	}
}

pub fn generate_register_data() -> Result<(String, String), SentcError>
{
	Ok(generate_user_register_data()?)
}

pub fn prepare_register(user_identifier: &str, password: &str) -> Result<String, SentcError>
{
	if user_identifier.is_empty() || password.is_empty() {
		return Err(SentcError::UsernameOrPasswordRequired);
	}

	Ok(sentc_crypto_light::user::register(user_identifier, password)?)
}

pub fn done_register(server_output: &str) -> Result<UserId, SentcError>
{
	Ok(sentc_crypto_light::user::done_register(server_output)?)
}

pub fn prepare_register_device_start(device_identifier: &str, password: &str) -> Result<String, SentcError>
{
	prepare_register(device_identifier, password)
}

pub fn done_register_device_start(server_output: &str) -> Result<(), SentcError>
{
	Ok(sentc_crypto_light::user::done_register_device_start(server_output)?)
}
