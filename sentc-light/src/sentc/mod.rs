#[cfg(feature = "network")]
pub mod net;

use sentc_crypto_light::sdk_common::UserId;
use sentc_crypto_light::user::{done_register_device_start, generate_user_register_data};

use crate::error::SentcError;

pub struct Sentc
{
	base_url: String,
	app_token: String,

	#[cfg(feature = "network")]
	cache: crate::cache::l_one::L1Cache,
}

impl Sentc
{
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
		Self::prepare_register(device_identifier, password)
	}

	pub fn done_register_device_start(server_output: &str) -> Result<(), SentcError>
	{
		Ok(done_register_device_start(server_output)?)
	}
}
