use std::str::FromStr;

use sentc_crypto_light::error::SdkLightError;
use sentc_crypto_light::sdk_common::user::{UserPublicKeyData, UserVerifyKeyData};
use sentc_crypto_light::sdk_common::{DeviceId, UserId};
use sentc_crypto_light::sdk_utils::cryptomat::KeyToString;
use sentc_crypto_light::sdk_utils::error::SdkUtilError;
use sentc_crypto_light::sdk_utils::user::DeviceKeyDataInt;
use sentc_crypto_light::{DeviceKeyDataExport, UserDataInt};
use serde::{Deserialize, Serialize};

use crate::error::SentcError;
use crate::user::User;

#[derive(Serialize, Deserialize)]
pub struct UserExportData
{
	jwt: String,
	refresh_token: String,
	user_id: UserId,
	user_identifier: String,
	device_id: DeviceId,
	mfa: bool,
	base_url: String,
	app_token: String,

	device_keys: DeviceKeyDataExport,
}

impl TryFrom<User> for UserExportData
{
	type Error = SentcError;

	fn try_from(value: User) -> Result<Self, Self::Error>
	{
		Ok(Self {
			jwt: value.jwt,
			refresh_token: value.refresh_token,
			user_id: value.user_id,
			user_identifier: value.user_identifier,
			device_id: value.device_id,
			mfa: value.mfa,
			base_url: value.base_url,
			app_token: value.app_token,
			device_keys: DeviceKeyDataExport {
				private_key: value.private_device_key.to_string()?,
				sign_key: value.sign_device_key.to_string()?,
				public_key: value.public_device_key.to_string()?,
				verify_key: value.verify_device_key.to_string()?,
				exported_public_key: value.exported_public_device_key.to_string()?,
				exported_verify_key: value.exported_verify_device_key.to_string()?,
			},
		})
	}
}

impl<'a> TryFrom<&'a User> for UserExportData
{
	type Error = SentcError;

	fn try_from(value: &'a User) -> Result<Self, Self::Error>
	{
		Ok(Self {
			jwt: value.jwt.clone(),
			refresh_token: value.refresh_token.clone(),
			user_id: value.user_id.clone(),
			user_identifier: value.user_identifier.clone(),
			device_id: value.device_id.clone(),
			mfa: value.mfa,
			base_url: value.base_url.clone(),
			app_token: value.app_token.clone(),
			device_keys: DeviceKeyDataExport {
				private_key: value.private_device_key.to_string_ref()?,
				sign_key: value.sign_device_key.to_string_ref()?,
				public_key: value.public_device_key.to_string_ref()?,
				verify_key: value.verify_device_key.to_string_ref()?,
				exported_public_key: value.exported_public_device_key.to_string()?,
				exported_verify_key: value.exported_verify_device_key.to_string()?,
			},
		})
	}
}

#[allow(clippy::from_over_into)]
impl TryInto<User> for UserExportData
{
	type Error = SentcError;

	fn try_into(self) -> Result<User, Self::Error>
	{
		Ok(User::new_user(
			self.base_url,
			self.app_token,
			self.user_identifier,
			UserDataInt {
				jwt: self.jwt,
				refresh_token: self.refresh_token,
				user_id: self.user_id,
				device_id: self.device_id,
				device_keys: DeviceKeyDataInt {
					private_key: self
						.device_keys
						.private_key
						.parse()
						.map_err(|_| SdkLightError::Util(SdkUtilError::ImportingKeyFromPemFailed))?,
					sign_key: self
						.device_keys
						.sign_key
						.parse()
						.map_err(|_| SdkLightError::Util(SdkUtilError::ImportingKeyFromPemFailed))?,
					public_key: self
						.device_keys
						.public_key
						.parse()
						.map_err(|_| SdkLightError::Util(SdkUtilError::ImportingKeyFromPemFailed))?,
					verify_key: self
						.device_keys
						.verify_key
						.parse()
						.map_err(|_| SdkLightError::Util(SdkUtilError::ImportingKeyFromPemFailed))?,
					exported_public_key: UserPublicKeyData::from_string(&self.device_keys.exported_public_key)
						.map_err(|_| SdkLightError::Util(SdkUtilError::ImportingKeyFromPemFailed))?,
					exported_verify_key: UserVerifyKeyData::from_string(&self.device_keys.exported_verify_key)
						.map_err(|_| SdkLightError::Util(SdkUtilError::ImportingKeyFromPemFailed))?,
				},
			},
			self.mfa,
		))
	}
}

impl FromStr for User
{
	type Err = SentcError;

	fn from_str(s: &str) -> Result<Self, Self::Err>
	{
		let data: UserExportData = serde_json::from_str(s)?;

		data.try_into()
	}
}

impl User
{
	pub fn to_string(self) -> Result<String, SentcError>
	{
		Ok(serde_json::to_string(&TryInto::<UserExportData>::try_into(self)?)?)
	}

	pub fn to_string_ref(&self) -> Result<String, SentcError>
	{
		Ok(serde_json::to_string(&TryInto::<UserExportData>::try_into(self)?)?)
	}
}
