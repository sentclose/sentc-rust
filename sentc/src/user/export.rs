use std::str::FromStr;

use sentc_crypto::entities::user::{DeviceKeyDataExport, UserDataInt, UserKeyDataExport};
use sentc_crypto::sdk_common::{DeviceId, UserId};
use sentc_crypto::sdk_core::cryptomat::{PwHash, SearchableKeyGen, SortableKeyGen};
use sentc_crypto::sdk_utils::cryptomat::{
	KeyToString,
	PkFromUserKeyWrapper,
	SearchableKeyComposerWrapper,
	SignComposerWrapper,
	SignKeyPairWrapper,
	SortableKeyComposerWrapper,
	StaticKeyComposerWrapper,
	StaticKeyPairWrapper,
	SymKeyComposerWrapper,
	SymKeyGenWrapper,
	VerifyKFromUserKeyWrapper,
};
use sentc_crypto::sdk_utils::error::SdkUtilError;
use sentc_crypto::sdk_utils::user::DeviceKeyDataInt;
use sentc_crypto::SdkError;
use serde::{Deserialize, Serialize};

use crate::crypto_common::user::{UserPublicKeyData, UserVerifyKeyData};
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

	user_keys: Vec<UserKeyDataExport>,
	device_keys: DeviceKeyDataExport,
	hmac_keys: Vec<String>,
}

impl<SGen, StGen, SignGen, SearchGen, SortGen, SC, StC, SignC, SearchC, SortC, PC, VC, PwH>
	TryFrom<User<SGen, StGen, SignGen, SearchGen, SortGen, SC, StC, SignC, SearchC, SortC, PC, VC, PwH>> for UserExportData
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
	type Error = SentcError;

	fn try_from(value: User<SGen, StGen, SignGen, SearchGen, SortGen, SC, StC, SignC, SearchC, SortC, PC, VC, PwH>) -> Result<Self, Self::Error>
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
			user_keys: value
				.user_keys
				.into_iter()
				.map(|k| k.try_into())
				.collect::<Result<_, SdkError>>()?,
			device_keys: DeviceKeyDataExport {
				private_key: value.private_device_key.to_string()?,
				sign_key: value.sign_device_key.to_string()?,
				public_key: value.public_device_key.to_string()?,
				verify_key: value.verify_device_key.to_string()?,
				exported_public_key: value.exported_public_device_key.to_string()?,
				exported_verify_key: value.exported_verify_device_key.to_string()?,
			},
			hmac_keys: value
				.hmac_keys
				.into_iter()
				.map(|k| k.to_string())
				.collect::<Result<_, SdkUtilError>>()?,
		})
	}
}

impl<'a, SGen, StGen, SignGen, SearchGen, SortGen, SC, StC, SignC, SearchC, SortC, PC, VC, PwH>
	TryFrom<&'a User<SGen, StGen, SignGen, SearchGen, SortGen, SC, StC, SignC, SearchC, SortC, PC, VC, PwH>> for UserExportData
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
	type Error = SentcError;

	fn try_from(value: &'a User<SGen, StGen, SignGen, SearchGen, SortGen, SC, StC, SignC, SearchC, SortC, PC, VC, PwH>) -> Result<Self, Self::Error>
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
			user_keys: value
				.user_keys
				.iter()
				.map(|k| k.try_into())
				.collect::<Result<_, SdkError>>()?,
			device_keys: DeviceKeyDataExport {
				private_key: value.private_device_key.to_string_ref()?,
				sign_key: value.sign_device_key.to_string_ref()?,
				public_key: value.public_device_key.to_string_ref()?,
				verify_key: value.verify_device_key.to_string_ref()?,
				exported_public_key: value.exported_public_device_key.to_string()?,
				exported_verify_key: value.exported_verify_device_key.to_string()?,
			},
			hmac_keys: value
				.hmac_keys
				.iter()
				.map(|k| k.to_string_ref())
				.collect::<Result<_, SdkUtilError>>()?,
		})
	}
}

#[allow(clippy::from_over_into)]
impl<SGen, StGen, SignGen, SearchGen, SortGen, SC, StC, SignC, SearchC, SortC, PC, VC, PwH>
	TryInto<User<SGen, StGen, SignGen, SearchGen, SortGen, SC, StC, SignC, SearchC, SortC, PC, VC, PwH>> for UserExportData
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
	type Error = SentcError;

	fn try_into(self) -> Result<User<SGen, StGen, SignGen, SearchGen, SortGen, SC, StC, SignC, SearchC, SortC, PC, VC, PwH>, Self::Error>
	{
		let (mut user, _) = User::new_user(
			self.base_url,
			self.app_token,
			self.user_identifier,
			UserDataInt {
				jwt: self.jwt,
				refresh_token: self.refresh_token,
				user_id: self.user_id,
				device_id: self.device_id,
				user_keys: self
					.user_keys
					.into_iter()
					.map(|k| k.try_into())
					.collect::<Result<_, SdkError>>()?,
				device_keys: DeviceKeyDataInt {
					private_key: self
						.device_keys
						.private_key
						.parse()
						.map_err(|_| SdkError::Util(SdkUtilError::ImportingKeyFromPemFailed))?,
					sign_key: self
						.device_keys
						.sign_key
						.parse()
						.map_err(|_| SdkError::Util(SdkUtilError::ImportingKeyFromPemFailed))?,
					public_key: self
						.device_keys
						.public_key
						.parse()
						.map_err(|_| SdkError::Util(SdkUtilError::ImportingKeyFromPemFailed))?,
					verify_key: self
						.device_keys
						.verify_key
						.parse()
						.map_err(|_| SdkError::Util(SdkUtilError::ImportingKeyFromPemFailed))?,
					exported_public_key: UserPublicKeyData::from_string(&self.device_keys.exported_public_key)
						.map_err(|_| SdkError::Util(SdkUtilError::ImportingKeyFromPemFailed))?,
					exported_verify_key: UserVerifyKeyData::from_string(&self.device_keys.exported_verify_key)
						.map_err(|_| SdkError::Util(SdkUtilError::ImportingKeyFromPemFailed))?,
				},
				hmac_keys: vec![],
			},
			self.mfa,
		)?;

		user.hmac_keys = self
			.hmac_keys
			.into_iter()
			.map(|k| {
				k.parse()
					.map_err(|_| SdkUtilError::ImportingKeyFromPemFailed)
			})
			.collect::<Result<_, SdkUtilError>>()?;

		Ok(user)
	}
}

//__________________________________________________________________________________________________

impl<SGen, StGen, SignGen, SearchGen, SortGen, SC, StC, SignC, SearchC, SortC, PC, VC, PwH> FromStr
	for User<SGen, StGen, SignGen, SearchGen, SortGen, SC, StC, SignC, SearchC, SortC, PC, VC, PwH>
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
	type Err = SentcError;

	fn from_str(s: &str) -> Result<Self, Self::Err>
	{
		let data: UserExportData = serde_json::from_str(s)?;

		data.try_into()
	}
}

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
	pub fn to_string(self) -> Result<String, SentcError>
	{
		Ok(serde_json::to_string(&TryInto::<UserExportData>::try_into(self)?)?)
	}

	pub fn to_string_ref(&self) -> Result<String, SentcError>
	{
		Ok(serde_json::to_string(&TryInto::<UserExportData>::try_into(self)?)?)
	}
}
