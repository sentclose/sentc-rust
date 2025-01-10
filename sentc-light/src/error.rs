use sentc_crypto_light::error::SdkLightError;
use sentc_crypto_light::sdk_utils::error::SdkUtilError;

#[derive(Debug)]
pub enum SentcError
{
	Sdk(SdkLightError),

	TimeError,
	JsonToStringFailed,
	JsonParseFailed(serde_json::Error),

	UsernameOrPasswordRequired,
	UserMfaRequired,
}

impl From<SdkLightError> for SentcError
{
	fn from(value: SdkLightError) -> Self
	{
		Self::Sdk(value)
	}
}

impl From<serde_json::Error> for SentcError
{
	fn from(value: serde_json::Error) -> Self
	{
		Self::Sdk(value.into())
	}
}

impl From<sentc_crypto_light::sdk_core::Error> for SentcError
{
	fn from(value: sentc_crypto_light::sdk_core::Error) -> Self
	{
		Self::Sdk(value.into())
	}
}

impl From<SdkUtilError> for SentcError
{
	fn from(value: SdkUtilError) -> Self
	{
		Self::Sdk(SdkLightError::Util(value))
	}
}
