use sentc_crypto_light::error::SdkLightError;

#[derive(Debug)]
pub enum SentcError
{
	Sdk(SdkLightError),

	UserNotFound,
	GroupNotFound,
	KeyNotFound,
	NoKeyFound,

	ParentGroupNotFoundButRequired,
	ParentGroupKeyNotFoundButRequired,
	ConnectedGroupNotFoundButRequired,
	ConnectedGroupKeyNotFoundButRequired,

	NoGroupKeysFound,

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
		value.into()
	}
}

impl From<sentc_crypto_light::sdk_core::Error> for SentcError
{
	fn from(value: sentc_crypto_light::sdk_core::Error) -> Self
	{
		value.into()
	}
}
