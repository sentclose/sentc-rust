use sentc_crypto::sdk_utils::error::SdkUtilError;
use sentc_crypto::SdkError;

#[derive(Debug)]
pub enum SentcError
{
	Sdk(SdkError),

	UserNotFound,
	GroupNotFound,
	KeyNotFound,
	KeyRequired(String),

	ParentGroupKeyNotFoundButRequired(String),

	NoGroupKeysFound,

	TimeError,
	JsonToStringFailed,
	JsonParseFailed(serde_json::Error),

	UsernameOrPasswordRequired,
	UserMfaRequired,

	#[cfg(feature = "file")]
	FileReadError(std::io::Error),
	#[cfg(feature = "file")]
	FilePartNotFound,

	JwtExpired,

	GroupFetchUserKeyNotFound,
	GroupFetchGroupKeyNotFound(String),
}

impl From<SdkError> for SentcError
{
	fn from(value: SdkError) -> Self
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

impl From<sentc_crypto::sdk_core::Error> for SentcError
{
	fn from(value: sentc_crypto::sdk_core::Error) -> Self
	{
		value.into()
	}
}

impl From<SdkUtilError> for SentcError
{
	fn from(value: SdkUtilError) -> Self
	{
		Self::Sdk(SdkError::Util(value))
	}
}
