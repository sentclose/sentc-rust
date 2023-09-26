use sentc_crypto::SdkError;

#[derive(Debug)]
pub enum SentcError
{
	Sdk(SdkError),
	#[cfg(feature = "ear")]
	EarCore(sentc_ear_core::error::SdkEarError),

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

#[cfg(feature = "ear")]
impl From<sentc_ear_core::error::SdkEarError> for SentcError
{
	fn from(value: sentc_ear_core::error::SdkEarError) -> Self
	{
		Self::EarCore(value)
	}
}
