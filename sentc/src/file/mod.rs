use sentc_crypto::sdk_utils::cryptomat::SymKeyWrapper;

use crate::crypto_common::file::FileData;

#[cfg(feature = "network")]
pub mod downloader_net;
#[cfg(feature = "network")]
pub mod uploader_net;

pub type DefaultCallback = fn(u32);

pub struct FileCreateOutput
{
	pub file_id: String,
	pub master_key_id: String,
	pub encrypted_file_name: Option<String>,
}

pub struct FileDownloadOutput<S: SymKeyWrapper>
{
	pub file_data: FileData,
	pub key: S,
	pub file_name: Option<String>,
}
