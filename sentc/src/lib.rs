pub mod error;
#[cfg(feature = "file")]
pub mod file;
pub mod group;
pub mod keys;
#[cfg(feature = "network")]
pub mod net_helper;
pub mod user;

use std::collections::HashMap;

use sentc_crypto::sdk_common::SymKeyId;
pub use sentc_crypto::{entities as crypto_entities, sdk_common as crypto_common};

pub type KeyMap = HashMap<SymKeyId, usize>;

pub fn split_head_and_encrypted_data<'a, T: serde::Deserialize<'a>>(data_with_head: &'a [u8]) -> Result<(T, &[u8]), error::SentcError>
{
	Ok(sentc_crypto::crypto::split_head_and_encrypted_data(data_with_head)?)
}

pub fn split_head_and_encrypted_string(encrypted_data_with_head: &str) -> Result<crypto_common::crypto::EncryptedHead, error::SentcError>
{
	Ok(sentc_crypto::crypto::split_head_and_encrypted_string(
		encrypted_data_with_head,
	)?)
}
