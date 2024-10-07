#![doc=include_str!("../../README.md")]
#![doc=include_str!("../doc/user.md")]
#![doc=include_str!("../doc/encrypt_user.md")]
#![doc=include_str!("../doc/group.md")]
#![doc=include_str!("../doc/encrypt_group.md")]
#![doc=include_str!("../doc/searchable.md")]
#![doc=include_str!("../doc/sortable.md")]
#![doc=include_str!("../doc/file.md")]
#![doc=include_str!("../doc/create-app.md")]
//! # Advanced
#![doc=include_str!("../doc/protocol.md")]
#![doc=include_str!("../doc/end-to-end-encrypted-database.md")]
#![doc=include_str!("../doc/backend-only.md")]
#![doc=include_str!("../doc/self-hosted.md")]
#![allow(clippy::tabs_in_doc_comments, rustdoc::bare_urls)]

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

/// The map shows on what index and the key vec the key is in.
pub type KeyMap = HashMap<SymKeyId, usize>;

/// Helper function to get the head and the encrypted data
/// Sentc stores some information about the encryption in front of the encrypted data as a head for decryption.
/// Information about the key and algorithm is used and if it is signed and if so what alg and key was used.
pub fn split_head_and_encrypted_data<'a, T: serde::Deserialize<'a>>(data_with_head: &'a [u8]) -> Result<(T, &[u8]), error::SentcError>
{
	Ok(sentc_crypto::crypto::split_head_and_encrypted_data(data_with_head)?)
}

/// The same as split_head_and_encrypted_data but for strings to get just the head back not the string and head.
pub fn split_head_and_encrypted_string(encrypted_data_with_head: &str) -> Result<crypto_common::crypto::EncryptedHead, error::SentcError>
{
	Ok(sentc_crypto::crypto::split_head_and_encrypted_string(
		encrypted_data_with_head,
	)?)
}
