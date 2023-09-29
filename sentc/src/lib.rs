#[cfg(feature = "network")]
pub mod cache;
pub mod error;
#[cfg(feature = "file")]
pub mod file;
pub mod group;
#[cfg(feature = "network")]
mod net_helper;
pub mod sentc;
pub mod user;

use std::collections::HashMap;

use sentc_crypto::sdk_common::SymKeyId;
pub use sentc_crypto::{entities as crypto_entities, sdk_common as crypto_common};
#[cfg(feature = "ear")]
pub use sentc_ear_core::data as ear_data;

pub type KeyMap = HashMap<SymKeyId, usize>;

macro_rules! decrypt_hmac_key {
	($key:expr, $self:expr, $hmac_key:expr) => {
		let decrypted_hmac_key = sentc_crypto::group::decrypt_group_hmac_key($key, $hmac_key)?;
		$self.hmac_keys.push(decrypted_hmac_key);
	};
}

macro_rules! decrypt_sort_key {
	($key:expr, $self:expr, $sort_key:expr) => {
		let decrypted_key = sentc_crypto::group::decrypt_group_sortable_key($key, $sort_key)?;
		$self.sortable_keys.push(decrypted_key);
	};
}

use {decrypt_hmac_key, decrypt_sort_key};
