use std::collections::VecDeque;

use sentc_crypto::entities::keys::{SignKeyFormatInt, SymKeyFormatInt};
use sentc_crypto::sdk_common::crypto::EncryptedHead;
use sentc_crypto::sdk_common::user::UserVerifyKeyData;
use sentc_ear_core::data::entities::{DataDecrypt, DataEncrypt, DataOutFormat, DataOutput};
use sentc_ear_core::data::{decrypt_data, decrypt_row, encrypt_data, encrypt_row, prepare_search};
use sentc_ear_core::file::entities::FileKey;
use sentc_ear_core::file::{prepare_file_key_download, prepare_file_key_upload};

use crate::error::SentcError;
use crate::group::Group;

#[macro_export]
macro_rules! encrypt_row {
    ($self:expr, $sign_key:expr, [$($data:expr),*]) => {
		||{
           	let group_keys = match $self
				.get_newest_key() {
				Some(gk) => gk,
				None=> return Err($crate::error::SentcError::NoKeyFound)
			};

			let key = &group_keys.group_key;

            let head = $crate::ear_data::get_head_from_keys(key, $sign_key);
			let head = match head.to_string().map_err(|_| $crate::error::SentcError::JsonToStringFailed) {
				Ok(h) => h,
				Err(e)=> return Err(e)
			};

			Ok((head, $(
				match $crate::ear_data::encrypt_data_single(
					key,
					$data,
					$sign_key,
					Some($self.get_newest_hmac_key()),
					Some($self.get_newest_sortable_key())
				) {
					Ok(o) => o,
					Err(e) => return Err(e.into())
				}

			),*))
        }
    };

	//without sign
	($self:expr, [$($data:expr),*]) => {
		$crate::encrypt_row!($self, None, [$($data),*])
	};
}

#[macro_export]
macro_rules! encrypt_row_no_c {
    ($self:expr, $sign_key:expr, [$($data:expr),*]) => {
        {
			let group_keys = $self.get_newest_key().ok_or($crate::error::SentcError::NoKeyFound)?;

			let key = &group_keys.group_key;

            let head = $crate::ear_data::get_head_from_keys(key, $sign_key);
			let head = head.to_string().map_err(|_| $crate::error::SentcError::JsonToStringFailed)?;

            (
				head,
				$($crate::ear_data::encrypt_data_single(
					key,
					$data,
					$sign_key,
					Some($self.get_newest_hmac_key()),
					Some($self.get_newest_sortable_key())
				).map_err($crate::error::SentcError::from)?),*)
        }
    };

	($self:expr, [$($data:expr),*]) => {
		$crate::encrypt_row_no_c!($self, None, [$($data),*])
	};
}

#[macro_export]
macro_rules! decrypt_row {
	($self:expr, $verify_key:expr, $head:expr, [$($data:expr),*]) => {
        ||{
           let head = match $crate::crypto_common::crypto::EncryptedHead::from_string($head).map_err($crate::error::SentcError::JsonParseFailed) {
			   Ok(h) => h,
			   Err(e)=> return Err(e)
		   };

		   let group_keys = match $self.get_group_key(&head.id) {
				Some(gk) => gk,
				None=> return Err($crate::error::SentcError::NoKeyFound)
		   };

		   let key = &group_keys.group_key;

		   Ok(($(

			match $crate::ear_data::decrypt_data(key, $data, $verify_key, &head){
				Ok(o) => o,
				Err(e) => return Err(e.into())
			}

			),*))
        }
    };

	($self:expr, $head:expr, [$($data:expr),*]) => {
		$crate::decrypt_row!($self, None, $head, [$($data),*])
	}
}

#[macro_export]
macro_rules! decrypt_row_no_c {
    ($self:expr, $verify_key:expr, $head:expr, [$($data:expr),*]) => {
        {
			let head = $crate::crypto_common::crypto::EncryptedHead::from_string($head).map_err($crate::error::SentcError::JsonParseFailed)?;

			let group_keys = $self.get_group_key(&head.id).ok_or($crate::error::SentcError::NoKeyFound)?;

			let key = &group_keys.group_key;

            ($($crate::ear_data::decrypt_data(key, $data, $verify_key, &head).map_err($crate::error::SentcError::from)?),*)
        }
    };

	($self:expr, $head:expr, [$($data:expr),*]) => {
		$crate::decrypt_row_no_c!($self, None,  $head, [$($data),*])
	}
}

impl Group
{
	//sdk ear specific functions

	pub fn encrypt_row(&self, row: &[DataEncrypt], sign_key: Option<&SignKeyFormatInt>) -> Result<(String, VecDeque<DataOutput>), SentcError>
	{
		let key = self.get_newest_key().ok_or(SentcError::NoKeyFound)?;

		Ok(encrypt_row(
			&key.group_key,
			row,
			sign_key,
			Some(self.get_newest_hmac_key()),
			Some(self.get_newest_sortable_key()),
		)?)
	}

	pub fn encrypt_data(&self, data: DataEncrypt, sign_key: Option<&SignKeyFormatInt>) -> Result<(String, DataOutput), SentcError>
	{
		let key = self.get_newest_key().ok_or(SentcError::NoKeyFound)?;

		Ok(encrypt_data(
			&key.group_key,
			data,
			sign_key,
			Some(self.get_newest_hmac_key()),
			Some(self.get_newest_sortable_key()),
		)?)
	}

	pub fn decrypt_row(&self, data: &[DataDecrypt], verify_key: Option<&UserVerifyKeyData>, head: &str)
		-> Result<VecDeque<DataOutFormat>, SentcError>
	{
		let head: EncryptedHead = serde_json::from_str(head)?;

		let key = self
			.get_group_key(&head.id)
			.ok_or(SentcError::KeyNotFound)?;

		Ok(decrypt_row(&key.group_key, data, verify_key, &head)?)
	}

	pub fn decrypt_data(&self, data: DataDecrypt, verify_key: Option<&UserVerifyKeyData>, head: &str) -> Result<DataOutFormat, SentcError>
	{
		let head: EncryptedHead = serde_json::from_str(head)?;
		let key = self
			.get_group_key(&head.id)
			.ok_or(SentcError::KeyNotFound)?;

		Ok(decrypt_data(&key.group_key, data, verify_key, &head)?)
	}

	pub fn prepare_search(&self, data: &str) -> Result<String, SentcError>
	{
		let key = self.get_newest_hmac_key();

		Ok(prepare_search(key, data)?)
	}

	pub fn prepare_file_key_upload(&self) -> Result<(SymKeyFormatInt, FileKey), SentcError>
	{
		let key = self.get_newest_key().ok_or(SentcError::NoKeyFound)?;

		Ok(prepare_file_key_upload(&key.group_key)?)
	}

	pub fn prepare_file_key_download(&self, encrypted_key_info: &str) -> Result<SymKeyFormatInt, SentcError>
	{
		let encrypted_key_info: FileKey = serde_json::from_str(encrypted_key_info)?;

		let key = self
			.get_group_key(&encrypted_key_info.master_key_id)
			.ok_or(SentcError::KeyNotFound)?;

		Ok(prepare_file_key_download(&key.group_key, &encrypted_key_info)?)
	}
}

#[cfg(test)]
mod tests
{
	use super::*;
	use crate::cache::l_one::L1Cache;
	use crate::user::User;

	#[derive(Debug)]
	enum Te
	{
		Inner(SentcError),
	}

	impl From<SentcError> for Te
	{
		fn from(value: SentcError) -> Self
		{
			Self::Inner(value)
		}
	}

	#[tokio::test]
	async fn test_macro() -> Result<(), Te>
	{
		let c = L1Cache::new();

		let mut user = User::new();

		let group = user.get_group("abc", None, &c).await.unwrap();

		let g = group.read().await;

		let (head_s, a) = encrypt_row!(&g, None, [DataEncrypt::new("abcdefg".into(), None)])()?;

		let (h, b, c) = encrypt_row_no_c!(
			g,
			[DataEncrypt::new("abcdefg".into(), None), DataEncrypt::new(123.into(), None)]
		);

		let a = decrypt_row!(g, None, &head_s, [DataDecrypt::new_s(&a.encrypted, None)])().unwrap();

		let (b, c) = decrypt_row_no_c!(
			g,
			&h,
			[DataDecrypt::new_s(&b.encrypted, None), DataDecrypt::new_n(&c.encrypted, None)]
		);

		Ok(())
	}
}
