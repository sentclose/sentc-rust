use std::path::{Path, MAIN_SEPARATOR_STR};

use sentc_crypto::entities::keys::SymKeyFormatInt;
use sentc_crypto::sdk_common::file::{FileData, FilePartListItem};
use sentc_crypto::sdk_common::user::UserVerifyKeyData;
use sentc_crypto::sdk_core::SymKey;
use sentc_crypto_full::file::{download_and_decrypt_file_part, download_and_decrypt_file_part_start, download_file_meta, download_part_list};
use tokio::fs::{metadata, File};
use tokio::io::AsyncWriteExt;

use crate::error::SentcError;

#[allow(clippy::too_many_arguments)]
#[inline(always)]
pub(crate) async fn download_parts(
	mut file: File,
	base_url: &str,
	app_token: &str,
	url_prefix: Option<String>,
	contend_key: &SymKeyFormatInt,
	part_list: &[FilePartListItem],
	upload_callback: Option<impl Fn(u32)>,
	verify_key: Option<&UserVerifyKeyData>,
) -> Result<(), SentcError>
{
	//default key -> will be set after the first chunk was processed.
	let mut next_file_key: SymKey = SymKey::Aes(Default::default());

	for (i, part) in part_list.iter().enumerate() {
		let external = part.extern_storage;

		let part_url_base = if external { url_prefix.clone() } else { None };

		let part = if i == 0 {
			let (decrypted_part, next_key) = download_and_decrypt_file_part_start(
				base_url.to_string(),
				part_url_base,
				app_token,
				&part.part_id,
				contend_key,
				verify_key,
			)
			.await?;

			next_file_key = next_key;
			decrypted_part
		} else {
			let (decrypted_part, next_key) = download_and_decrypt_file_part(
				base_url.to_string(),
				part_url_base,
				app_token,
				&part.part_id,
				&next_file_key,
				verify_key,
			)
			.await?;

			next_file_key = next_key;
			decrypted_part
		};

		file.write_all(&part)
			.await
			.map_err(SentcError::FileReadError)?;

		if let Some(cb) = &upload_callback {
			cb(((i + 1) / part_list.len()) as u32);
		}
	}

	file.shutdown().await.map_err(SentcError::FileReadError)?;

	Ok(())
}

pub(crate) async fn download_file_meta_information(
	base_url: &str,
	app_token: &str,
	jwt: &str,
	file_id: &str,
	group_id: Option<&str>,
	group_as_member: Option<&str>,
) -> Result<FileData, SentcError>
{
	let meta = download_file_meta(
		base_url.to_string(),
		app_token,
		file_id,
		Some(jwt),
		group_id,
		group_as_member,
	)
	.await?;

	if meta.part_list.len() < 500 {
		return Ok(meta);
	}

	let mut part_list = meta.part_list;

	let mut next_fetch = true;

	while next_fetch {
		//parts are there in last otherwise it would returned the meta
		let last_item = part_list.last().ok_or(SentcError::FilePartNotFound)?;

		let mut fetched_parts = download_part_list(
			base_url.to_string(),
			app_token,
			file_id,
			last_item.sequence.to_string().as_str(),
		)
		.await?;

		next_fetch = fetched_parts.len() >= 500;

		part_list.append(&mut fetched_parts);
	}

	Ok(FileData {
		file_id: meta.file_id,
		master_key_id: meta.master_key_id,
		owner: meta.owner,
		belongs_to: meta.belongs_to,
		belongs_to_type: meta.belongs_to_type,
		encrypted_key: meta.encrypted_key,
		encrypted_key_alg: meta.encrypted_key_alg,
		encrypted_file_name: meta.encrypted_file_name,
		part_list,
	})
}

pub(crate) async fn check_if_file_exists(path: &str, name: &str) -> Result<String, SentcError>
{
	let p = Path::new(name);

	let mut file_name = p
		.file_stem()
		.and_then(|n| n.to_str())
		.map(|n| n.to_string())
		.unwrap_or("".to_string());

	let ext = p.extension().and_then(|n| n.to_str()).unwrap_or("");

	let path = path.to_string() + MAIN_SEPARATOR_STR;

	let mut i = 1;

	'l1: loop {
		let c_path = path.clone() + &file_name + "." + ext;

		let f = match metadata(&c_path).await {
			Ok(f) => f,
			Err(_) => break 'l1,
		};

		if !f.is_file() {
			//file not exists
			break 'l1;
		}

		file_name = file_name.to_string() + i.to_string().as_str();
		i += 1;
	}

	Ok(file_name + "." + ext)
}
