use std::fs::Metadata;

use sentc_crypto::entities::keys::{SignKeyFormatInt, SymKeyFormatInt};
use sentc_crypto::sdk_common::crypto::GeneratedSymKeyHeadServerOutput;
use sentc_crypto::sdk_common::file::BelongsToType;
use sentc_crypto::sdk_core::SymKey;
use sentc_crypto_full::file::{register_file, upload_part, upload_part_start};
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncSeekExt, SeekFrom};

use crate::error::SentcError;

pub const DEFAULT_CHUNK_SIZE: usize = 1024 * 1024 * 4;

#[allow(clippy::too_many_arguments)]
#[inline(always)]
pub(crate) async fn check_file_upload(
	mut file: File,
	file_meta: &Metadata,
	base_url: &str,
	url_prefix: Option<String>,
	app_token: &str,
	jwt: &str,
	content_key: &SymKeyFormatInt,
	session_id: &str,
	sign_key: Option<&SignKeyFormatInt>,
	upload_callback: Option<impl Fn(u32)>,
) -> Result<(), SentcError>
{
	let mut start = 0;
	let mut end = DEFAULT_CHUNK_SIZE as u64;
	let file_size = file_meta.len();
	let total_chunks = file_size / DEFAULT_CHUNK_SIZE as u64;

	let mut current_chunk = 0;

	//default key -> will be set after the first chunk was processed.
	let mut next_file_key: SymKey = SymKey::Aes(Default::default());

	while start < file_size {
		current_chunk += 1;

		// Adjust the end position if it exceeds the file size
		if end > file_size {
			end = file_size;
		}

		file.seek(SeekFrom::Start(start))
			.await
			.map_err(SentcError::FileReadError)?;

		let mut chunk = vec![0; (end - start) as usize];

		let bytes_read = file
			.read_exact(&mut chunk)
			.await
			.map_err(SentcError::FileReadError)?;

		if bytes_read == 0 {
			break;
		}

		start = end;
		end = start + DEFAULT_CHUNK_SIZE as u64;
		let is_end = start >= file_size;

		if current_chunk == 1 {
			next_file_key = upload_part_start(
				base_url.to_string(),
				url_prefix.clone(),
				app_token,
				jwt,
				session_id,
				is_end,
				current_chunk as i32,
				content_key,
				sign_key,
				&chunk,
			)
			.await?;
		} else {
			next_file_key = upload_part(
				base_url.to_string(),
				url_prefix.clone(),
				app_token,
				jwt,
				session_id,
				is_end,
				current_chunk as i32,
				&next_file_key,
				sign_key,
				&chunk,
			)
			.await?;
		}

		if let Some(cb) = &upload_callback {
			cb((current_chunk / total_chunks) as u32);
		}
	}

	Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn upload_file(
	file: File,
	file_name: Option<String>,
	base_url: &str,
	url_prefix: Option<String>,
	app_token: &str,
	jwt: &str,
	content_key: &SymKeyFormatInt,
	encrypted_content_key: &GeneratedSymKeyHeadServerOutput,
	sign_key: Option<&SignKeyFormatInt>,
	upload_callback: Option<impl Fn(u32)>,
	group_id: Option<&str>,
	other_user_id: Option<&str>,
	group_as_member: Option<&str>,
) -> Result<(String, Option<String>), SentcError>
{
	let file_meta = file.metadata().await.map_err(SentcError::FileReadError)?;

	let (belongs_to_type, belongs_to_id) = if group_id.is_some() {
		(BelongsToType::Group, group_id)
	} else if other_user_id.is_some() {
		(BelongsToType::User, other_user_id)
	} else {
		(BelongsToType::None, None)
	};

	let (file_id, session_id, encrypted_file_name) = register_file(
		base_url.to_string(),
		app_token,
		jwt,
		encrypted_content_key.master_key_id.clone(),
		content_key,
		encrypted_content_key
			.to_string()
			.map_err(SentcError::JsonParseFailed)?,
		belongs_to_id.map(|o| o.to_string()),
		belongs_to_type,
		file_name,
		group_id,
		group_as_member,
	)
	.await?;

	check_file_upload(
		file,
		&file_meta,
		base_url,
		url_prefix,
		app_token,
		jwt,
		content_key,
		&session_id,
		sign_key,
		upload_callback,
	)
	.await?;

	Ok((file_id, encrypted_file_name))
}
