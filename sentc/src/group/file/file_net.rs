use std::path::{Path, MAIN_SEPARATOR_STR};

use sentc_crypto::entities::keys::SymmetricKey;
use sentc_crypto::sdk_common::file::FileData;
use sentc_crypto::sdk_common::user::UserVerifyKeyData;
use sentc_crypto_full::file::{delete_file, update_file_name};
use tokio::fs::File;

use crate::cache::l_one::L1Cache;
use crate::error::SentcError;
use crate::file::downloader_net::{check_if_file_exists, download_file_meta_information, download_parts};
use crate::file::uploader_net::upload_file;
use crate::file::DefaultCallback;
use crate::group::Group;

pub struct FileCreateOutput
{
	pub file_id: String,
	pub master_key_id: String,
	pub encrypted_file_name: Option<String>,
}

pub struct FileDownloadOutput
{
	pub file_data: FileData,
	pub key: SymmetricKey,
	pub file_name: Option<String>,
}

impl Group
{
	async fn create_file_internally(
		&self,
		file: File,
		file_name: Option<String>,
		sign: bool,
		upload_callback: Option<impl Fn(u32)>,
		c: &L1Cache,
	) -> Result<FileCreateOutput, SentcError>
	{
		let user = c
			.get_user(&self.used_user_id)
			.await
			.ok_or(SentcError::UserNotFound)?;

		let mut user_write = user.write().await;

		user_write.check_jwt(c).await?;

		//drop the suer and get the jwt from read guard to not block the user
		// just in case if other needs to read while the file is uploading.
		drop(user_write);

		let (key, encrypted_key) = self.generate_non_registered_key()?;

		let user_read = user.read().await;
		let jwt = user_read.get_jwt_sync();

		let sign_key = if sign {
			Some(
				user_read
					.get_newest_sign_key()
					.ok_or(SentcError::KeyNotFound)?,
			)
		} else {
			None
		};

		let (file_id, encrypted_file_name) = upload_file(
			file,
			file_name,
			&self.base_url,
			c.file_part_url.clone(),
			&self.app_token,
			jwt,
			&key,
			&encrypted_key,
			sign_key,
			upload_callback,
			Some(self.get_group_id()),
			None,
			self.get_access_group_as_member(),
		)
		.await?;

		Ok(FileCreateOutput {
			file_id,
			master_key_id: encrypted_key.master_key_id,
			encrypted_file_name,
		})
	}

	pub async fn create_file_with_path(&self, path: &str, sign: bool, c: &L1Cache) -> Result<FileCreateOutput, SentcError>
	{
		let file = File::open(path).await.map_err(SentcError::FileReadError)?;

		let file_name = Path::new(path)
			.file_name()
			.and_then(|n| n.to_str())
			.map(|n| n.to_string());

		self.create_file_internally(file, file_name, sign, None::<DefaultCallback>, c)
			.await
	}

	pub async fn create_file_with_file(&self, file: File, file_name: Option<String>, sign: bool, c: &L1Cache)
		-> Result<FileCreateOutput, SentcError>
	{
		self.create_file_internally(file, file_name, sign, None::<DefaultCallback>, c)
			.await
	}

	pub async fn create_file_with_path_and_upload_progress(
		&self,
		path: &str,
		sign: bool,
		upload_callback: impl Fn(u32),
		c: &L1Cache,
	) -> Result<FileCreateOutput, SentcError>
	{
		let file = File::open(path).await.map_err(SentcError::FileReadError)?;

		let file_name = Path::new(path)
			.file_name()
			.and_then(|n| n.to_str())
			.map(|n| n.to_string());

		self.create_file_internally(file, file_name, sign, Some(upload_callback), c)
			.await
	}

	pub async fn create_file_with_file_and_upload_progress(
		&self,
		file: File,
		file_name: Option<String>,
		sign: bool,
		upload_callback: impl Fn(u32),
		c: &L1Cache,
	) -> Result<FileCreateOutput, SentcError>
	{
		self.create_file_internally(file, file_name, sign, Some(upload_callback), c)
			.await
	}

	//______________________________________________________________________________________________
	//download

	pub async fn get_file_meta(
		&mut self,
		file_id: &str,
		verify_key: Option<&UserVerifyKeyData>,
		c: &L1Cache,
	) -> Result<(FileData, SymmetricKey, Option<String>), SentcError>
	{
		let user = c
			.get_user(&self.used_user_id)
			.await
			.ok_or(SentcError::UserNotFound)?;

		let mut user_write = user.write().await;

		user_write.check_jwt(c).await?;

		//drop the suer and get the jwt from read guard to not block the user
		// just in case if other needs to read while the file is uploading.
		drop(user_write);

		let user_read = user.read().await;
		let jwt = user_read.get_jwt_sync();

		let meta = download_file_meta_information(
			&self.base_url,
			&self.app_token,
			jwt,
			file_id,
			Some(self.get_group_id()),
			self.get_access_group_as_member(),
		)
		.await?;

		//drop here to fetch the group key
		drop(user_read);

		//the user in get_non_registered_key should be dropped in the fn
		let key = self
			.get_non_registered_key(&meta.master_key_id, &meta.encrypted_key, c)
			.await?;

		let file_name = if let Some(file_name) = &meta.encrypted_file_name {
			Some(key.decrypt_string(file_name, verify_key)?)
		} else {
			None
		};

		Ok((meta, key, file_name))
	}

	pub async fn download_file_with_meta_info(
		&self,
		file: File,
		file_meta: FileData,
		content_key: &SymmetricKey,
		verify_key: Option<&UserVerifyKeyData>,
		c: &L1Cache,
	) -> Result<(), SentcError>
	{
		download_parts(
			file,
			&self.base_url,
			&self.app_token,
			c.file_part_url.clone(),
			content_key,
			&file_meta.part_list,
			None::<DefaultCallback>,
			verify_key,
		)
		.await
	}

	pub async fn download_file_with_meta_info_with_progress(
		&self,
		file: File,
		file_meta: FileData,
		content_key: &SymmetricKey,
		upload_callback: impl Fn(u32),
		verify_key: Option<&UserVerifyKeyData>,
		c: &L1Cache,
	) -> Result<(), SentcError>
	{
		download_parts(
			file,
			&self.base_url,
			&self.app_token,
			c.file_part_url.clone(),
			content_key,
			&file_meta.part_list,
			Some(upload_callback),
			verify_key,
		)
		.await
	}

	pub async fn download_file(
		&mut self,
		file: File,
		file_id: &str,
		verify_key: Option<&UserVerifyKeyData>,
		c: &L1Cache,
	) -> Result<FileDownloadOutput, SentcError>
	{
		let (meta, content_key, decrypted_file_name) = self.get_file_meta(file_id, verify_key, c).await?;

		download_parts(
			file,
			&self.base_url,
			&self.app_token,
			c.file_part_url.clone(),
			&content_key,
			&meta.part_list,
			None::<DefaultCallback>,
			verify_key,
		)
		.await?;

		Ok(FileDownloadOutput {
			file_data: meta,
			key: content_key,
			file_name: decrypted_file_name,
		})
	}

	pub async fn download_file_with_progress(
		&mut self,
		file: File,
		file_id: &str,
		upload_callback: impl Fn(u32),
		verify_key: Option<&UserVerifyKeyData>,
		c: &L1Cache,
	) -> Result<FileDownloadOutput, SentcError>
	{
		let (meta, content_key, decrypted_file_name) = self.get_file_meta(file_id, verify_key, c).await?;

		download_parts(
			file,
			&self.base_url,
			&self.app_token,
			c.file_part_url.clone(),
			&content_key,
			&meta.part_list,
			Some(upload_callback),
			verify_key,
		)
		.await?;

		Ok(FileDownloadOutput {
			file_data: meta,
			key: content_key,
			file_name: decrypted_file_name,
		})
	}

	pub async fn download_file_with_path(
		&mut self,
		path: &str,
		file_id: &str,
		verify_key: Option<&UserVerifyKeyData>,
		c: &L1Cache,
	) -> Result<FileDownloadOutput, SentcError>
	{
		let (meta, content_key, decrypted_file_name) = self.get_file_meta(file_id, verify_key, c).await?;

		let file_name = decrypted_file_name.as_deref().unwrap_or("file");

		//check if the file exists

		let file_name = check_if_file_exists(path, file_name).await?;

		let file = File::create(path.to_string() + MAIN_SEPARATOR_STR + &file_name)
			.await
			.map_err(SentcError::FileReadError)?;

		download_parts(
			file,
			&self.base_url,
			&self.app_token,
			c.file_part_url.clone(),
			&content_key,
			&meta.part_list,
			None::<DefaultCallback>,
			verify_key,
		)
		.await?;

		Ok(FileDownloadOutput {
			file_data: meta,
			key: content_key,
			file_name: Some(file_name),
		})
	}

	pub async fn download_file_with_path_with_progress(
		&mut self,
		path: &str,
		file_id: &str,
		upload_callback: impl Fn(u32),
		verify_key: Option<&UserVerifyKeyData>,
		c: &L1Cache,
	) -> Result<FileDownloadOutput, SentcError>
	{
		let (meta, content_key, decrypted_file_name) = self.get_file_meta(file_id, verify_key, c).await?;

		let file_name = decrypted_file_name.as_deref().unwrap_or("file");

		//check if the file exists

		let file_name = check_if_file_exists(path, file_name).await?;

		let file = File::create(path.to_string() + MAIN_SEPARATOR_STR + &file_name)
			.await
			.map_err(SentcError::FileReadError)?;

		download_parts(
			file,
			&self.base_url,
			&self.app_token,
			c.file_part_url.clone(),
			&content_key,
			&meta.part_list,
			Some(upload_callback),
			verify_key,
		)
		.await?;

		Ok(FileDownloadOutput {
			file_data: meta,
			key: content_key,
			file_name: Some(file_name),
		})
	}

	//______________________________________________________________________________________________

	pub async fn update_file_name(&self, file_id: &str, content_key: &SymmetricKey, file_name: Option<String>, c: &L1Cache)
		-> Result<(), SentcError>
	{
		let user = c
			.get_user(&self.used_user_id)
			.await
			.ok_or(SentcError::UserNotFound)?;

		let mut user_write = user.write().await;

		let jwt = user_write.get_jwt(c).await?;

		Ok(update_file_name(
			self.base_url.clone(),
			&self.app_token,
			jwt,
			file_id,
			content_key,
			file_name,
		)
		.await?)
	}

	pub async fn delete_file(&self, file_id: &str, c: &L1Cache) -> Result<(), SentcError>
	{
		let user = c
			.get_user(&self.used_user_id)
			.await
			.ok_or(SentcError::UserNotFound)?;

		let mut user_write = user.write().await;

		let jwt = user_write.get_jwt(c).await?;

		Ok(delete_file(
			self.base_url.clone(),
			&self.app_token,
			jwt,
			file_id,
			Some(self.get_group_id()),
			self.get_access_group_as_member(),
		)
		.await?)
	}
}
