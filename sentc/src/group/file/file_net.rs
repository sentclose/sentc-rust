use std::path::Path;

use tokio::fs::File;

use crate::cache::l_one::L1Cache;
use crate::error::SentcError;
use crate::file::uploader_net::upload_file;
use crate::group::Group;

pub struct FileCreateOutput
{
	pub file_id: String,
	pub master_key_id: String,
	pub encrypted_file_name: Option<String>,
}

pub type DefaultCallback = fn(u32);

impl Group
{
	async fn create_file(
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
			None, //TODO get it from global option
			&self.app_token,
			jwt,
			&key,
			&encrypted_key,
			sign_key,
			upload_callback,
			Some(self.get_group_id()),
			None,
			self.access_by_group_as_member.as_deref(),
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

		self.create_file(file, file_name, sign, None::<DefaultCallback>, c)
			.await
	}

	pub async fn create_file_with_file(&self, file: File, file_name: Option<String>, sign: bool, c: &L1Cache)
		-> Result<FileCreateOutput, SentcError>
	{
		self.create_file(file, file_name, sign, None::<DefaultCallback>, c)
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

		self.create_file(file, file_name, sign, Some(upload_callback), c)
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
		self.create_file(file, file_name, sign, Some(upload_callback), c)
			.await
	}

	//______________________________________________________________________________________________
	//download
}
