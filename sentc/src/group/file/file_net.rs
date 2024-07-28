use std::future::Future;
use std::path::{Path, MAIN_SEPARATOR_STR};

use sentc_crypto::sdk_common::file::FileData;
use sentc_crypto::sdk_common::user::UserVerifyKeyData;
use sentc_crypto::sdk_core::cryptomat::{PwHash, SearchableKeyGen, SortableKeyGen};
use sentc_crypto::sdk_utils::cryptomat::{
	PkFromUserKeyWrapper,
	SearchableKeyComposerWrapper,
	SignComposerWrapper,
	SignKeyPairWrapper,
	SortableKeyComposerWrapper,
	StaticKeyComposerWrapper,
	StaticKeyPairWrapper,
	SymKeyComposerWrapper,
	SymKeyCrypto,
	SymKeyGenWrapper,
	SymKeyWrapper,
	VerifyKFromUserKeyWrapper,
};
use sentc_crypto::util_req_full::file::{delete_file, update_file_name};
use tokio::fs::File;

use crate::error::SentcError;
use crate::file::downloader_net::{check_if_file_exists, download_file_meta_information, FileEncryptorDownload};
use crate::file::uploader_net::FileEncryptorUpload;
use crate::file::DefaultCallback;
use crate::group::Group;

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

impl<SGen, StGen, SignGen, SearchGen, SortGen, SC, StC, SignC, SearchC, SortC, PC, VC, PwH>
	Group<SGen, StGen, SignGen, SearchGen, SortGen, SC, StC, SignC, SearchC, SortC, PC, VC, PwH>
where
	SGen: SymKeyGenWrapper,
	StGen: StaticKeyPairWrapper,
	SignGen: SignKeyPairWrapper,
	SearchGen: SearchableKeyGen,
	SortGen: SortableKeyGen,
	SC: SymKeyComposerWrapper,
	StC: StaticKeyComposerWrapper,
	SignC: SignComposerWrapper,
	SearchC: SearchableKeyComposerWrapper,
	SortC: SortableKeyComposerWrapper,
	PC: PkFromUserKeyWrapper,
	VC: VerifyKFromUserKeyWrapper,
	PwH: PwHash,
{
	async fn create_file_internally(
		&self,
		jwt: &str,
		file: File,
		file_name: Option<String>,
		file_part_url: Option<String>,
		sign_key: Option<&SignC::SignKWrapper>,
		upload_callback: Option<impl Fn(u32)>,
	) -> Result<FileCreateOutput, SentcError>
	{
		let (key, encrypted_key) = self.generate_non_registered_key()?;

		let (file_id, encrypted_file_name) = FileEncryptorUpload::<SGen::KeyGen, SC::Composer, SignC::SignKWrapper, VC>::upload_file(
			file,
			file_name,
			&self.base_url,
			file_part_url,
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

	pub async fn create_file_with_path(
		&self,
		jwt: &str,
		path: &str,
		file_part_url: Option<String>,
		sign_key: Option<&SignC::SignKWrapper>,
	) -> Result<FileCreateOutput, SentcError>
	{
		let file = File::open(path).await.map_err(SentcError::FileReadError)?;

		let file_name = Path::new(path)
			.file_name()
			.and_then(|n| n.to_str())
			.map(|n| n.to_string());

		self.create_file_internally(jwt, file, file_name, file_part_url, sign_key, None::<DefaultCallback>)
			.await
	}

	pub fn create_file_with_file<'a>(
		&'a self,
		jwt: &'a str,
		file: File,
		file_name: Option<String>,
		file_part_url: Option<String>,
		sign_key: Option<&'a SignC::SignKWrapper>,
	) -> impl Future<Output = Result<FileCreateOutput, SentcError>> + 'a
	{
		self.create_file_internally(jwt, file, file_name, file_part_url, sign_key, None::<DefaultCallback>)
	}

	pub async fn create_file_with_path_and_upload_progress(
		&self,
		jwt: &str,
		path: &str,
		file_part_url: Option<String>,
		sign_key: Option<&SignC::SignKWrapper>,
		upload_callback: impl Fn(u32),
	) -> Result<FileCreateOutput, SentcError>
	{
		let file = File::open(path).await.map_err(SentcError::FileReadError)?;

		let file_name = Path::new(path)
			.file_name()
			.and_then(|n| n.to_str())
			.map(|n| n.to_string());

		self.create_file_internally(jwt, file, file_name, file_part_url, sign_key, Some(upload_callback))
			.await
	}

	pub async fn create_file_with_file_and_upload_progress<'a>(
		&'a self,
		jwt: &'a str,
		file: File,
		file_name: Option<String>,
		file_part_url: Option<String>,
		sign_key: Option<&'a SignC::SignKWrapper>,
		upload_callback: impl Fn(u32) + 'a,
	) -> impl Future<Output = Result<FileCreateOutput, SentcError>> + 'a
	{
		self.create_file_internally(jwt, file, file_name, file_part_url, sign_key, Some(upload_callback))
	}

	//______________________________________________________________________________________________
	//download

	pub async fn get_file_meta(
		&self,
		jwt: &str,
		file_id: &str,
		verify_key: Option<&UserVerifyKeyData>,
	) -> Result<(FileData, SC::SymmetricKeyWrapper, Option<String>), SentcError>
	{
		let meta = download_file_meta_information(
			&self.base_url,
			&self.app_token,
			jwt,
			file_id,
			Some(self.get_group_id()),
			self.get_access_group_as_member(),
		)
		.await?;

		//the user in get_non_registered_key should be dropped in the fn
		let key = self.get_non_registered_key_sync(&meta.master_key_id, &meta.encrypted_key)?;

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
		content_key: &impl SymKeyWrapper,
		verify_key: Option<&UserVerifyKeyData>,
		file_part_url: Option<String>,
	) -> Result<(), SentcError>
	{
		FileEncryptorDownload::<SGen::KeyGen, SC::Composer, SignC::SignKWrapper, VC>::download_parts(
			file,
			&self.base_url,
			&self.app_token,
			file_part_url,
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
		content_key: &impl SymKeyWrapper,
		upload_callback: impl Fn(u32),
		verify_key: Option<&UserVerifyKeyData>,
		file_part_url: Option<String>,
	) -> Result<(), SentcError>
	{
		FileEncryptorDownload::<SGen::KeyGen, SC::Composer, SignC::SignKWrapper, VC>::download_parts(
			file,
			&self.base_url,
			&self.app_token,
			file_part_url,
			content_key,
			&file_meta.part_list,
			Some(upload_callback),
			verify_key,
		)
		.await
	}

	pub async fn download_file(
		&self,
		jwt: &str,
		file: File,
		file_id: &str,
		verify_key: Option<&UserVerifyKeyData>,
		file_part_url: Option<String>,
	) -> Result<FileDownloadOutput<SC::SymmetricKeyWrapper>, SentcError>
	{
		let (meta, content_key, decrypted_file_name) = self.get_file_meta(jwt, file_id, verify_key).await?;

		FileEncryptorDownload::<SGen::KeyGen, SC::Composer, SignC::SignKWrapper, VC>::download_parts(
			file,
			&self.base_url,
			&self.app_token,
			file_part_url,
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
		&self,
		jwt: &str,
		file: File,
		file_id: &str,
		upload_callback: impl Fn(u32),
		verify_key: Option<&UserVerifyKeyData>,
		file_part_url: Option<String>,
	) -> Result<FileDownloadOutput<SC::SymmetricKeyWrapper>, SentcError>
	{
		let (meta, content_key, decrypted_file_name) = self.get_file_meta(jwt, file_id, verify_key).await?;

		FileEncryptorDownload::<SGen::KeyGen, SC::Composer, SignC::SignKWrapper, VC>::download_parts(
			file,
			&self.base_url,
			&self.app_token,
			file_part_url,
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
		&self,
		jwt: &str,
		path: &str,
		file_id: &str,
		verify_key: Option<&UserVerifyKeyData>,
		file_part_url: Option<String>,
	) -> Result<FileDownloadOutput<SC::SymmetricKeyWrapper>, SentcError>
	{
		let (meta, content_key, decrypted_file_name) = self.get_file_meta(jwt, file_id, verify_key).await?;

		let file_name = decrypted_file_name.as_deref().unwrap_or("file");

		//check if the file exists

		let file_name = check_if_file_exists(path, file_name).await?;

		let file = File::create(path.to_string() + MAIN_SEPARATOR_STR + &file_name)
			.await
			.map_err(SentcError::FileReadError)?;

		FileEncryptorDownload::<SGen::KeyGen, SC::Composer, SignC::SignKWrapper, VC>::download_parts(
			file,
			&self.base_url,
			&self.app_token,
			file_part_url,
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
		&self,
		jwt: &str,
		path: &str,
		file_id: &str,
		upload_callback: impl Fn(u32),
		verify_key: Option<&UserVerifyKeyData>,
		file_part_url: Option<String>,
	) -> Result<FileDownloadOutput<SC::SymmetricKeyWrapper>, SentcError>
	{
		let (meta, content_key, decrypted_file_name) = self.get_file_meta(jwt, file_id, verify_key).await?;

		let file_name = decrypted_file_name.as_deref().unwrap_or("file");

		//check if the file exists

		let file_name = check_if_file_exists(path, file_name).await?;

		let file = File::create(path.to_string() + MAIN_SEPARATOR_STR + &file_name)
			.await
			.map_err(SentcError::FileReadError)?;

		FileEncryptorDownload::<SGen::KeyGen, SC::Composer, SignC::SignKWrapper, VC>::download_parts(
			file,
			&self.base_url,
			&self.app_token,
			file_part_url,
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

	pub async fn update_file_name(
		&self,
		jwt: &str,
		file_id: &str,
		content_key: &impl SymKeyWrapper,
		file_name: Option<String>,
	) -> Result<(), SentcError>
	{
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

	pub async fn delete_file(&self, jwt: &str, file_id: &str) -> Result<(), SentcError>
	{
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
