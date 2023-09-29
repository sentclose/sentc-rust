use std::sync::Arc;

use sentc_crypto::sdk_common::user::{UserPublicKeyData, UserVerifyKeyData};
use sentc_crypto_full::user::{
	check_user_identifier_available,
	login,
	mfa_login,
	register,
	register_device_start,
	PreLoginOut,
	PrepareLoginOtpOutput,
};
use tokio::sync::RwLock;

use crate::cache::l_one::L1Cache;
use crate::error::SentcError;
use crate::net_helper::{get_group_public_key, get_user_public_key_data, get_user_verify_key_data};
use crate::sentc::Sentc;
use crate::user::User;

pub enum UserLoginReturn
{
	Direct(Arc<RwLock<User>>),
	Otp(PrepareLoginOtpOutput),
}

impl Sentc
{
	pub async fn init(base_url: &str, app_token: &str, file_part_url: Option<&str>, cache: Option<L1Cache>) -> Sentc
	{
		let mut cache = match cache {
			None => L1Cache::new(),
			Some(c) => c,
		};

		cache.file_part_url = file_part_url.map(|u| u.to_string());

		Self {
			base_url: base_url.to_string(),
			app_token: app_token.to_string(),
			cache,
		}
	}

	pub fn get_cache(&self) -> &L1Cache
	{
		&self.cache
	}

	//==============================================================================================

	pub async fn check_user_name_available(&self, user_identifier: &str) -> Result<bool, SentcError>
	{
		if user_identifier.is_empty() {
			return Ok(false);
		}

		Ok(check_user_identifier_available(self.base_url.clone(), &self.app_token, user_identifier).await?)
	}

	pub async fn register(&self, user_identifier: &str, password: &str) -> Result<String, SentcError>
	{
		if user_identifier.is_empty() || password.is_empty() {
			return Err(SentcError::UsernameOrPasswordRequired);
		}

		Ok(register(self.base_url.clone(), &self.app_token, user_identifier, password).await?)
	}

	pub async fn register_device_start(&self, device_identifier: &str, password: &str) -> Result<String, SentcError>
	{
		if device_identifier.is_empty() || password.is_empty() {
			return Err(SentcError::UsernameOrPasswordRequired);
		}

		Ok(register_device_start(self.base_url.clone(), &self.app_token, device_identifier, password).await?)
	}

	//______________________________________________________________________________________________

	pub async fn login(&self, device_identifier: &str, password: &str) -> Result<UserLoginReturn, SentcError>
	{
		let out = login(self.base_url.clone(), &self.app_token, device_identifier, password).await?;

		match out {
			PreLoginOut::Direct(data) => {
				let user_id = data.user_id.clone();
				let c = self.get_cache();

				User::set_user(
					&self.base_url,
					&self.app_token,
					device_identifier.to_string(),
					data,
					false,
					c,
				)
				.await?;

				let user = c.get_user(&user_id).await.ok_or(SentcError::UserNotFound)?;

				c.set_actual_user(user_id).await;

				Ok(UserLoginReturn::Direct(user))
			},
			PreLoginOut::Otp(i) => Ok(UserLoginReturn::Otp(i)),
		}
	}

	pub async fn login_forced(&self, device_identifier: &str, password: &str) -> Result<Arc<RwLock<User>>, SentcError>
	{
		let out = login(self.base_url.clone(), &self.app_token, device_identifier, password).await?;

		match out {
			PreLoginOut::Direct(data) => {
				let user_id = data.user_id.clone();
				let c = self.get_cache();

				User::set_user(
					&self.base_url,
					&self.app_token,
					device_identifier.to_string(),
					data,
					false,
					c,
				)
				.await?;

				let user = c.get_user(&user_id).await.ok_or(SentcError::UserNotFound)?;

				c.set_actual_user(user_id).await;

				Ok(user)
			},
			PreLoginOut::Otp(_) => Err(SentcError::UserMfaRequired),
		}
	}

	pub async fn mfa_login(&self, token: String, device_identifier: &str, login_data: PrepareLoginOtpOutput)
		-> Result<Arc<RwLock<User>>, SentcError>
	{
		let data = mfa_login(
			self.base_url.clone(),
			&self.app_token,
			&login_data.master_key,
			login_data.auth_key,
			device_identifier.to_string(),
			token,
			false,
		)
		.await?;

		let user_id = data.user_id.clone();
		let c = self.get_cache();

		User::set_user(
			&self.base_url,
			&self.app_token,
			device_identifier.to_string(),
			data,
			true,
			c,
		)
		.await?;

		let user = c.get_user(&user_id).await.ok_or(SentcError::UserNotFound)?;

		c.set_actual_user(user_id).await;

		Ok(user)
	}

	pub async fn mfa_recovery_login(
		&self,
		recovery_token: String,
		device_identifier: &str,
		login_data: PrepareLoginOtpOutput,
	) -> Result<Arc<RwLock<User>>, SentcError>
	{
		let data = mfa_login(
			self.base_url.clone(),
			&self.app_token,
			&login_data.master_key,
			login_data.auth_key,
			device_identifier.to_string(),
			recovery_token,
			true,
		)
		.await?;

		let user_id = data.user_id.clone();
		let c = self.get_cache();

		User::set_user(
			&self.base_url,
			&self.app_token,
			device_identifier.to_string(),
			data,
			true,
			c,
		)
		.await?;

		let user = c.get_user(&user_id).await.ok_or(SentcError::UserNotFound)?;

		c.set_actual_user(user_id).await;

		Ok(user)
	}

	//______________________________________________________________________________________________

	pub async fn get_actual_user(&self) -> Result<Arc<RwLock<User>>, SentcError>
	{
		let id = self.cache.get_actual_user();
		let id = id.read().await;

		let u = self.cache.get_user(&id.0).await;

		u.ok_or(SentcError::UserNotFound)
	}

	pub async fn get_user_public_key_data(&self, user_id: &str) -> Result<Arc<UserPublicKeyData>, SentcError>
	{
		get_user_public_key_data(&self.base_url, &self.app_token, user_id, self.get_cache()).await
	}

	pub async fn get_group_public_key(&self, group_id: &str) -> Result<Arc<UserPublicKeyData>, SentcError>
	{
		get_group_public_key(&self.base_url, &self.app_token, group_id, self.get_cache()).await
	}

	pub async fn get_user_verify_key_data(&self, user_id: &str, verify_key_id: &str) -> Result<Arc<UserVerifyKeyData>, SentcError>
	{
		get_user_verify_key_data(
			&self.base_url,
			&self.app_token,
			user_id,
			verify_key_id,
			self.get_cache(),
		)
		.await
	}
}
