use std::sync::Arc;

use sentc_crypto::entities::user::UserDataInt;
use sentc_crypto::sdk_common::group::GroupHmacData;
use sentc_crypto::sdk_common::user::{OtpRegister, UserDeviceList};
use sentc_crypto::sdk_common::GroupId;
use sentc_crypto_full::decode_jwt;
use sentc_crypto_full::user::{
	change_password,
	delete,
	delete_device,
	device_key_session,
	disable_otp,
	done_key_rotation,
	fetch_user_key,
	get_fresh_jwt,
	get_otp_recover_keys,
	get_user_devices,
	key_rotation,
	prepare_done_key_rotation,
	refresh_jwt,
	register_device,
	register_otp,
	register_raw_otp,
	reset_otp,
	reset_password,
	reset_raw_otp,
	update,
};

use crate::cache::l_one::L1Cache;
use crate::decrypt_hmac_key;
use crate::error::SentcError;
use crate::group::Group;
use crate::user::User;

macro_rules! get_user_key {
	($key_id:expr, $self:expr, $c:expr, |$key:ident| $scope:block) => {
		#[allow(clippy::unnecessary_mut_passed)]
		match $self.get_user_keys($key_id) {
			Some($key) => $scope,
			None => {
				$self.fetch_user_key_internally($key_id, false, $c).await?;

				let $key = &$self
					.get_user_keys($key_id)
					.ok_or(SentcError::KeyNotFound)?;

				$scope
			},
		}
	};
}

macro_rules! get_user_private_key {
	($key_id:expr, $self:expr, $c:expr, |$private_key:ident| $scope:block) => {
		get_user_key!($key_id, $self, $c, |key| {
			let $private_key = &key.private_key;
			$scope
		})
	};
}

macro_rules! get_user_public_key {
	($key_id:expr, $self:expr, $c:expr, |$public_key:ident| $scope:block) => {
		get_user_key!($key_id, $self, $c, |key| {
			let $public_key = &key.public_key;
			$scope
		})
	};
}

pub(crate) use {get_user_key, get_user_private_key, get_user_public_key};

use crate::net_helper::get_time;

impl User
{
	pub fn new() -> Self
	{
		//TODO remove
		todo!()
	}

	pub async fn get_group(
		&mut self,
		group_id: &str,
		group_as_member: Option<&str>,
		c: &L1Cache,
	) -> Result<Arc<tokio::sync::RwLock<Group>>, SentcError>
	{
		Group::fetch_group(
			group_id,
			self.base_url.clone(),
			self.app_token.clone(),
			self,
			false,
			group_as_member,
			false,
			c,
		)
		.await?;

		let user_id = if let Some(gam) = group_as_member { gam } else { self.get_user_id() };

		c.get_group(user_id, group_id)
			.await
			.ok_or(SentcError::GroupNotFound)
	}

	pub async fn create_group(&mut self, c: &L1Cache) -> Result<GroupId, SentcError>
	{
		self.check_jwt(c).await?;
		let jwt = &self.jwt;

		let group_id = sentc_crypto_full::group::create(
			self.base_url.clone(),
			&self.app_token,
			jwt,
			self.get_newest_public_key()
				.ok_or(SentcError::KeyNotFound)?,
			None,
		)
		.await?;

		Ok(group_id)
	}

	//==============================================================================================
	//otp

	pub async fn register_raw_otp(
		&mut self,
		password: &str,
		mfa_token: Option<String>,
		mfa_recovery: Option<bool>,
		c: &L1Cache,
	) -> Result<OtpRegister, SentcError>
	{
		let jwt = self
			.get_fresh_jwt(&self.user_identifier, password, mfa_token, mfa_recovery)
			.await?;

		let out = register_raw_otp(self.base_url.clone(), &self.app_token, &jwt).await?;

		self.mfa = true;
		c.update_cache_layer_for_user(&self.user_id).await?;

		Ok(out)
	}

	pub async fn register_otp(
		&mut self,
		issuer: &str,
		audience: &str,
		password: &str,
		mfa_token: Option<String>,
		mfa_recovery: Option<bool>,
		c: &L1Cache,
	) -> Result<(String, Vec<String>), SentcError>
	{
		let jwt = self
			.get_fresh_jwt(&self.user_identifier, password, mfa_token, mfa_recovery)
			.await?;

		let (url, recover) = register_otp(self.base_url.clone(), &self.app_token, issuer, audience, &jwt).await?;

		self.mfa = true;

		c.update_cache_layer_for_user(&self.user_id).await?;

		Ok((url, recover))
	}

	pub async fn get_otp_recover_keys(&self, password: &str, mfa_token: Option<String>, mfa_recovery: Option<bool>)
		-> Result<Vec<String>, SentcError>
	{
		let jwt = self
			.get_fresh_jwt(&self.user_identifier, password, mfa_token, mfa_recovery)
			.await?;

		let out = get_otp_recover_keys(self.base_url.clone(), &self.app_token, &jwt).await?;

		Ok(out.keys)
	}

	pub async fn reset_raw_otp(&self, password: &str, mfa_token: Option<String>, mfa_recovery: Option<bool>) -> Result<OtpRegister, SentcError>
	{
		let jwt = self
			.get_fresh_jwt(&self.user_identifier, password, mfa_token, mfa_recovery)
			.await?;

		Ok(reset_raw_otp(self.base_url.clone(), &self.app_token, &jwt).await?)
	}

	pub async fn reset_otp(
		&self,
		issuer: &str,
		audience: &str,
		password: &str,
		mfa_token: Option<String>,
		mfa_recovery: Option<bool>,
	) -> Result<(String, Vec<String>), SentcError>
	{
		let jwt = self
			.get_fresh_jwt(&self.user_identifier, password, mfa_token, mfa_recovery)
			.await?;

		Ok(reset_otp(self.base_url.clone(), &self.app_token, issuer, audience, &jwt).await?)
	}

	pub async fn disable_otp(&mut self, password: &str, mfa_token: Option<String>, mfa_recovery: Option<bool>) -> Result<(), SentcError>
	{
		let jwt = self
			.get_fresh_jwt(&self.user_identifier, password, mfa_token, mfa_recovery)
			.await?;

		disable_otp(self.base_url.clone(), &self.app_token, &jwt).await?;

		self.mfa = false;

		Ok(())
	}

	//==============================================================================================

	pub async fn reset_password(&mut self, new_password: &str, c: &L1Cache) -> Result<(), SentcError>
	{
		self.check_jwt(c).await?;

		let jwt = self.get_jwt_sync();

		Ok(reset_password(
			self.base_url.clone(),
			&self.app_token,
			jwt,
			new_password,
			&self.private_device_key,
			&self.sign_device_key,
		)
		.await?)
	}

	pub async fn change_password(
		&mut self,
		old_password: &str,
		new_password: &str,
		mfa_token: Option<String>,
		mfa_recovery: Option<bool>,
	) -> Result<(), SentcError>
	{
		Ok(change_password(
			self.base_url.clone(),
			&self.app_token,
			&self.user_identifier,
			old_password,
			new_password,
			mfa_token,
			mfa_recovery,
		)
		.await?)
	}

	pub async fn update_user(&mut self, new_identifier: String, c: &L1Cache) -> Result<(), SentcError>
	{
		self.check_jwt(c).await?;

		let jwt = self.get_jwt_sync();

		update(self.base_url.clone(), &self.app_token, jwt, new_identifier.clone()).await?;

		self.user_identifier = new_identifier;

		c.update_cache_layer_for_user(self.get_user_id()).await?;

		Ok(())
	}

	pub async fn delete(&self, password: &str, mfa_token: Option<String>, mfa_recovery: Option<bool>, c: &L1Cache) -> Result<(), SentcError>
	{
		let jwt = self
			.get_fresh_jwt(&self.user_identifier, password, mfa_token, mfa_recovery)
			.await?;

		delete(self.base_url.clone(), &self.app_token, &jwt).await?;

		c.delete_user(self.get_user_id()).await?;

		Ok(())
	}

	pub async fn delete_device(
		&self,
		password: &str,
		device_id: &str,
		mfa_token: Option<String>,
		mfa_recovery: Option<bool>,
	) -> Result<(), SentcError>
	{
		let jwt = self
			.get_fresh_jwt(&self.user_identifier, password, mfa_token, mfa_recovery)
			.await?;

		delete_device(self.base_url.clone(), &self.app_token, &jwt, device_id).await?;

		Ok(())
	}

	//==============================================================================================

	pub async fn register_device(&mut self, server_output: &str, c: &L1Cache) -> Result<(), SentcError>
	{
		self.check_jwt(c).await?;

		let (keys, _) = self.prepare_group_keys_ref(0);

		let jwt = self.get_jwt_sync();

		let (session_id, public_key) = register_device(
			self.base_url.clone(),
			&self.app_token,
			jwt,
			server_output,
			self.user_keys.len() as i32,
			&keys,
		)
		.await?;

		let session_id = if let Some(id) = session_id {
			id
		} else {
			return Ok(());
		};

		let mut i = 1;
		loop {
			let (next_keys, next_page) = self.prepare_group_keys_ref(i);

			device_key_session(
				self.base_url.clone(),
				&self.app_token,
				jwt,
				&session_id,
				&public_key,
				&next_keys,
			)
			.await?;

			if !next_page {
				break;
			}

			i += 1;
		}

		Ok(())
	}

	pub async fn get_devices(&mut self, last_item: Option<&UserDeviceList>, c: &L1Cache) -> Result<Vec<UserDeviceList>, SentcError>
	{
		self.check_jwt(c).await?;

		let jwt = self.get_jwt_sync();

		let (last_time, last_id) = if let Some(li) = last_item {
			(li.time, li.device_id.as_str())
		} else {
			(0, "none")
		};

		Ok(get_user_devices(
			self.base_url.clone(),
			&self.app_token,
			jwt,
			&last_time.to_string(),
			last_id,
		)
		.await?)
	}

	//==============================================================================================

	pub async fn key_rotation(&mut self, c: &L1Cache) -> Result<(), SentcError>
	{
		self.check_jwt(c).await?;

		let key_id = key_rotation(
			self.base_url.clone(),
			&self.app_token,
			self.get_jwt_sync(),
			&self.public_device_key,
			&self
				.get_newest_key()
				.ok_or(SentcError::KeyNotFound)?
				.group_key,
		)
		.await?;

		self.fetch_user_key_internally(&key_id, true, c).await
	}

	pub async fn finish_key_rotation(&mut self, c: &L1Cache) -> Result<(), SentcError>
	{
		self.check_jwt(c).await?;

		let jwt = self.get_jwt_sync().to_string();

		let mut keys = prepare_done_key_rotation(self.base_url.clone(), &self.app_token, &jwt).await?;

		if keys.is_empty() {
			return Ok(());
		}

		for _i in 0..10 {
			//outer loop for the rotation tires

			let mut left_keys = Vec::new();

			'l2: for key in keys {
				let pre_pre = match self.get_user_keys(&key.previous_group_key_id) {
					Some(k) => k,
					None => {
						match self
							.fetch_user_key_internally(&key.previous_group_key_id, false, c)
							.await
						{
							Ok(_) => {},
							Err(_) => {
								left_keys.push(key);
								continue 'l2;
							},
						}

						self.get_user_keys(&key.previous_group_key_id)
							.ok_or(SentcError::KeyNotFound)?
					},
				};

				let key_id = key.new_group_key_id.clone();

				done_key_rotation(
					self.base_url.clone(),
					&self.app_token,
					&jwt,
					key,
					&pre_pre.group_key,
					&self.public_device_key,
					&self.private_device_key,
				)
				.await?;

				self.fetch_user_key_internally(&key_id, false, c).await?;
			}

			//end of the for loop

			if !left_keys.is_empty() {
				keys = left_keys;
			} else {
				break;
			}
		}

		c.update_cache_layer_for_user(self.get_user_id()).await?;

		Ok(())
	}

	//==============================================================================================

	pub(crate) async fn set_user(
		base_url: &str,
		app_token: &str,
		user_identifier: String,
		data: UserDataInt,
		mfa: bool,
		c: &L1Cache,
	) -> Result<(), SentcError>
	{
		let user_id = data.user_id.clone();

		let (mut u, hmac_keys) = Self::new_user(
			base_url.to_string(),
			app_token.to_string(),
			user_identifier,
			data,
			mfa,
		)?;

		//decrypt hmac keys
		for hmac_key in hmac_keys {
			u.decrypt_hmac_key(hmac_key, c).await?;
		}

		c.insert_user(user_id, u).await?;

		Ok(())
	}

	async fn decrypt_hmac_key(&mut self, hmac_key: GroupHmacData, c: &L1Cache) -> Result<(), SentcError>
	{
		let key_id = &hmac_key.encrypted_hmac_encryption_key_id;

		if let Some(k) = self.get_user_keys(key_id) {
			decrypt_hmac_key!(&k.group_key, self, hmac_key);
		} else {
			self.fetch_user_key_internally(key_id, false, c).await?;

			let k = self.get_user_keys(key_id).ok_or(SentcError::KeyNotFound)?;

			decrypt_hmac_key!(&k.group_key, self, hmac_key);
		}

		Ok(())
	}

	pub(crate) async fn check_jwt(&mut self, c: &L1Cache) -> Result<(), SentcError>
	{
		//internal fn to get and check the jwt internally.
		// in a struct fn we can't use get jwt together if immutable borrow because get_jwt is mut borrow

		let jwt_data = decode_jwt(&self.jwt)?;

		if jwt_data.exp > (get_time()? + 30) as usize {
			return Ok(());
		}

		self.jwt = refresh_jwt(
			self.base_url.clone(),
			&self.app_token,
			&self.jwt,
			self.refresh_token.clone(),
		)
		.await?;

		//update the layer cache
		c.update_cache_layer_for_user(self.get_user_id()).await?;

		Ok(())
	}

	async fn get_fresh_jwt(&self, username: &str, password: &str, mfa_token: Option<String>, mfa_recovery: Option<bool>)
		-> Result<String, SentcError>
	{
		Ok(get_fresh_jwt(
			self.base_url.clone(),
			&self.app_token,
			username,
			password,
			mfa_token,
			mfa_recovery,
		)
		.await?)
	}

	pub async fn get_jwt(&mut self, c: &L1Cache) -> Result<&str, SentcError>
	{
		self.check_jwt(c).await?;

		Ok(&self.jwt)
	}

	pub(crate) async fn fetch_user_key_internally(&mut self, key_id: &str, first: bool, c: &L1Cache) -> Result<(), SentcError>
	{
		//no check if the key exists needed here because this is only called internally
		self.check_jwt(c).await?;

		let user_keys = fetch_user_key(
			self.base_url.clone(),
			&self.app_token,
			&self.jwt,
			key_id,
			self.get_private_device_key(),
		)
		.await?;

		if first {
			self.set_newest_key_id(user_keys.group_key.key_id.clone());
		}

		self.extend_user_key(user_keys);

		c.update_cache_layer_for_user(self.get_user_id()).await?;

		Ok(())
	}
}
