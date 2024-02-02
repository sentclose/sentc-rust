use std::sync::Arc;

use sentc_crypto_light::sdk_common::group::{GroupInviteReqList, ListGroups};
use sentc_crypto_light::sdk_common::user::{OtpRegister, UserDeviceList};
use sentc_crypto_light::sdk_common::GroupId;
use sentc_crypto_light::UserDataInt;
use sentc_crypto_light_full::decode_jwt;
use sentc_crypto_light_full::group::{
	accept_invite,
	delete_sent_join_req,
	get_groups_for_user,
	get_invites_for_user,
	get_sent_join_req,
	join_req,
	reject_invite,
};
use sentc_crypto_light_full::user::{
	change_password,
	delete,
	delete_device,
	disable_otp,
	get_fresh_jwt,
	get_otp_recover_keys,
	get_user_devices,
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
use crate::error::SentcError;
use crate::group::Group;
use crate::net_helper::get_time;
use crate::user::User;

impl User
{
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

		let group_id = sentc_crypto_light_full::group::create(self.base_url.clone(), &self.app_token, jwt, None).await?;

		Ok(group_id)
	}

	pub async fn get_groups(&mut self, c: &L1Cache, last_item: Option<&ListGroups>) -> Result<Vec<ListGroups>, SentcError>
	{
		self.check_jwt(c).await?;
		let jwt = &self.jwt;

		let (last_time, last_id) = if let Some(li) = last_item {
			(li.time, li.group_id.as_str())
		} else {
			(0, "none")
		};

		Ok(get_groups_for_user(
			self.base_url.clone(),
			&self.app_token,
			jwt,
			last_time.to_string().as_str(),
			last_id,
			None,
		)
		.await?)
	}

	pub async fn get_group_invites(&mut self, c: &L1Cache, last_item: Option<&GroupInviteReqList>) -> Result<Vec<GroupInviteReqList>, SentcError>
	{
		self.check_jwt(c).await?;
		let jwt = &self.jwt;

		let (last_time, last_id) = if let Some(li) = last_item {
			(li.time, li.group_id.as_str())
		} else {
			(0, "none")
		};

		Ok(get_invites_for_user(
			self.base_url.clone(),
			&self.app_token,
			jwt,
			&last_time.to_string(),
			last_id,
			None,
			None,
		)
		.await?)
	}

	pub async fn accept_group_invite(&mut self, group_id_to_accept: &str, c: &L1Cache) -> Result<(), SentcError>
	{
		self.check_jwt(c).await?;
		let jwt = &self.jwt;

		Ok(accept_invite(
			self.base_url.clone(),
			&self.app_token,
			jwt,
			group_id_to_accept,
			None,
			None,
		)
		.await?)
	}

	pub async fn reject_group_invite(&mut self, group_id_to_reject: &str, c: &L1Cache) -> Result<(), SentcError>
	{
		self.check_jwt(c).await?;
		let jwt = &self.jwt;

		Ok(reject_invite(
			self.base_url.clone(),
			&self.app_token,
			jwt,
			group_id_to_reject,
			None,
			None,
		)
		.await?)
	}

	pub async fn group_join_request(&mut self, group_id_to_join: &str, c: &L1Cache) -> Result<(), SentcError>
	{
		self.check_jwt(c).await?;
		let jwt = &self.jwt;

		Ok(join_req(
			self.base_url.clone(),
			&self.app_token,
			jwt,
			group_id_to_join,
			None,
			None,
		)
		.await?)
	}

	pub async fn delete_join_req(&mut self, id: &str, c: &L1Cache) -> Result<(), SentcError>
	{
		self.check_jwt(c).await?;
		let jwt = &self.jwt;

		Ok(delete_sent_join_req(self.base_url.clone(), &self.app_token, jwt, None, None, id, None).await?)
	}

	pub async fn get_sent_join_req(
		&mut self,
		c: &L1Cache,
		last_fetched_item: Option<&GroupInviteReqList>,
	) -> Result<Vec<GroupInviteReqList>, SentcError>
	{
		self.check_jwt(c).await?;
		let jwt = &self.jwt;

		let (last_time, last_id) = if let Some(li) = last_fetched_item {
			(li.time, li.group_id.as_str())
		} else {
			(0, "none")
		};

		Ok(get_sent_join_req(
			self.base_url.clone(),
			&self.app_token,
			jwt,
			None,
			None,
			&last_time.to_string(),
			last_id,
			None,
		)
		.await?)
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

	/**
	Resets the password of a device of a user.

	This req can only be done with the secret token from your backend, not your frontend!
	 */
	pub async fn reset_password(&mut self, new_password: &str, c: &L1Cache) -> Result<(), SentcError>
	{
		self.check_jwt(c).await?;

		let jwt = self.get_jwt_sync();

		Ok(reset_password(self.base_url.clone(), &self.app_token, jwt, new_password).await?)
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

		self.logout(c).await?;

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

	pub async fn logout(&self, c: &L1Cache) -> Result<(), SentcError>
	{
		c.delete_user(self.get_user_id()).await
	}

	//==============================================================================================

	pub async fn register_device(&mut self, server_output: &str, c: &L1Cache) -> Result<(), SentcError>
	{
		self.check_jwt(c).await?;

		let jwt = self.get_jwt_sync();

		Ok(register_device(self.base_url.clone(), &self.app_token, jwt, server_output).await?)
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

		let u = Self::new_user(
			base_url.to_string(),
			app_token.to_string(),
			user_identifier,
			data,
			mfa,
		)?;

		c.insert_user(user_id, u).await?;

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
}
