use std::future::Future;

use sentc_crypto_light::sdk_common::group::{GroupInviteReqList, ListGroups};
use sentc_crypto_light::sdk_common::user::{OtpRegister, UserDeviceList};
use sentc_crypto_light::sdk_common::GroupId;
use sentc_crypto_light::util_req_full::group::{
	accept_invite,
	delete_sent_join_req,
	get_groups_for_user,
	get_invites_for_user,
	get_sent_join_req,
	join_req,
	reject_invite,
};
use sentc_crypto_light::util_req_full::user::{
	change_password,
	check_user_identifier_available,
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
	PreLoginOut,
	PrepareLoginOtpOutput,
};
use sentc_crypto_light::UserDataInt;

use crate::error::SentcError;
use crate::group::Group;
use crate::net_helper::check_jwt;
use crate::user::User;

#[allow(clippy::large_enum_variant)]
pub enum UserLoginReturn
{
	Direct(User),
	Otp(PrepareLoginOtpOutput),
}

impl User
{
	pub fn get_group<'a>(&'a self, group_id: &'a str, group_as_member: Option<&'a str>) -> impl Future<Output = Result<Group, SentcError>> + 'a
	{
		Group::fetch_group(
			group_id,
			self.base_url.clone(),
			self.app_token.clone(),
			&self.jwt,
			false,
			group_as_member,
		)
	}

	pub async fn create_group(&self) -> Result<GroupId, SentcError>
	{
		check_jwt(&self.jwt)?;

		let group_id = sentc_crypto_light::util_req_full::group::create(self.base_url.clone(), &self.app_token, &self.jwt, None).await?;

		Ok(group_id)
	}

	pub async fn get_groups(&self, last_item: Option<&ListGroups>) -> Result<Vec<ListGroups>, SentcError>
	{
		check_jwt(&self.jwt)?;

		let (last_time, last_id) = if let Some(li) = last_item {
			(li.time, li.group_id.as_str())
		} else {
			(0, "none")
		};

		Ok(get_groups_for_user(
			self.base_url.clone(),
			&self.app_token,
			&self.jwt,
			last_time.to_string().as_str(),
			last_id,
			None,
		)
		.await?)
	}

	pub async fn get_group_invites(&self, last_item: Option<&GroupInviteReqList>) -> Result<Vec<GroupInviteReqList>, SentcError>
	{
		check_jwt(&self.jwt)?;

		let (last_time, last_id) = if let Some(li) = last_item {
			(li.time, li.group_id.as_str())
		} else {
			(0, "none")
		};

		Ok(get_invites_for_user(
			self.base_url.clone(),
			&self.app_token,
			&self.jwt,
			&last_time.to_string(),
			last_id,
			None,
			None,
		)
		.await?)
	}

	pub async fn accept_group_invite(&self, group_id_to_accept: &str) -> Result<(), SentcError>
	{
		check_jwt(&self.jwt)?;

		Ok(accept_invite(
			self.base_url.clone(),
			&self.app_token,
			&self.jwt,
			group_id_to_accept,
			None,
			None,
		)
		.await?)
	}

	pub async fn reject_group_invite(&self, group_id_to_reject: &str) -> Result<(), SentcError>
	{
		check_jwt(&self.jwt)?;

		Ok(reject_invite(
			self.base_url.clone(),
			&self.app_token,
			&self.jwt,
			group_id_to_reject,
			None,
			None,
		)
		.await?)
	}

	pub async fn group_join_request(&self, group_id_to_join: &str) -> Result<(), SentcError>
	{
		check_jwt(&self.jwt)?;

		Ok(join_req(
			self.base_url.clone(),
			&self.app_token,
			&self.jwt,
			group_id_to_join,
			None,
			None,
		)
		.await?)
	}

	pub async fn delete_join_req(&self, id: &str) -> Result<(), SentcError>
	{
		check_jwt(&self.jwt)?;

		Ok(delete_sent_join_req(
			self.base_url.clone(),
			&self.app_token,
			&self.jwt,
			None,
			None,
			id,
			None,
		)
		.await?)
	}

	pub async fn get_sent_join_req(&self, last_fetched_item: Option<&GroupInviteReqList>) -> Result<Vec<GroupInviteReqList>, SentcError>
	{
		check_jwt(&self.jwt)?;

		let (last_time, last_id) = if let Some(li) = last_fetched_item {
			(li.time, li.group_id.as_str())
		} else {
			(0, "none")
		};

		Ok(get_sent_join_req(
			self.base_url.clone(),
			&self.app_token,
			&self.jwt,
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

	pub async fn register_raw_otp(&mut self, password: &str, mfa_token: Option<String>, mfa_recovery: Option<bool>)
		-> Result<OtpRegister, SentcError>
	{
		let jwt = self
			.get_fresh_jwt(&self.user_identifier, password, mfa_token, mfa_recovery)
			.await?;

		let out = register_raw_otp(self.base_url.clone(), &self.app_token, &jwt).await?;

		self.mfa = true;

		Ok(out)
	}

	pub async fn register_otp(
		&mut self,
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

		let (url, recover) = register_otp(self.base_url.clone(), &self.app_token, issuer, audience, &jwt).await?;

		self.mfa = true;

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
	pub async fn reset_password(&self, new_password: &str) -> Result<(), SentcError>
	{
		check_jwt(&self.jwt)?;

		Ok(reset_password(self.base_url.clone(), &self.app_token, &self.jwt, new_password).await?)
	}

	pub async fn change_password(
		&self,
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

	pub async fn update_user(&mut self, new_identifier: String) -> Result<(), SentcError>
	{
		check_jwt(&self.jwt)?;

		update(
			self.base_url.clone(),
			&self.app_token,
			&self.jwt,
			new_identifier.clone(),
		)
		.await?;

		self.user_identifier = new_identifier;

		Ok(())
	}

	pub async fn delete(&self, password: &str, mfa_token: Option<String>, mfa_recovery: Option<bool>) -> Result<(), SentcError>
	{
		let jwt = self
			.get_fresh_jwt(&self.user_identifier, password, mfa_token, mfa_recovery)
			.await?;

		delete(self.base_url.clone(), &self.app_token, &jwt).await?;

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

	pub async fn register_device(&self, server_output: &str) -> Result<(), SentcError>
	{
		check_jwt(&self.jwt)?;

		let jwt = self.get_jwt_sync();

		Ok(register_device(self.base_url.clone(), &self.app_token, jwt, server_output).await?)
	}

	pub async fn get_devices(&self, last_item: Option<&UserDeviceList>) -> Result<Vec<UserDeviceList>, SentcError>
	{
		check_jwt(&self.jwt)?;

		let (last_time, last_id) = if let Some(li) = last_item {
			(li.time, li.device_id.as_str())
		} else {
			(0, "none")
		};

		Ok(get_user_devices(
			self.base_url.clone(),
			&self.app_token,
			&self.jwt,
			&last_time.to_string(),
			last_id,
		)
		.await?)
	}

	//==============================================================================================

	pub(crate) async fn set_user(
		base_url: String,
		app_token: String,
		user_identifier: String,
		data: UserDataInt,
		mfa: bool,
	) -> Result<Self, SentcError>
	{
		Self::new_user(base_url, app_token, user_identifier, data, mfa)
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

	pub async fn get_jwt(&self) -> Result<&str, SentcError>
	{
		check_jwt(&self.jwt)?;

		Ok(&self.jwt)
	}

	pub async fn refresh_jwt(&mut self) -> Result<&str, SentcError>
	{
		self.jwt = refresh_jwt(
			self.base_url.clone(),
			&self.app_token,
			&self.jwt,
			self.refresh_token.clone(),
		)
		.await?;

		Ok(&self.jwt)
	}
}

pub async fn check_user_name_available(base_url: String, app_token: &str, user_identifier: &str) -> Result<bool, SentcError>
{
	if user_identifier.is_empty() {
		return Ok(false);
	}

	Ok(check_user_identifier_available(base_url, app_token, user_identifier).await?)
}

pub async fn register(base_url: String, app_token: &str, user_identifier: &str, password: &str) -> Result<String, SentcError>
{
	if user_identifier.is_empty() || password.is_empty() {
		return Err(SentcError::UsernameOrPasswordRequired);
	}

	Ok(sentc_crypto_light::util_req_full::user::register(base_url, app_token, user_identifier, password).await?)
}

pub async fn register_device_start(base_url: String, app_token: &str, device_identifier: &str, password: &str) -> Result<String, SentcError>
{
	if device_identifier.is_empty() || password.is_empty() {
		return Err(SentcError::UsernameOrPasswordRequired);
	}

	Ok(sentc_crypto_light::util_req_full::user::register_device_start(base_url, app_token, device_identifier, password).await?)
}

//__________________________________________________________________________________________________

pub async fn login(base_url: String, app_token: String, device_identifier: &str, password: &str) -> Result<UserLoginReturn, SentcError>
{
	let out = sentc_crypto_light::util_req_full::user::login(base_url.clone(), &app_token, device_identifier, password).await?;

	match out {
		PreLoginOut::Direct(data) => {
			let user = User::set_user(base_url, app_token, device_identifier.to_string(), data, false).await?;

			Ok(UserLoginReturn::Direct(user))
		},
		PreLoginOut::Otp(i) => Ok(UserLoginReturn::Otp(i)),
	}
}

pub async fn login_forced(base_url: String, app_token: String, device_identifier: &str, password: &str) -> Result<User, SentcError>
{
	let out = sentc_crypto_light::util_req_full::user::login(base_url.clone(), &app_token, device_identifier, password).await?;

	match out {
		PreLoginOut::Direct(data) => {
			let user = User::set_user(base_url, app_token, device_identifier.to_string(), data, false).await?;

			Ok(user)
		},
		PreLoginOut::Otp(_) => Err(SentcError::UserMfaRequired),
	}
}

pub async fn mfa_login(
	base_url: String,
	app_token: String,
	token: String,
	device_identifier: &str,
	login_data: PrepareLoginOtpOutput,
) -> Result<User, SentcError>
{
	let data = sentc_crypto_light::util_req_full::user::mfa_login(
		base_url.clone(),
		&app_token,
		&login_data.master_key,
		login_data.auth_key,
		device_identifier.to_string(),
		token,
		false,
	)
	.await?;

	let user = User::set_user(base_url, app_token, device_identifier.to_string(), data, true).await?;

	Ok(user)
}

pub async fn mfa_recovery_login(
	base_url: String,
	app_token: String,
	recovery_token: String,
	device_identifier: &str,
	login_data: PrepareLoginOtpOutput,
) -> Result<User, SentcError>
{
	let data = sentc_crypto_light::util_req_full::user::mfa_login(
		base_url.clone(),
		&app_token,
		&login_data.master_key,
		login_data.auth_key,
		device_identifier.to_string(),
		recovery_token,
		true,
	)
	.await?;

	let user = User::set_user(base_url, app_token, device_identifier.to_string(), data, true).await?;

	Ok(user)
}
