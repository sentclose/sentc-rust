use sentc_crypto::entities::group::GroupOutData;
use sentc_crypto::entities::user::UserDataInt;
use sentc_crypto::group::Group as SdkGroup;
use sentc_crypto::sdk_common::group::{GroupHmacData, GroupInviteReqList, ListGroups};
use sentc_crypto::sdk_common::user::{OtpRegister, UserDeviceList};
use sentc_crypto::sdk_common::GroupId;
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
	SymKeyGenWrapper,
	SymKeyWrapper,
	VerifyKFromUserKeyWrapper,
};
use sentc_crypto::sdk_utils::full::user::PrepareLoginOtpOutput;
use sentc_crypto::user::User as SdkUser;
use sentc_crypto::util_req_full::group::{
	accept_invite,
	delete_sent_join_req,
	get_groups_for_user,
	get_invites_for_user,
	get_sent_join_req,
	join_req,
	reject_invite,
};
use sentc_crypto::util_req_full::user::{
	check_user_identifier_available,
	delete,
	delete_device,
	disable_otp,
	get_otp_recover_keys,
	get_user_devices,
	prepare_done_key_rotation,
	refresh_jwt,
	register_otp,
	register_raw_otp,
	reset_otp,
	reset_raw_otp,
	update,
	PreLoginOut,
};

use crate::crypto_common::user::{UserPublicKeyData, UserVerifyKeyData};
use crate::error::SentcError;
use crate::group::net::GroupFetchResult;
use crate::group::{Group, GroupKeyVerifyKeys};
use crate::net_helper::{check_jwt, get_user_verify_key_data};
use crate::user::User;

#[allow(clippy::large_enum_variant)]
pub enum UserLoginReturn<SGen, StGen, SignGen, SearchGen, SortGen, SC, StC, SignC, SearchC, SortC, PC, VC, PwH>
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
	#[allow(clippy::type_complexity)]
	Direct(User<SGen, StGen, SignGen, SearchGen, SortGen, SC, StC, SignC, SearchC, SortC, PC, VC, PwH>),
	Otp(PrepareLoginOtpOutput<PwH::DMK>),
}

impl<SGen, StGen, SignGen, SearchGen, SortGen, SC, StC, SignC, SearchC, SortC, PC, VC, PwH>
	User<SGen, StGen, SignGen, SearchGen, SortGen, SC, StC, SignC, SearchC, SortC, PC, VC, PwH>
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
	pub async fn register(base_url: String, app_token: &str, user_identifier: &str, password: &str) -> Result<String, SentcError>
	{
		if user_identifier.is_empty() || password.is_empty() {
			return Err(SentcError::UsernameOrPasswordRequired);
		}

		Ok(
			SdkUser::<SGen, StGen, SignGen, SearchGen, SortGen, SC, StC, SignC, SearchC, SortC, PC, VC, PwH>::register_req(
				base_url,
				app_token,
				user_identifier,
				password,
			)
			.await?,
		)
	}

	pub async fn register_device_start(base_url: String, app_token: &str, device_identifier: &str, password: &str) -> Result<String, SentcError>
	{
		if device_identifier.is_empty() || password.is_empty() {
			return Err(SentcError::UsernameOrPasswordRequired);
		}

		Ok(
			SdkUser::<SGen, StGen, SignGen, SearchGen, SortGen, SC, StC, SignC, SearchC, SortC, PC, VC, PwH>::register_device_start(
				base_url,
				app_token,
				device_identifier,
				password,
			)
			.await?,
		)
	}

	//______________________________________________________________________________________________

	pub async fn login(
		base_url: String,
		app_token: &str,
		device_identifier: &str,
		password: &str,
	) -> Result<UserLoginReturn<SGen, StGen, SignGen, SearchGen, SortGen, SC, StC, SignC, SearchC, SortC, PC, VC, PwH>, SentcError>
	{
		let out = SdkUser::<SGen, StGen, SignGen, SearchGen, SortGen, SC, StC, SignC, SearchC, SortC, PC, VC, PwH>::login(
			base_url.clone(),
			app_token,
			device_identifier,
			password,
		)
		.await?;

		match out {
			PreLoginOut::Direct(data) => {
				let user = User::set_user(&base_url, app_token, device_identifier.to_string(), data, false).await?;

				Ok(UserLoginReturn::Direct(user))
			},
			PreLoginOut::Otp(i) => Ok(UserLoginReturn::Otp(i)),
		}
	}

	pub async fn login_forced(
		base_url: String,
		app_token: &str,
		device_identifier: &str,
		password: &str,
	) -> Result<User<SGen, StGen, SignGen, SearchGen, SortGen, SC, StC, SignC, SearchC, SortC, PC, VC, PwH>, SentcError>
	{
		let out = SdkUser::<SGen, StGen, SignGen, SearchGen, SortGen, SC, StC, SignC, SearchC, SortC, PC, VC, PwH>::login(
			base_url.clone(),
			app_token,
			device_identifier,
			password,
		)
		.await?;

		match out {
			PreLoginOut::Direct(data) => User::set_user(&base_url, app_token, device_identifier.to_string(), data, false).await,
			PreLoginOut::Otp(_) => Err(SentcError::UserMfaRequired),
		}
	}

	pub async fn mfa_login(
		base_url: String,
		app_token: &str,
		token: String,
		device_identifier: &str,
		login_data: PrepareLoginOtpOutput<PwH::DMK>,
	) -> Result<User<SGen, StGen, SignGen, SearchGen, SortGen, SC, StC, SignC, SearchC, SortC, PC, VC, PwH>, SentcError>
	{
		let data = SdkUser::<SGen, StGen, SignGen, SearchGen, SortGen, SC, StC, SignC, SearchC, SortC, PC, VC, PwH>::mfa_login(
			base_url.clone(),
			app_token,
			&login_data.master_key,
			login_data.auth_key,
			device_identifier.to_string(),
			token,
			false,
		)
		.await?;

		User::set_user(&base_url, app_token, device_identifier.to_string(), data, true).await
	}

	pub async fn mfa_recovery_login(
		base_url: String,
		app_token: &str,
		recovery_token: String,
		device_identifier: &str,
		login_data: PrepareLoginOtpOutput<PwH::DMK>,
	) -> Result<User<SGen, StGen, SignGen, SearchGen, SortGen, SC, StC, SignC, SearchC, SortC, PC, VC, PwH>, SentcError>
	{
		let data = SdkUser::<SGen, StGen, SignGen, SearchGen, SortGen, SC, StC, SignC, SearchC, SortC, PC, VC, PwH>::mfa_login(
			base_url.clone(),
			app_token,
			&login_data.master_key,
			login_data.auth_key,
			device_identifier.to_string(),
			recovery_token,
			true,
		)
		.await?;

		User::set_user(&base_url, app_token, device_identifier.to_string(), data, true).await
	}

	//______________________________________________________________________________________________

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

	#[allow(clippy::type_complexity)]
	pub async fn prepare_get_group(
		&self,
		group_id: &str,
		group_as_member: Option<&Group<SGen, StGen, SignGen, SearchGen, SortGen, SC, StC, SignC, SearchC, SortC, PC, VC, PwH>>,
	) -> Result<(GroupOutData, GroupFetchResult), SentcError>
	{
		let jwt = self.get_jwt()?;

		let gam = group_as_member.map(|g| g.get_group_id());

		Group::<SGen, StGen, SignGen, SearchGen, SortGen, SC, StC, SignC, SearchC, SortC, PC, VC, PwH>::prepare_fetch_group(
			group_id,
			self.base_url.clone(),
			self.app_token.clone(),
			jwt,
			gam,
			Some(self),
			group_as_member,
			false,
		)
		.await
	}

	#[allow(clippy::type_complexity)]
	pub fn done_get_group(
		&self,
		data: GroupOutData,
		group_as_member: Option<&Group<SGen, StGen, SignGen, SearchGen, SortGen, SC, StC, SignC, SearchC, SortC, PC, VC, PwH>>,
		verify_keys: GroupKeyVerifyKeys,
	) -> Result<Group<SGen, StGen, SignGen, SearchGen, SortGen, SC, StC, SignC, SearchC, SortC, PC, VC, PwH>, SentcError>
	{
		Group::<SGen, StGen, SignGen, SearchGen, SortGen, SC, StC, SignC, SearchC, SortC, PC, VC, PwH>::done_fetch_group(
			self.base_url.clone(),
			self.app_token.clone(),
			false,
			data,
			Some(self),
			group_as_member,
			verify_keys,
		)
	}

	pub async fn create_group(&self, sign: bool) -> Result<GroupId, SentcError>
	{
		check_jwt(&self.jwt)?;

		let sign_key = if sign { self.get_newest_sign_key() } else { None };

		let group_id = SdkGroup::<SGen, StGen, SignGen, SearchGen, SortGen, SC, StC, SignC, SearchC, SortC, PC, VC>::create(
			self.base_url.clone(),
			&self.app_token,
			&self.jwt,
			self.get_newest_public_key()
				.ok_or(SentcError::KeyNotFound)?,
			None,
			sign_key,
			self.user_id.clone(),
		)
		.await?;

		Ok(group_id)
	}

	//______________________________________________________________________________________________

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

	pub async fn reset_password(&self, new_password: &str) -> Result<(), SentcError>
	{
		//No jwt check for reset password

		Ok(
			SdkUser::<SGen, StGen, SignGen, SearchGen, SortGen, SC, StC, SignC, SearchC, SortC, PC, VC, PwH>::reset_password_req(
				self.base_url.clone(),
				&self.app_token,
				&self.jwt,
				new_password,
				&self.private_device_key,
				&self.sign_device_key,
			)
			.await?,
		)
	}

	pub async fn change_password(
		&self,
		old_password: &str,
		new_password: &str,
		mfa_token: Option<String>,
		mfa_recovery: Option<bool>,
	) -> Result<(), SentcError>
	{
		Ok(
			SdkUser::<SGen, StGen, SignGen, SearchGen, SortGen, SC, StC, SignC, SearchC, SortC, PC, VC, PwH>::change_password_req(
				self.base_url.clone(),
				&self.app_token,
				&self.user_identifier,
				old_password,
				new_password,
				mfa_token,
				mfa_recovery,
			)
			.await?,
		)
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

		let (keys, _) = self.prepare_group_keys_ref(0);

		let (session_id, public_key) =
			SdkUser::<SGen, StGen, SignGen, SearchGen, SortGen, SC, StC, SignC, SearchC, SortC, PC, VC, PwH>::register_device(
				self.base_url.clone(),
				&self.app_token,
				&self.jwt,
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

			SdkUser::<SGen, StGen, SignGen, SearchGen, SortGen, SC, StC, SignC, SearchC, SortC, PC, VC, PwH>::device_key_session(
				self.base_url.clone(),
				&self.app_token,
				&self.jwt,
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

	pub async fn key_rotation(&mut self) -> Result<(), SentcError>
	{
		check_jwt(&self.jwt)?;

		let key_id = SdkUser::<SGen, StGen, SignGen, SearchGen, SortGen, SC, StC, SignC, SearchC, SortC, PC, VC, PwH>::key_rotation(
			self.base_url.clone(),
			&self.app_token,
			&self.jwt,
			&self.public_device_key,
			&self
				.get_newest_key()
				.ok_or(SentcError::KeyNotFound)?
				.group_key,
		)
		.await?;

		self.fetch_user_key_internally(&key_id, true).await
	}

	pub async fn finish_key_rotation(&mut self) -> Result<(), SentcError>
	{
		check_jwt(&self.jwt)?;

		let mut keys = prepare_done_key_rotation(self.base_url.clone(), &self.app_token, &self.jwt).await?;

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
							.fetch_user_key_internally(&key.previous_group_key_id, false)
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

				SdkUser::<SGen, StGen, SignGen, SearchGen, SortGen, SC, StC, SignC, SearchC, SortC, PC, VC, PwH>::done_key_rotation(
					self.base_url.clone(),
					&self.app_token,
					&self.jwt,
					key,
					&pre_pre.group_key,
					&self.public_device_key,
					&self.private_device_key,
				)
				.await?;

				self.fetch_user_key_internally(&key_id, true).await?;
			}

			//end of the for loop

			if !left_keys.is_empty() {
				keys = left_keys;
			} else {
				break;
			}
		}

		Ok(())
	}

	//==============================================================================================

	pub async fn get_user_public_key_data(&self, user_id: &str) -> Result<UserPublicKeyData, SentcError>
	{
		Ok(sentc_crypto::util_req_full::user::fetch_user_public_key(self.base_url.to_string(), &self.app_token, user_id).await?)
	}

	pub async fn get_user_verify_key_data(&self, user_id: &str, verify_key_id: &str) -> Result<UserVerifyKeyData, SentcError>
	{
		Ok(
			sentc_crypto::util_req_full::user::fetch_user_verify_key_by_id(self.base_url.to_string(), &self.app_token, user_id, verify_key_id)
				.await?,
		)
	}

	pub async fn verify_user_public_key(base_url: String, app_token: &str, user_id: &str, public_key: &UserPublicKeyData)
		-> Result<bool, SentcError>
	{
		if let (Some(_sig), Some(key_id)) = (&public_key.public_key_sig, &public_key.public_key_sig_key_id) {
			let verify_key = get_user_verify_key_data(base_url, app_token, user_id, key_id).await?;

			let verify = SdkUser::<SGen, StGen, SignGen, SearchGen, SortGen, SC, StC, SignC, SearchC, SortC, PC, VC, PwH>::verify_user_public_key(
				&verify_key,
				public_key,
			)?;

			Ok(verify)
		} else {
			Ok(false)
		}
	}

	pub async fn get_group_public_key_data(&self, group_id: &str) -> Result<UserPublicKeyData, SentcError>
	{
		Ok(sentc_crypto::util_req_full::group::get_public_key_data(self.base_url.to_string(), &self.app_token, group_id).await?)
	}

	//==============================================================================================

	#[allow(clippy::type_complexity)]
	pub(crate) async fn set_user(
		base_url: &str,
		app_token: &str,
		user_identifier: String,
		data: UserDataInt<SC::SymmetricKeyWrapper, StC::SkWrapper, StC::PkWrapper, SignC::SignKWrapper, SignC::VerifyKWrapper>,
		mfa: bool,
	) -> Result<User<SGen, StGen, SignGen, SearchGen, SortGen, SC, StC, SignC, SearchC, SortC, PC, VC, PwH>, SentcError>
	{
		let (mut u, hmac_keys) = Self::new_user(
			base_url.to_string(),
			app_token.to_string(),
			user_identifier,
			data,
			mfa,
		)?;

		//decrypt hmac keys
		for hmac_key in hmac_keys {
			u.decrypt_hmac_key(hmac_key).await?;
		}

		Ok(u)
	}

	async fn decrypt_hmac_key(&mut self, hmac_key: GroupHmacData) -> Result<(), SentcError>
	{
		let key_id = &hmac_key.encrypted_hmac_encryption_key_id;

		if let Some(k) = self.get_user_keys(key_id) {
			let decrypted_hmac_key =
				SdkGroup::<SGen, StGen, SignGen, SearchGen, SortGen, SC, StC, SignC, SearchC, SortC, PC, VC>::decrypt_group_hmac_key(
					&k.group_key,
					hmac_key,
				)?;

			self.hmac_keys.push(decrypted_hmac_key);
		} else {
			self.fetch_user_key_internally(key_id, false).await?;

			let k = self.get_user_keys(key_id).ok_or(SentcError::KeyNotFound)?;

			let decrypted_hmac_key =
				SdkGroup::<SGen, StGen, SignGen, SearchGen, SortGen, SC, StC, SignC, SearchC, SortC, PC, VC>::decrypt_group_hmac_key(
					&k.group_key,
					hmac_key,
				)?;

			self.hmac_keys.push(decrypted_hmac_key);
		}

		Ok(())
	}

	async fn get_fresh_jwt(&self, username: &str, password: &str, mfa_token: Option<String>, mfa_recovery: Option<bool>)
		-> Result<String, SentcError>
	{
		Ok(
			SdkUser::<SGen, StGen, SignGen, SearchGen, SortGen, SC, StC, SignC, SearchC, SortC, PC, VC, PwH>::get_fresh_jwt(
				self.base_url.clone(),
				&self.app_token,
				username,
				password,
				mfa_token,
				mfa_recovery,
			)
			.await?,
		)
	}

	pub fn get_jwt(&self) -> Result<&str, SentcError>
	{
		check_jwt(&self.jwt)?;

		Ok(&self.jwt)
	}

	pub(crate) async fn fetch_user_key_internally(&mut self, key_id: &str, first: bool) -> Result<(), SentcError>
	{
		//no check if the key exists needed here because this is only called internally
		check_jwt(&self.jwt)?;

		let user_keys = SdkUser::<SGen, StGen, SignGen, SearchGen, SortGen, SC, StC, SignC, SearchC, SortC, PC, VC, PwH>::fetch_user_key(
			self.base_url.clone(),
			&self.app_token,
			&self.jwt,
			key_id,
			self.get_private_device_key(),
		)
		.await?;

		if first {
			self.set_newest_key_id(user_keys.group_key.get_id().to_string());
		}

		self.extend_user_key(user_keys);

		Ok(())
	}
}

pub async fn check_user_name_available(base_url: String, app_token: &str, user_identifier: &str) -> Result<bool, SentcError>
{
	if user_identifier.is_empty() {
		return Ok(false);
	}

	Ok(check_user_identifier_available(base_url, app_token, user_identifier).await?)
}
