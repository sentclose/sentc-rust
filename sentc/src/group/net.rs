use std::future::Future;

use sentc_crypto::entities::group::GroupOutData;
use sentc_crypto::group::Group as SdkGroup;
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
	VerifyKFromUserKeyWrapper,
};
use sentc_crypto::util_req_full::group::{
	accept_invite,
	delete_group,
	delete_sent_join_req,
	get_all_first_level_children,
	get_group,
	get_group_key,
	get_group_keys,
	get_group_updates,
	get_groups_for_user,
	get_invites_for_user,
	get_join_reqs,
	get_member,
	get_sent_join_req,
	join_req,
	kick_user,
	leave_group,
	prepare_done_key_rotation,
	reject_invite,
	reject_join_req,
	stop_group_invites,
	update_rank,
};

use crate::crypto_common::group::{
	GroupChildrenList,
	GroupHmacData,
	GroupInviteReqList,
	GroupJoinReqList,
	GroupKeyServerOutput,
	GroupSortableData,
	GroupUserListItem,
	KeyRotationInput,
	ListGroups,
};
use crate::crypto_common::user::{UserPublicKeyData, UserVerifyKeyData};
use crate::crypto_common::{SymKeyId, UserId};
use crate::error::SentcError;
use crate::group::Group;
use crate::net_helper::check_jwt;
use crate::user::User;

#[derive(Debug)]
pub enum GroupFetchResult
{
	Ok,
	MissingUserKeys(Vec<String>),
	MissingGroupKeys(Vec<String>),
}

pub enum GroupKeyFetchResult
{
	Done,
	Ok(GroupKeyServerOutput),
	MissingGroupKey((String, GroupKeyServerOutput)),
	MissingUserKeys((String, GroupKeyServerOutput)),
}

pub enum GroupFinishKeyRotation
{
	Empty,
	Ok(Vec<KeyRotationInput>),
	MissingKeys
	{
		rotation: Vec<KeyRotationInput>,
		group_keys: Vec<String>,
		group_private_keys: Vec<String>,
		user_private_keys: Vec<String>,
	},
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
	pub async fn get_children(&self, jwt: &str, last_fetched_item: Option<&GroupChildrenList>) -> Result<Vec<GroupChildrenList>, SentcError>
	{
		check_jwt(jwt)?;

		let (last_time, last_id) = if let Some(li) = last_fetched_item {
			(li.time, li.group_id.as_str())
		} else {
			(0, "none")
		};

		Ok(get_all_first_level_children(
			self.base_url.clone(),
			&self.app_token,
			jwt,
			self.get_group_id(),
			&last_time.to_string(),
			last_id,
			self.get_access_group_as_member(),
		)
		.await?)
	}

	pub async fn prepare_get_child_group(&self, group_id: &str, jwt: &str) -> Result<(GroupOutData, GroupFetchResult), SentcError>
	{
		check_jwt(jwt)?;

		Group::<SGen, StGen, SignGen, SearchGen, SortGen, SC, StC, SignC, SearchC, SortC, PC, VC, PwH>::prepare_fetch_group(
			group_id,
			self.base_url.clone(),
			self.app_token.clone(),
			jwt,
			self.access_by_group_as_member.as_deref(),
			None,
			Some(self),
			true,
		)
		.await
	}

	#[allow(clippy::type_complexity)]
	pub fn done_get_child_group(
		&self,
		data: GroupOutData,
	) -> Result<Group<SGen, StGen, SignGen, SearchGen, SortGen, SC, StC, SignC, SearchC, SortC, PC, VC, PwH>, SentcError>
	{
		Group::<SGen, StGen, SignGen, SearchGen, SortGen, SC, StC, SignC, SearchC, SortC, PC, VC, PwH>::done_fetch_group(
			self.base_url.clone(),
			self.app_token.clone(),
			true,
			data,
			None,
			Some(self),
		)
	}

	pub async fn prepare_get_connected_group(&self, group_id: &str, jwt: &str) -> Result<(GroupOutData, GroupFetchResult), SentcError>
	{
		check_jwt(jwt)?;

		Group::<SGen, StGen, SignGen, SearchGen, SortGen, SC, StC, SignC, SearchC, SortC, PC, VC, PwH>::prepare_fetch_group(
			group_id,
			self.base_url.clone(),
			self.app_token.clone(),
			jwt,
			Some(&self.group_id),
			None,
			Some(self),
			false,
		)
		.await
	}

	#[allow(clippy::type_complexity)]
	pub fn done_get_connected_group(
		&self,
		data: GroupOutData,
	) -> Result<Group<SGen, StGen, SignGen, SearchGen, SortGen, SC, StC, SignC, SearchC, SortC, PC, VC, PwH>, SentcError>
	{
		Group::<SGen, StGen, SignGen, SearchGen, SortGen, SC, StC, SignC, SearchC, SortC, PC, VC, PwH>::done_fetch_group(
			self.base_url.clone(),
			self.app_token.clone(),
			false,
			data,
			None,
			Some(self),
		)
	}

	pub async fn create_child_group(&self, jwt: &str) -> Result<String, SentcError>
	{
		check_jwt(jwt)?;

		let last_key = &self
			.get_newest_key()
			.ok_or(SentcError::KeyNotFound)?
			.public_group_key;

		let group_id = SdkGroup::<SGen, StGen, SignGen, SearchGen, SortGen, SC, StC, SignC, SearchC, SortC, PC, VC>::create_child_group(
			self.base_url.clone(),
			&self.app_token,
			jwt,
			&self.group_id,
			self.rank,
			last_key,
			self.access_by_group_as_member.as_deref(),
		)
		.await?;

		Ok(group_id)
	}

	pub async fn create_connected_group(&self, jwt: &str) -> Result<String, SentcError>
	{
		check_jwt(jwt)?;

		let last_key = &self
			.get_newest_key()
			.ok_or(SentcError::KeyNotFound)?
			.public_group_key;

		let group_id = SdkGroup::<SGen, StGen, SignGen, SearchGen, SortGen, SC, StC, SignC, SearchC, SortC, PC, VC>::create_connected_group(
			self.base_url.clone(),
			&self.app_token,
			jwt,
			&self.group_id,
			self.rank,
			last_key,
			self.access_by_group_as_member.as_deref(),
		)
		.await?;

		Ok(group_id)
	}

	pub async fn group_update_check(&mut self, jwt: &str) -> Result<(), SentcError>
	{
		check_jwt(jwt)?;

		let update = get_group_updates(
			self.base_url.clone(),
			&self.app_token,
			jwt,
			&self.group_id,
			self.access_by_group_as_member.as_deref(),
		)
		.await?;

		self.rank = update.rank;
		self.key_update = update.key_update;

		Ok(())
	}

	//______________________________________________________________________________________________

	#[allow(clippy::type_complexity)]
	pub async fn prepare_fetch_group_key(
		&self,
		group_key_id: &str,
		jwt: &str,
		user: Option<&User<SGen, StGen, SignGen, SearchGen, SortGen, SC, StC, SignC, SearchC, SortC, PC, VC, PwH>>,
		parent_group: Option<&Group<SGen, StGen, SignGen, SearchGen, SortGen, SC, StC, SignC, SearchC, SortC, PC, VC, PwH>>,
	) -> Result<GroupKeyFetchResult, SentcError>
	{
		check_jwt(jwt)?;

		if let Some(_k) = self.get_group_key(group_key_id) {
			return Ok(GroupKeyFetchResult::Done);
		}

		let fetched_key = get_group_key(
			self.base_url.clone(),
			&self.app_token,
			jwt,
			self.get_group_id(),
			group_key_id,
			self.get_access_group_as_member(),
		)
		.await?;

		let key_id = &fetched_key.user_public_key_id;

		//check if the master key is in the group

		let fetch_type = if self.access_by_parent.is_some() || self.access_by_group_as_member.is_some() {
			if let Some(g) = parent_group {
				if g.has_group_key(key_id).is_none() {
					GroupKeyFetchResult::MissingGroupKey((key_id.clone(), fetched_key))
				} else {
					GroupKeyFetchResult::Ok(fetched_key)
				}
			} else {
				return Err(SentcError::GroupNotFound);
			}
		} else if let Some(u) = user {
			if u.has_user_keys(key_id).is_none() {
				GroupKeyFetchResult::MissingUserKeys((key_id.clone(), fetched_key))
			} else {
				GroupKeyFetchResult::Ok(fetched_key)
			}
		} else {
			return Err(SentcError::GroupNotFound);
		};

		Ok(fetch_type)
	}

	#[allow(clippy::type_complexity)]
	pub fn done_fetch_group_key(
		&mut self,
		data: GroupKeyServerOutput,
		user: Option<&User<SGen, StGen, SignGen, SearchGen, SortGen, SC, StC, SignC, SearchC, SortC, PC, VC, PwH>>,
		parent_group: Option<&Group<SGen, StGen, SignGen, SearchGen, SortGen, SC, StC, SignC, SearchC, SortC, PC, VC, PwH>>,
	) -> Result<(), SentcError>
	{
		self.decrypt_group_keys(user, parent_group, data)
	}

	#[allow(clippy::type_complexity)]
	pub fn done_fetch_group_key_after_rotation(
		&mut self,
		data: GroupKeyServerOutput,
		user: Option<&User<SGen, StGen, SignGen, SearchGen, SortGen, SC, StC, SignC, SearchC, SortC, PC, VC, PwH>>,
		parent_group: Option<&Group<SGen, StGen, SignGen, SearchGen, SortGen, SC, StC, SignC, SearchC, SortC, PC, VC, PwH>>,
	) -> Result<(), SentcError>
	{
		let newest_key_id = data.group_key_id.clone();

		self.decrypt_group_keys(user, parent_group, data)?;

		self.set_newest_key_id(newest_key_id);
		Ok(())
	}

	#[allow(clippy::type_complexity)]
	pub async fn prepare_key_rotation(
		&self,
		jwt: &str,
		sign: bool,
		user_id: UserId,
		user: Option<&User<SGen, StGen, SignGen, SearchGen, SortGen, SC, StC, SignC, SearchC, SortC, PC, VC, PwH>>,
		parent_group: Option<&Group<SGen, StGen, SignGen, SearchGen, SortGen, SC, StC, SignC, SearchC, SortC, PC, VC, PwH>>,
	) -> Result<GroupKeyFetchResult, SentcError>
	{
		check_jwt(jwt)?;

		let pk = if !self.from_parent && self.access_by_group_as_member.is_none() {
			user.ok_or(SentcError::UserNotFound)?
				.get_newest_public_key()
				.ok_or(SentcError::KeyNotFound)?
		} else {
			&parent_group
				.ok_or(SentcError::GroupNotFound)?
				.get_newest_key()
				.ok_or(SentcError::KeyNotFound)?
				.public_group_key
		};

		let sign_key = if sign && user.is_some() {
			user.ok_or(SentcError::UserNotFound)?.get_newest_sign_key()
		} else {
			None
		};

		let key_id = SdkGroup::<SGen, StGen, SignGen, SearchGen, SortGen, SC, StC, SignC, SearchC, SortC, PC, VC>::key_rotation_req(
			self.base_url.clone(),
			&self.app_token,
			jwt,
			self.get_group_id(),
			pk,
			&self
				.get_newest_key()
				.ok_or(SentcError::KeyNotFound)?
				.group_key,
			false,
			sign_key,
			user_id,
			self.access_by_group_as_member.as_deref(),
		)
		.await?;

		self.prepare_fetch_group_key(&key_id, jwt, user, parent_group)
			.await
	}

	#[allow(clippy::type_complexity)]
	pub async fn prepare_finish_key_rotation(
		&self,
		jwt: &str,
		user: Option<&User<SGen, StGen, SignGen, SearchGen, SortGen, SC, StC, SignC, SearchC, SortC, PC, VC, PwH>>,
		parent_group: Option<&Group<SGen, StGen, SignGen, SearchGen, SortGen, SC, StC, SignC, SearchC, SortC, PC, VC, PwH>>,
	) -> Result<GroupFinishKeyRotation, SentcError>
	{
		check_jwt(jwt)?;

		let keys = prepare_done_key_rotation(
			self.base_url.clone(),
			&self.app_token,
			jwt,
			self.get_group_id(),
			false,
			self.access_by_group_as_member.as_deref(),
		)
		.await?;

		if keys.is_empty() {
			return Ok(GroupFinishKeyRotation::Empty);
		}

		let mut group_keys = Vec::new();
		let mut group_private_keys = Vec::new();
		let mut user_private_keys = Vec::new();

		for key in keys.iter() {
			//group key needs to be fetched first
			if self.has_group_key(&key.previous_group_key_id).is_none() {
				group_keys.push(key.previous_group_key_id.clone());
			}

			if !self.from_parent && self.access_by_group_as_member.is_none() {
				if user
					.ok_or(SentcError::UserNotFound)?
					.has_user_keys(&key.encrypted_eph_key_key_id)
					.is_none()
				{
					user_private_keys.push(key.encrypted_eph_key_key_id.clone());
				}
			} else if parent_group
				.ok_or(SentcError::GroupNotFound)?
				.has_group_key(&key.encrypted_eph_key_key_id)
				.is_none()
			{
				group_private_keys.push(key.encrypted_eph_key_key_id.clone());
			}
		}

		if group_keys.is_empty() && group_private_keys.is_empty() && user_private_keys.is_empty() {
			return Ok(GroupFinishKeyRotation::Ok(keys));
		}

		Ok(GroupFinishKeyRotation::MissingKeys {
			rotation: keys,
			group_keys,
			group_private_keys,
			user_private_keys,
		})
	}

	#[allow(clippy::type_complexity)]
	pub async fn done_key_rotation(
		&self,
		jwt: &str,
		keys: Vec<KeyRotationInput>,
		verify: Option<UserVerifyKeyData>,
		user: Option<&User<SGen, StGen, SignGen, SearchGen, SortGen, SC, StC, SignC, SearchC, SortC, PC, VC, PwH>>,
		parent_group: Option<&Group<SGen, StGen, SignGen, SearchGen, SortGen, SC, StC, SignC, SearchC, SortC, PC, VC, PwH>>,
	) -> Result<Vec<GroupKeyFetchResult>, SentcError>
	{
		check_jwt(jwt)?;

		//hacky way to bypass rust mut borrowing rules.
		let public_key = if !self.from_parent && self.access_by_group_as_member.is_none() {
			user.ok_or(SentcError::UserNotFound)?
				.get_newest_public_key()
				.ok_or(SentcError::KeyNotFound)?
				.clone()
		} else {
			parent_group
				.ok_or(SentcError::GroupNotFound)?
				.get_newest_key()
				.ok_or(SentcError::KeyNotFound)?
				.public_group_key
				.clone()
		};

		let mut fetch_results = Vec::new();

		for key in keys {
			let pre_key = self
				.get_group_key(&key.previous_group_key_id)
				.ok_or(SentcError::ParentGroupKeyNotFoundButRequired(
					key.previous_group_key_id.clone(),
				))?;

			let vk = match (&verify, &key.signed_by_user_sign_key_id) {
				(Some(vk), Some(_)) => Some(vk),
				_ => None,
			};

			let private_key_id = &key.encrypted_eph_key_key_id;

			let private_key = if self.from_parent || self.access_by_group_as_member.is_some() {
				//use group
				if let Some(k) = parent_group
					.ok_or(SentcError::GroupNotFound)?
					.get_group_key(private_key_id)
				{
					&k.private_group_key
				} else {
					return Err(SentcError::GroupFetchGroupKeyNotFound(private_key_id.clone()));
				}
			} else {
				//use user
				if let Some(k) = user
					.ok_or(SentcError::UserNotFound)?
					.get_user_keys(private_key_id)
				{
					&k.private_key
				} else {
					return Err(SentcError::GroupFetchUserKeyNotFound);
				}
			};

			let key_id = key.new_group_key_id.clone();

			SdkGroup::<SGen, StGen, SignGen, SearchGen, SortGen, SC, StC, SignC, SearchC, SortC, PC, VC>::done_key_rotation_req(
				self.base_url.clone(),
				&self.app_token,
				jwt,
				self.get_group_id(),
				key,
				&pre_key.group_key,
				&public_key,
				private_key,
				false,
				vk,
				self.access_by_group_as_member.as_deref(),
			)
			.await?;

			fetch_results.push(
				self.prepare_fetch_group_key(&key_id, jwt, user, parent_group)
					.await?,
			);
		}

		Ok(fetch_results)
	}

	//______________________________________________________________________________________________
	//admin fn for user management

	pub async fn update_rank(&self, jwt: &str, user_id: &str, new_rank: i32) -> Result<(), SentcError>
	{
		check_jwt(jwt)?;

		Ok(update_rank(
			self.base_url.clone(),
			&self.app_token,
			jwt,
			self.get_group_id(),
			user_id,
			new_rank,
			self.rank,
			self.access_by_group_as_member.as_deref(),
		)
		.await?)
	}

	pub async fn kick_user(&self, jwt: &str, user_id: &str) -> Result<(), SentcError>
	{
		check_jwt(jwt)?;

		Ok(kick_user(
			self.base_url.clone(),
			&self.app_token,
			jwt,
			self.get_group_id(),
			user_id,
			self.rank,
			self.access_by_group_as_member.as_deref(),
		)
		.await?)
	}

	//______________________________________________________________________________________________

	pub async fn leave(&self, jwt: &str) -> Result<(), SentcError>
	{
		check_jwt(jwt)?;

		Ok(leave_group(
			self.base_url.clone(),
			&self.app_token,
			jwt,
			self.get_group_id(),
			self.access_by_group_as_member.as_deref(),
		)
		.await?)
	}

	//______________________________________________________________________________________________

	pub async fn get_member(&self, jwt: &str, last_item: Option<&GroupUserListItem>) -> Result<Vec<GroupUserListItem>, SentcError>
	{
		check_jwt(jwt)?;

		let (last_time, last_id) = if let Some(li) = last_item {
			(li.joined_time, li.user_id.as_str())
		} else {
			(0, "none")
		};

		Ok(get_member(
			self.base_url.clone(),
			&self.app_token,
			jwt,
			self.get_group_id(),
			last_time.to_string().as_str(),
			last_id,
			self.access_by_group_as_member.as_deref(),
		)
		.await?)
	}

	//______________________________________________________________________________________________
	//group as member

	pub async fn get_groups(&self, jwt: &str, last_fetched_item: Option<&ListGroups>) -> Result<Vec<ListGroups>, SentcError>
	{
		check_jwt(jwt)?;

		let (last_time, last_id) = if let Some(li) = last_fetched_item {
			(li.time, li.group_id.as_str())
		} else {
			(0, "none")
		};

		Ok(get_groups_for_user(
			self.base_url.clone(),
			&self.app_token,
			jwt,
			&last_time.to_string(),
			last_id,
			Some(self.get_group_id()),
		)
		.await?)
	}

	pub async fn get_group_invites(&self, jwt: &str, last_item: Option<&GroupInviteReqList>) -> Result<Vec<GroupInviteReqList>, SentcError>
	{
		check_jwt(jwt)?;

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
			Some(self.get_group_id()),
			self.access_by_group_as_member.as_deref(),
		)
		.await?)
	}

	pub async fn accept_group_invite(&self, jwt: &str, group_id_to_accept: &str) -> Result<(), SentcError>
	{
		check_jwt(jwt)?;

		Ok(accept_invite(
			self.base_url.clone(),
			&self.app_token,
			jwt,
			group_id_to_accept,
			Some(self.get_group_id()),
			self.access_by_group_as_member.as_deref(),
		)
		.await?)
	}

	pub async fn reject_group_invite(&self, jwt: &str, group_id_to_reject: &str) -> Result<(), SentcError>
	{
		check_jwt(jwt)?;

		Ok(reject_invite(
			self.base_url.clone(),
			&self.app_token,
			jwt,
			group_id_to_reject,
			Some(self.get_group_id()),
			self.access_by_group_as_member.as_deref(),
		)
		.await?)
	}

	//join req to another group
	pub async fn group_join_request(&self, jwt: &str, group_id_to_join: &str) -> Result<(), SentcError>
	{
		check_jwt(jwt)?;

		Ok(join_req(
			self.base_url.clone(),
			&self.app_token,
			jwt,
			group_id_to_join,
			Some(self.get_group_id()),
			self.access_by_group_as_member.as_deref(),
		)
		.await?)
	}

	pub async fn get_group_sent_join_req(
		&self,
		jwt: &str,
		last_fetched_item: Option<&GroupInviteReqList>,
	) -> Result<Vec<GroupInviteReqList>, SentcError>
	{
		check_jwt(jwt)?;

		let (last_time, last_id) = if let Some(li) = last_fetched_item {
			(li.time, li.group_id.as_str())
		} else {
			(0, "none")
		};

		Ok(get_sent_join_req(
			self.base_url.clone(),
			&self.app_token,
			jwt,
			Some(self.get_group_id()),
			Some(self.rank),
			&last_time.to_string(),
			last_id,
			self.access_by_group_as_member.as_deref(),
		)
		.await?)
	}

	pub async fn delete_join_req(&self, id: &str, jwt: &str) -> Result<(), SentcError>
	{
		check_jwt(jwt)?;

		Ok(delete_sent_join_req(
			self.base_url.clone(),
			&self.app_token,
			jwt,
			Some(self.get_group_id()),
			Some(self.rank),
			id,
			self.access_by_group_as_member.as_deref(),
		)
		.await?)
	}

	//______________________________________________________________________________________________
	//send invite to user

	pub async fn stop_invites(&self, jwt: &str) -> Result<(), SentcError>
	{
		check_jwt(jwt)?;

		Ok(stop_group_invites(
			self.base_url.clone(),
			&self.app_token,
			jwt,
			self.get_group_id(),
			self.rank,
			self.access_by_group_as_member.as_deref(),
		)
		.await?)
	}

	pub fn invite<'a>(
		&'a self,
		jwt: &'a str,
		user_id: &'a str,
		user_key: &'a UserPublicKeyData,
		rank: Option<i32>,
	) -> impl Future<Output = Result<(), SentcError>> + 'a
	{
		self.invite_user_internally(jwt, user_id, user_key, rank, false, false, false)
	}

	pub fn invite_auto<'a>(
		&'a self,
		jwt: &'a str,
		user_id: &'a str,
		user_key: &'a UserPublicKeyData,
		rank: Option<i32>,
	) -> impl Future<Output = Result<(), SentcError>> + 'a
	{
		self.invite_user_internally(jwt, user_id, user_key, rank, true, false, false)
	}

	pub fn invite_group<'a>(
		&'a self,
		jwt: &'a str,
		user_id: &'a str,
		user_key: &'a UserPublicKeyData,
		rank: Option<i32>,
	) -> impl Future<Output = Result<(), SentcError>> + 'a
	{
		self.invite_user_internally(jwt, user_id, user_key, rank, false, true, false)
	}

	pub fn invite_group_auto<'a>(
		&'a self,
		jwt: &'a str,
		user_id: &'a str,
		user_key: &'a UserPublicKeyData,
		rank: Option<i32>,
	) -> impl Future<Output = Result<(), SentcError>> + 'a
	{
		self.invite_user_internally(jwt, user_id, user_key, rank, true, true, false)
	}

	pub fn re_invite_user<'a>(
		&'a self,
		jwt: &'a str,
		user_id: &'a str,
		user_key: &'a UserPublicKeyData,
	) -> impl Future<Output = Result<(), SentcError>> + 'a
	{
		self.invite_user_internally(jwt, user_id, user_key, None, false, false, true)
	}

	pub fn re_invite_group<'a>(
		&'a self,
		jwt: &'a str,
		user_id: &'a str,
		user_key: &'a UserPublicKeyData,
	) -> impl Future<Output = Result<(), SentcError>> + 'a
	{
		self.invite_user_internally(jwt, user_id, user_key, None, false, true, true)
	}

	#[allow(clippy::too_many_arguments)]
	async fn invite_user_internally(
		&self,
		jwt: &str,
		user_id: &str,
		user_key: &UserPublicKeyData,
		rank: Option<i32>,
		auto: bool,
		group: bool,
		re_invite: bool,
	) -> Result<(), SentcError>
	{
		let (keys, _) = self.prepare_group_keys_ref(0);

		let session_id = SdkGroup::<SGen, StGen, SignGen, SearchGen, SortGen, SC, StC, SignC, SearchC, SortC, PC, VC>::invite_user(
			self.base_url.clone(),
			&self.app_token,
			jwt,
			self.get_group_id(),
			user_id,
			self.keys.len() as i32,
			rank,
			self.rank,
			auto,
			group,
			re_invite,
			user_key,
			&keys,
			self.access_by_group_as_member.as_deref(),
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

			SdkGroup::<SGen, StGen, SignGen, SearchGen, SortGen, SC, StC, SignC, SearchC, SortC, PC, VC>::invite_user_session(
				self.base_url.clone(),
				&self.app_token,
				jwt,
				self.get_group_id(),
				&session_id,
				auto,
				user_key,
				&next_keys,
				self.access_by_group_as_member.as_deref(),
			)
			.await?;

			if !next_page {
				break;
			}

			i += 1;
		}

		Ok(())
	}

	pub async fn handle_invite_session_keys_for_new_member(
		&self,
		jwt: &str,
		user_key: &UserPublicKeyData,
		session_id: String,
		auto: bool,
	) -> Result<(), SentcError>
	{
		let mut i = 1;
		loop {
			let (next_keys, next_page) = self.prepare_group_keys_ref(i);

			SdkGroup::<SGen, StGen, SignGen, SearchGen, SortGen, SC, StC, SignC, SearchC, SortC, PC, VC>::invite_user_session(
				self.base_url.clone(),
				&self.app_token,
				jwt,
				self.get_group_id(),
				&session_id,
				auto,
				user_key,
				&next_keys,
				self.access_by_group_as_member.as_deref(),
			)
			.await?;

			if !next_page {
				break;
			}

			i += 1;
		}

		Ok(())
	}

	//______________________________________________________________________________________________
	//join req

	pub async fn get_join_requests(&self, jwt: &str, last_item: Option<&GroupJoinReqList>) -> Result<Vec<GroupJoinReqList>, SentcError>
	{
		let (last_time, last_id) = if let Some(li) = last_item {
			(li.time, li.user_id.as_str())
		} else {
			(0, "none")
		};

		Ok(get_join_reqs(
			self.base_url.clone(),
			&self.app_token,
			jwt,
			self.get_group_id(),
			self.rank,
			&last_time.to_string(),
			last_id,
			self.access_by_group_as_member.as_deref(),
		)
		.await?)
	}

	pub async fn reject_join_request(&self, jwt: &str, id_to_reject: &str) -> Result<(), SentcError>
	{
		Ok(reject_join_req(
			self.base_url.clone(),
			&self.app_token,
			jwt,
			self.get_group_id(),
			self.rank,
			id_to_reject,
			self.access_by_group_as_member.as_deref(),
		)
		.await?)
	}

	pub async fn accept_join_request(&self, jwt: &str, user_key: &UserPublicKeyData, user_id: &str, rank: Option<i32>) -> Result<(), SentcError>
	{
		let (keys, _) = self.prepare_group_keys_ref(0);

		let session_id = SdkGroup::<SGen, StGen, SignGen, SearchGen, SortGen, SC, StC, SignC, SearchC, SortC, PC, VC>::accept_join_req(
			self.base_url.clone(),
			&self.app_token,
			jwt,
			self.get_group_id(),
			user_id,
			self.keys.len() as i32,
			rank,
			self.rank,
			user_key,
			&keys,
			self.access_by_group_as_member.as_deref(),
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

			SdkGroup::<SGen, StGen, SignGen, SearchGen, SortGen, SC, StC, SignC, SearchC, SortC, PC, VC>::join_user_session(
				self.base_url.clone(),
				&self.app_token,
				jwt,
				self.get_group_id(),
				&session_id,
				user_key,
				&next_keys,
				self.access_by_group_as_member.as_deref(),
			)
			.await?;

			if !next_page {
				break;
			}

			i += 1;
		}

		Ok(())
	}

	//______________________________________________________________________________________________

	pub async fn delete_group(&self, jwt: &str) -> Result<(), SentcError>
	{
		Ok(delete_group(
			self.base_url.clone(),
			&self.app_token,
			jwt,
			self.get_group_id(),
			self.rank,
			self.access_by_group_as_member.as_deref(),
		)
		.await?)
	}

	//==============================================================================================
	//internal fn

	#[allow(clippy::too_many_arguments, clippy::type_complexity)]
	pub(crate) async fn prepare_fetch_group(
		group_id: &str,
		base_url: String,
		app_token: String,
		jwt: &str,
		group_as_member: Option<&str>,
		user: Option<&User<SGen, StGen, SignGen, SearchGen, SortGen, SC, StC, SignC, SearchC, SortC, PC, VC, PwH>>,
		parent_group: Option<&Group<SGen, StGen, SignGen, SearchGen, SortGen, SC, StC, SignC, SearchC, SortC, PC, VC, PwH>>,
		parent: bool,
	) -> Result<(GroupOutData, GroupFetchResult), SentcError>
	{
		let mut out = get_group(base_url.clone(), &app_token, jwt, group_id, group_as_member).await?;

		let key_len = out.keys.len();

		if key_len == 0 {
			return Err(SentcError::NoGroupKeysFound);
		}

		//check the keys if a key needs to be fetched
		out.keys = if key_len >= 50 {
			let last = out.keys.last().ok_or(SentcError::KeyNotFound)?;

			let more_keys = fetch_keys(
				base_url,
				&app_token,
				jwt,
				group_id,
				out.access_by_group_as_member.as_deref(),
				last.time,
				last.group_key_id.clone(),
			)
			.await?;

			[out.keys, more_keys].into_iter().flatten().collect()
		} else {
			out.keys
		};

		let fetch_type = if parent || out.access_by_group_as_member.is_some() {
			let mut missing_keys = Vec::new();

			let pg = parent_group.ok_or(SentcError::GroupNotFound)?;

			for k in out.keys.iter() {
				let key_id = &k.user_public_key_id;

				//get group key
				if pg.has_group_key(key_id).is_none() {
					missing_keys.push(key_id.to_string());
				}
			}

			if !missing_keys.is_empty() {
				GroupFetchResult::MissingGroupKeys(missing_keys)
			} else {
				GroupFetchResult::Ok
			}
		} else {
			let mut missing_keys = Vec::new();

			let u = user.ok_or(SentcError::UserNotFound)?;

			for k in out.keys.iter() {
				let key_id = &k.user_public_key_id;

				if u.has_user_keys(key_id).is_none() {
					missing_keys.push(key_id.to_string());
				}
			}

			if !missing_keys.is_empty() {
				GroupFetchResult::MissingUserKeys(missing_keys)
			} else {
				GroupFetchResult::Ok
			}
		};

		//No extra check for hmac or sortable because all keys are already fetched here. if the key does not exist then something was wrong.

		Ok((out, fetch_type))
	}

	#[allow(clippy::type_complexity)]
	pub(crate) fn done_fetch_group(
		base_url: String,
		app_token: String,
		parent: bool,
		data: GroupOutData,
		user: Option<&User<SGen, StGen, SignGen, SearchGen, SortGen, SC, StC, SignC, SearchC, SortC, PC, VC, PwH>>,
		parent_group: Option<&Group<SGen, StGen, SignGen, SearchGen, SortGen, SC, StC, SignC, SearchC, SortC, PC, VC, PwH>>,
	) -> Result<Group<SGen, StGen, SignGen, SearchGen, SortGen, SC, StC, SignC, SearchC, SortC, PC, VC, PwH>, SentcError>
	{
		let key_len = data.keys.len();

		let mut group = Self::new_group(
			base_url,
			app_token,
			data.group_id,
			data.parent_group_id,
			parent,
			data.key_update,
			data.created_time,
			data.joined_time,
			data.rank,
			data.is_connected_group,
			data.access_by_parent_group,
			data.access_by_group_as_member,
			key_len,
			data.hmac_keys.len(),
			data.sortable_keys.len(),
		);

		group.set_newest_key_id(data.keys[0].group_key_id.clone());

		//in data.keys are all keys of the group not only the first page
		for key in data.keys {
			group.decrypt_group_keys(user, parent_group, key)?;
		}

		for search_key in data.hmac_keys {
			group.decrypt_search_key(search_key)?;
		}

		for sortable_key in data.sortable_keys {
			group.decrypt_sort_key(sortable_key)?;
		}

		Ok(group)
	}

	#[allow(clippy::type_complexity)]
	fn decrypt_group_keys(
		&mut self,
		user: Option<&User<SGen, StGen, SignGen, SearchGen, SortGen, SC, StC, SignC, SearchC, SortC, PC, VC, PwH>>,
		group: Option<&Group<SGen, StGen, SignGen, SearchGen, SortGen, SC, StC, SignC, SearchC, SortC, PC, VC, PwH>>,
		fetched_keys: GroupKeyServerOutput,
	) -> Result<(), SentcError>
	{
		let key_id = &fetched_keys.user_public_key_id;

		let private_key = if self.from_parent || self.access_by_group_as_member.is_some() {
			//use group
			if let Some(k) = group
				.ok_or(SentcError::GroupNotFound)?
				.get_group_key(key_id)
			{
				&k.private_group_key
			} else {
				return Err(SentcError::GroupFetchGroupKeyNotFound(key_id.clone()));
			}
		} else {
			//use user
			if let Some(k) = user.ok_or(SentcError::UserNotFound)?.get_user_keys(key_id) {
				&k.private_key
			} else {
				return Err(SentcError::GroupFetchUserKeyNotFound);
			}
		};

		self.set_keys(private_key, fetched_keys)
	}

	fn decrypt_search_key(&mut self, hmac_key: GroupHmacData) -> Result<(), SentcError>
	{
		let key_id = &hmac_key.encrypted_hmac_encryption_key_id;

		if let Some(k) = self.get_group_key(key_id) {
			let decrypted_hmac_key =
				SdkGroup::<SGen, StGen, SignGen, SearchGen, SortGen, SC, StC, SignC, SearchC, SortC, PC, VC>::decrypt_group_hmac_key(
					&k.group_key,
					hmac_key,
				)?;

			self.hmac_keys.push(decrypted_hmac_key);
		} else {
			return Err(SentcError::GroupFetchGroupKeyNotFound(key_id.clone()));
		}

		Ok(())
	}

	fn decrypt_sort_key(&mut self, sort_key: GroupSortableData) -> Result<(), SentcError>
	{
		let key_id = &sort_key.encrypted_sortable_encryption_key_id;

		if let Some(k) = self.get_group_key(key_id) {
			let decrypted_sortable_key =
				SdkGroup::<SGen, StGen, SignGen, SearchGen, SortGen, SC, StC, SignC, SearchC, SortC, PC, VC>::decrypt_group_sortable_key(
					&k.group_key,
					sort_key,
				)?;

			self.sortable_keys.push(decrypted_sortable_key);
		} else {
			return Err(SentcError::GroupFetchGroupKeyNotFound(key_id.clone()));
		}

		Ok(())
	}
}

async fn fetch_keys(
	base_url: String,
	app_token: &str,
	jwt: &str,
	group_id: &str,
	get_access_group_as_member: Option<&str>,
	last_key_time: u128,
	last_key_id: SymKeyId,
) -> Result<Vec<GroupKeyServerOutput>, SentcError>
{
	//only fetch them, not decrypting them

	let mut last_key_time = last_key_time;
	let mut last_key_id = last_key_id;

	let mut fetched_keys = Vec::new();

	loop {
		let fetched_key = get_group_keys(
			base_url.clone(),
			app_token,
			jwt,
			group_id,
			&last_key_time.to_string(),
			&last_key_id,
			get_access_group_as_member,
		)
		.await?;

		let key_len = fetched_key.len();

		let last = fetched_key.last().ok_or(SentcError::KeyNotFound)?;
		last_key_time = last.time;
		last_key_id = last.group_key_id.clone();

		fetched_keys.push(fetched_key);

		if key_len < 50 {
			break;
		}
	}

	Ok(fetched_keys.into_iter().flatten().collect())
}
