use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use sentc_crypto::entities::group::GroupKeyData;
use sentc_crypto::sdk_common::group::{
	GroupChildrenList,
	GroupHmacData,
	GroupInviteReqList,
	GroupJoinReqList,
	GroupKeyServerOutput,
	GroupSortableData,
	ListGroups,
};
use sentc_crypto_full::group::{
	accept_invite,
	accept_join_req,
	create_child_group,
	create_connected_group,
	delete_group,
	delete_sent_join_req,
	done_key_rotation,
	get_all_first_level_children,
	get_group,
	get_group_key,
	get_group_keys,
	get_group_updates,
	get_groups_for_user,
	get_invites_for_user,
	get_join_reqs,
	get_sent_join_req,
	invite_user,
	invite_user_session,
	join_req,
	join_user_session,
	key_rotation,
	kick_user,
	leave_group,
	prepare_done_key_rotation,
	reject_invite,
	reject_join_req,
	stop_group_invites,
	update_rank,
};
use tokio::sync::RwLock;

use crate::cache::l_one::L1Cache;
use crate::error::SentcError;
use crate::group::Group;
use crate::net_helper::{get_group_public_key, get_user_public_key_data, get_user_verify_key_data};
use crate::user::net::{get_user_key, get_user_private_key};
use crate::user::User;
use crate::{decrypt_hmac_key, decrypt_sort_key};

macro_rules! get_group_key_by_id {
	($key_id:expr, $user: expr, $self: expr, $c:expr, |$key:ident| $scope:block) => {{
		#[allow(clippy::unnecessary_mut_passed)]
		let group = $self.get_group_ref($user, $c).await?;

		//get the group via read access.
		// not write access yet,
		// because this is only needed once when the key was not set and not everytime when reading it.
		let group_read = group.read().await;

		match group_read.get_group_key($key_id) {
			Some($key) => $scope,
			None => {
				//key was not found -> fetch the key
				//drop the read guard otherwise we got a deadlock
				// where we are waiting here to access but the read access is still valid
				drop(group_read);

				//only use write guard if the key is not set, this should be really the case, so it is fine to get the groups again
				let mut group_write = group.write().await;

				group_write
					.fetch_group_key_internally($key_id, $user, false, $c)
					.await?;

				let $key = &group_write
					.get_group_key($key_id)
					.ok_or(SentcError::ParentGroupKeyNotFoundButRequired)?;

				$scope
			},
		}
	}};
}

macro_rules! get_private_key {
	($key_id:expr, $user: expr, $self: expr, $c:expr, |$private_key:ident| $scope:block) => {
		if !$self.from_parent && $self.access_by_group_as_member.is_none() {
			get_user_private_key!($key_id, $user, $c, |$private_key| { $scope })
		} else {
			get_group_key_by_id!($key_id, $user, $self, $c, |key| {
				let $private_key = &key.private_group_key;
				$scope
			})
		}
	};
}

/**
Gets the public key either from the user or the parent / connected group.

This is not the self group public key!
 */
macro_rules! get_public_key {
	($user:expr, $self:expr, $c:expr, |$public_key:ident| $scope:block) => {
		if !$self.from_parent && $self.access_by_group_as_member.is_none() {
			let $public_key = $user
				.get_newest_public_key()
				.ok_or(SentcError::KeyNotFound)?;
			$scope
		} else {
			let group_ref = $self.get_group_ref($user, $c).await?;

			let group_read = group_ref.read().await;

			let $public_key = &group_read
				.get_newest_key()
				.ok_or(SentcError::KeyNotFound)?
				.public_group_key;
			$scope
		}
	};
}

macro_rules! user_jwt {
	($self:expr, $c:expr, |$jwt:ident| $scope:block) => {{
		let user = $c
			.get_user(&$self.used_user_id)
			.await
			.ok_or(SentcError::UserNotFound)?;

		let mut user = user.write().await;

		let $jwt = user.get_jwt($c).await?;

		$scope
	}};
}

/**
Gets a group key and fetch it if it doesn't exists.

This macro does the same as get_and_fetch_key but without the boxed fut if the key exists.
It still needs an some kind owned version of a group (like WriteLock from RwLock)
 */
#[macro_export]
macro_rules! group_key {
	($group:expr, $key_id:expr, $c:expr) => {
		match $group.get_group_key($key_id) {
			Some(k) => Ok(k),
			None => {
				$group.fetch_group_key($key_id, $c).await?;

				$group
					.get_group_key($key_id)
					.ok_or($crate::error::SentcError::KeyNotFound)
			},
		}
	};
}

macro_rules! group_key_internally {
	($self:expr,$key_id:expr, $user:expr, $c:expr) => {
		match $self.get_group_key($key_id) {
			Some(k) => Ok(k),
			None => {
				$self
					.fetch_group_key_internally($key_id, $user, false, $c)
					.await?;

				$self
					.get_group_key($key_id)
					.ok_or($crate::error::SentcError::KeyNotFound)
			},
		}
	};
}

pub(super) use group_key_internally;

impl Group
{
	pub async fn get_children(&self, last_fetched_item: Option<&GroupChildrenList>, c: &L1Cache) -> Result<Vec<GroupChildrenList>, SentcError>
	{
		user_jwt!(self, c, |jwt| {
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
		})
	}

	pub async fn get_child_group(&self, group_id: &str, c: &L1Cache) -> Result<Arc<RwLock<Group>>, SentcError>
	{
		let user = c
			.get_user(&self.used_user_id)
			.await
			.ok_or(SentcError::UserNotFound)?;

		let mut user = user.write().await;

		Group::fetch_group(
			group_id,
			self.base_url.clone(),
			self.app_token.clone(),
			&mut user,
			true,
			self.access_by_group_as_member.as_deref(),
			false,
			c,
		)
		.await?;

		let user_id = if let Some(gam) = &self.access_by_group_as_member {
			gam
		} else {
			user.get_user_id()
		};

		c.get_group(user_id, group_id)
			.await
			.ok_or(SentcError::GroupNotFound)
	}

	pub async fn get_connected_group(&self, group_id: &str, c: &L1Cache) -> Result<Arc<RwLock<Group>>, SentcError>
	{
		let user = c
			.get_user(&self.used_user_id)
			.await
			.ok_or(SentcError::UserNotFound)?;

		let mut user = user.write().await;

		Group::fetch_group(
			group_id,
			self.base_url.clone(),
			self.app_token.clone(),
			&mut user,
			false,
			Some(&self.group_id),
			false,
			c,
		)
		.await?;

		c.get_group(&self.group_id, group_id)
			.await
			.ok_or(SentcError::GroupNotFound)
	}

	pub async fn create_child_group(&self, c: &L1Cache) -> Result<String, SentcError>
	{
		let user = c
			.get_user(&self.used_user_id)
			.await
			.ok_or(SentcError::UserNotFound)?;

		let mut user = user.write().await;

		let jwt = user.get_jwt(c).await?;

		let last_key = &self
			.get_newest_key()
			.ok_or(SentcError::KeyNotFound)?
			.public_group_key;

		let group_id = create_child_group(
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

	pub async fn create_connected_group(&self, c: &L1Cache) -> Result<String, SentcError>
	{
		let user = c
			.get_user(&self.used_user_id)
			.await
			.ok_or(SentcError::UserNotFound)?;

		let mut user = user.write().await;

		let jwt = user.get_jwt(c).await?;

		let last_key = &self
			.get_newest_key()
			.ok_or(SentcError::KeyNotFound)?
			.public_group_key;

		let group_id = create_connected_group(
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

	pub async fn group_update_check(&mut self, c: &L1Cache) -> Result<(), SentcError>
	{
		let user = c
			.get_user(&self.used_user_id)
			.await
			.ok_or(SentcError::UserNotFound)?;

		let mut user = user.write().await;

		let jwt = user.get_jwt(c).await?;

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

	pub async fn fetch_group_key(&mut self, group_key_id: &str, c: &L1Cache) -> Result<(), SentcError>
	{
		if let Some(_k) = self.get_group_key(group_key_id) {
			return Ok(());
		}

		let user = c
			.get_user(&self.used_user_id)
			.await
			.ok_or(SentcError::UserNotFound)?;

		let mut user = user.write().await;

		self.fetch_group_key_internally(group_key_id, &mut user, false, c)
			.await
	}

	pub async fn get_and_fetch_key(&mut self, group_key_id: &str, c: &L1Cache) -> Result<&GroupKeyData, SentcError>
	{
		//if key exists, no fetch is done.
		self.fetch_group_key(group_key_id, c).await?;

		self.get_group_key(group_key_id)
			.ok_or(SentcError::KeyNotFound)
	}

	pub async fn key_rotation(&mut self, sign: bool, c: &L1Cache) -> Result<(), SentcError>
	{
		let user = c
			.get_user(&self.used_user_id)
			.await
			.ok_or(SentcError::UserNotFound)?;

		let mut user = user.write().await;

		user.check_jwt(c).await?;

		let jwt = user.get_jwt_sync();

		let sign_key = if sign { user.get_newest_sign_key() } else { None };

		get_public_key!(&user, self, c, |public_key| {
			let key_id = key_rotation(
				self.base_url.clone(),
				&self.app_token,
				jwt,
				self.get_group_id(),
				public_key,
				&self
					.get_newest_key()
					.ok_or(SentcError::KeyNotFound)?
					.group_key,
				false,
				sign_key,
				user.get_user_id().to_string(),
				self.access_by_group_as_member.as_deref(),
			)
			.await?;

			self.fetch_group_key_internally(&key_id, &mut user, true, c)
				.await
		})
	}

	pub async fn finish_key_rotation(&mut self, verify: bool, c: &L1Cache) -> Result<(), SentcError>
	{
		let user = c
			.get_user(&self.used_user_id)
			.await
			.ok_or(SentcError::UserNotFound)?;

		let mut user = user.write().await;

		user.check_jwt(c).await?;

		let jwt = user.get_jwt_sync().to_string();

		let mut keys = prepare_done_key_rotation(
			self.base_url.clone(),
			&self.app_token,
			&jwt,
			self.get_group_id(),
			false,
			self.access_by_group_as_member.as_deref(),
		)
		.await?;

		if keys.is_empty() {
			return Ok(());
		}

		//hacky way to bypass rust mut borrowing rules.
		let public_key = if !self.from_parent && self.access_by_group_as_member.is_none() {
			user.get_newest_public_key()
				.ok_or(SentcError::KeyNotFound)?
				.clone()
		} else {
			let group_ref = self.get_group_ref(&user, c).await?;

			let group_read = group_ref.read().await;

			group_read
				.get_newest_key()
				.ok_or(SentcError::KeyNotFound)?
				.public_group_key
				.clone()
		};

		for _i in 0..10 {
			//outer loop for the rotation tires

			let mut left_keys = Vec::new();

			'l2: for key in keys {
				//inner loop for the keys of each rotation

				let pre_key = match self.get_group_key(&key.previous_group_key_id) {
					Some(k) => k,
					None => {
						match self.fetch_group_key(&key.previous_group_key_id, c).await {
							Ok(_) => {},
							Err(_e) => {
								left_keys.push(key);
								continue 'l2;
							},
						}

						self.get_group_key(&key.previous_group_key_id)
							.ok_or(SentcError::KeyNotFound)?
					},
				};

				let verify_key = match (verify, &key.signed_by_user_id, &key.signed_by_user_sign_key_id) {
					(true, Some(signed_by_user_id), Some(signed_by_user_sign_key_id)) => {
						let k = get_user_verify_key_data(
							&self.base_url,
							&self.app_token,
							signed_by_user_id,
							signed_by_user_sign_key_id,
							c,
						)
						.await?;

						Some(k)
					},
					_ => None,
				};

				get_private_key!(&key.encrypted_eph_key_key_id, &mut user, self, c, |private_key| {
					let key_id = key.new_group_key_id.clone();

					done_key_rotation(
						self.base_url.clone(),
						&self.app_token,
						&jwt,
						self.get_group_id(),
						key,
						&pre_key.group_key,
						&public_key,
						private_key,
						false,
						verify_key.as_deref(),
						self.access_by_group_as_member.as_deref(),
					)
					.await?;

					self.fetch_group_key_internally(&key_id, &mut user, true, c)
						.await?;
				});
			}

			//end of the for loop

			if !left_keys.is_empty() {
				keys = left_keys;
			} else {
				break;
			}
		}

		let user_id = if let Some(gam) = &self.access_by_group_as_member {
			gam
		} else {
			user.get_user_id()
		};

		//update the other cache layer
		c.update_cache_layer_for_group(user_id, self.get_group_id())
			.await?;

		Ok(())
	}

	//______________________________________________________________________________________________
	//admin fn for user management

	async fn update_rank_internally(&self, user_id: &str, jwt: &str, new_rank: i32) -> Result<(), SentcError>
	{
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

	pub async fn update_own_rank(&mut self, new_rank: i32, c: &L1Cache) -> Result<(), SentcError>
	{
		let user = c
			.get_user(&self.used_user_id)
			.await
			.ok_or(SentcError::UserNotFound)?;

		let mut user = user.write().await;

		user.check_jwt(c).await?;

		let jwt = user.get_jwt_sync();

		let user_id = if let Some(g) = &self.access_by_group_as_member {
			g
		} else {
			user.get_user_id()
		};

		self.update_rank_internally(user_id, jwt, new_rank).await?;

		self.rank = new_rank;

		c.update_cache_layer_for_group(user_id, self.get_group_id())
			.await
	}

	pub async fn update_rank(&self, user_id: &str, new_rank: i32, c: &L1Cache) -> Result<(), SentcError>
	{
		let user = c
			.get_user(&self.used_user_id)
			.await
			.ok_or(SentcError::UserNotFound)?;

		let mut user = user.write().await;

		let jwt = user.get_jwt(c).await?;

		self.update_rank_internally(user_id, jwt, new_rank).await
	}

	pub async fn kick_user(&self, user_id: &str, c: &L1Cache) -> Result<(), SentcError>
	{
		user_jwt!(self, c, |jwt| {
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
		})
	}

	//______________________________________________________________________________________________

	pub async fn leave(&self, c: &L1Cache) -> Result<(), SentcError>
	{
		user_jwt!(self, c, |jwt| {
			Ok(leave_group(
				self.base_url.clone(),
				&self.app_token,
				jwt,
				self.get_group_id(),
				self.access_by_group_as_member.as_deref(),
			)
			.await?)
		})
	}

	//______________________________________________________________________________________________
	//group as member

	pub async fn get_groups(&self, c: &L1Cache, last_fetched_item: Option<&ListGroups>) -> Result<Vec<ListGroups>, SentcError>
	{
		user_jwt!(self, c, |jwt| {
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
		})
	}

	pub async fn get_group_invites(&self, c: &L1Cache, last_item: Option<&GroupInviteReqList>) -> Result<Vec<GroupInviteReqList>, SentcError>
	{
		user_jwt!(self, c, |jwt| {
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
		})
	}

	pub async fn accept_group_invite(&self, group_id_to_accept: &str, c: &L1Cache) -> Result<(), SentcError>
	{
		user_jwt!(self, c, |jwt| {
			Ok(accept_invite(
				self.base_url.clone(),
				&self.app_token,
				jwt,
				group_id_to_accept,
				Some(self.get_group_id()),
				self.access_by_group_as_member.as_deref(),
			)
			.await?)
		})
	}

	pub async fn reject_group_invite(&self, group_id_to_reject: &str, c: &L1Cache) -> Result<(), SentcError>
	{
		user_jwt!(self, c, |jwt| {
			Ok(reject_invite(
				self.base_url.clone(),
				&self.app_token,
				jwt,
				group_id_to_reject,
				Some(self.get_group_id()),
				self.access_by_group_as_member.as_deref(),
			)
			.await?)
		})
	}

	//join req to another group
	pub async fn group_join_request(&self, group_id_to_join: &str, c: &L1Cache) -> Result<(), SentcError>
	{
		user_jwt!(self, c, |jwt| {
			Ok(join_req(
				self.base_url.clone(),
				&self.app_token,
				jwt,
				group_id_to_join,
				Some(self.get_group_id()),
				self.access_by_group_as_member.as_deref(),
			)
			.await?)
		})
	}

	pub async fn get_group_sent_join_req(
		&self,
		c: &L1Cache,
		last_fetched_item: Option<&GroupInviteReqList>,
	) -> Result<Vec<GroupInviteReqList>, SentcError>
	{
		user_jwt!(self, c, |jwt| {
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
		})
	}

	pub async fn delete_join_req(&self, id: &str, c: &L1Cache) -> Result<(), SentcError>
	{
		user_jwt!(self, c, |jwt| {
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
		})
	}

	//______________________________________________________________________________________________
	//send invite to user

	pub async fn stop_invites(&self, c: &L1Cache) -> Result<(), SentcError>
	{
		user_jwt!(self, c, |jwt| {
			Ok(stop_group_invites(
				self.base_url.clone(),
				&self.app_token,
				jwt,
				self.get_group_id(),
				self.rank,
				self.access_by_group_as_member.as_deref(),
			)
			.await?)
		})
	}

	pub async fn invite(&self, user_id: &str, rank: Option<i32>, c: &L1Cache) -> Result<(), SentcError>
	{
		self.invite_user_internally(user_id, rank, false, false, false, c)
			.await
	}

	pub async fn invite_auto(&self, user_id: &str, rank: Option<i32>, c: &L1Cache) -> Result<(), SentcError>
	{
		self.invite_user_internally(user_id, rank, true, false, false, c)
			.await
	}

	pub async fn invite_group(&self, user_id: &str, rank: Option<i32>, c: &L1Cache) -> Result<(), SentcError>
	{
		self.invite_user_internally(user_id, rank, false, true, false, c)
			.await
	}

	pub async fn invite_group_auto(&self, user_id: &str, rank: Option<i32>, c: &L1Cache) -> Result<(), SentcError>
	{
		self.invite_user_internally(user_id, rank, true, true, false, c)
			.await
	}

	pub async fn re_invite_user(&self, user_id: &str, c: &L1Cache) -> Result<(), SentcError>
	{
		self.invite_user_internally(user_id, None, false, false, true, c)
			.await
	}

	pub async fn re_invite_group(&self, user_id: &str, c: &L1Cache) -> Result<(), SentcError>
	{
		self.invite_user_internally(user_id, None, false, true, true, c)
			.await
	}

	async fn invite_user_internally(
		&self,
		user_id: &str,
		rank: Option<i32>,
		auto: bool,
		group: bool,
		re_invite: bool,
		c: &L1Cache,
	) -> Result<(), SentcError>
	{
		let user_key = if group {
			get_group_public_key(&self.base_url, &self.app_token, user_id, c).await?
		} else {
			get_user_public_key_data(&self.base_url, &self.app_token, user_id, c).await?
		};

		let (keys, _) = self.prepare_group_keys_ref(0);

		let user = c
			.get_user(&self.used_user_id)
			.await
			.ok_or(SentcError::UserNotFound)?;

		let mut user = user.write().await;

		let jwt = user.get_jwt(c).await?;

		let session_id = invite_user(
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
			&user_key,
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

			invite_user_session(
				self.base_url.clone(),
				&self.app_token,
				jwt,
				self.get_group_id(),
				&session_id,
				auto,
				&user_key,
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

	pub async fn get_join_requests(&self, last_item: Option<&GroupJoinReqList>, c: &L1Cache) -> Result<Vec<GroupJoinReqList>, SentcError>
	{
		user_jwt!(self, c, |jwt| {
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
		})
	}

	pub async fn reject_join_request(&self, id_to_reject: &str, c: &L1Cache) -> Result<(), SentcError>
	{
		user_jwt!(self, c, |jwt| {
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
		})
	}

	pub async fn accept_join_request(&self, user_id: &str, user_type: i32, rank: Option<i32>, c: &L1Cache) -> Result<(), SentcError>
	{
		let user_key = if user_type == 2 {
			get_group_public_key(&self.base_url, &self.app_token, user_id, c).await?
		} else {
			get_user_public_key_data(&self.base_url, &self.app_token, user_id, c).await?
		};

		let (keys, _) = self.prepare_group_keys_ref(0);

		let user = c
			.get_user(&self.used_user_id)
			.await
			.ok_or(SentcError::UserNotFound)?;

		let mut user = user.write().await;

		let jwt = user.get_jwt(c).await?;

		let session_id = accept_join_req(
			self.base_url.clone(),
			&self.app_token,
			jwt,
			self.get_group_id(),
			user_id,
			self.keys.len() as i32,
			rank,
			self.rank,
			&user_key,
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

			join_user_session(
				self.base_url.clone(),
				&self.app_token,
				jwt,
				self.get_group_id(),
				&session_id,
				&user_key,
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

	pub async fn delete_group(&self, c: &L1Cache) -> Result<(), SentcError>
	{
		let user = c
			.get_user(&self.used_user_id)
			.await
			.ok_or(SentcError::UserNotFound)?;

		let mut user = user.write().await;

		let jwt = user.get_jwt(c).await?;

		delete_group(
			self.base_url.clone(),
			&self.app_token,
			jwt,
			self.get_group_id(),
			self.rank,
			self.access_by_group_as_member.as_deref(),
		)
		.await?;

		let user_id = if let Some(gam) = &self.access_by_group_as_member {
			gam
		} else {
			user.get_user_id()
		};

		c.delete_group(user_id, self.get_group_id()).await?;

		Ok(())
	}

	//==============================================================================================
	//internal fn

	#[allow(clippy::too_many_arguments)]
	pub(crate) fn fetch_group<'a>(
		group_id: &'a str,
		base_url: String,
		app_token: String,
		user: &'a mut User,
		parent: bool,
		group_as_member: Option<&'a str>,
		rek: bool,
		c: &'a L1Cache,
	) -> Pin<Box<dyn Future<Output = Result<(), SentcError>> + 'a>>
	{
		Box::pin(async move {
			let user_id = if let Some(gam) = group_as_member { gam } else { user.get_user_id() };

			if let Some(_g) = c.get_group(user_id, group_id).await {
				return Ok(());
			}

			let user_id = user_id.to_string();
			let used_user_id = user.get_user_id().to_string();

			let out = get_group(
				base_url.clone(),
				&app_token,
				user.get_jwt(c).await?,
				group_id,
				group_as_member,
			)
			.await?;

			if let Some(gam) = &out.access_by_group_as_member {
				//only load the group once even for rek. calls.
				// otherwise when access_by_parent_group is also set this group will be checked again when loading the parent
				if !rek {
					//if group as member set. load this group first to get the keys
					//no group as member flag
					Self::fetch_group(gam, base_url.clone(), app_token.clone(), user, false, None, false, c).await?;
				}
			}

			let parent = if let Some(gap) = &out.access_by_parent_group {
				//check if the parent group is fetched
				//rec here because the user might be in a parent of the parent group or so
				//check the tree until we found the group where the user access by user
				Self::fetch_group(
					gap,
					base_url.clone(),
					app_token.clone(),
					user,
					false,
					group_as_member,
					true,
					c,
				)
				.await?;

				true
			} else {
				parent
			};

			let key_len = out.keys.len();

			if key_len == 0 {
				return Err(SentcError::NoGroupKeysFound);
			}

			let group_id = out.group_id;

			let mut group = Self::new_group(
				base_url,
				app_token,
				group_id.clone(),
				out.parent_group_id,
				parent,
				out.key_update,
				out.created_time,
				out.joined_time,
				out.rank,
				out.is_connected_group,
				used_user_id,
				out.access_by_parent_group,
				out.access_by_group_as_member,
				key_len,
				out.hmac_keys.len(),
				out.sortable_keys.len(),
			);

			group.set_newest_key_id(out.keys[0].group_key_id.clone());

			for key in out.keys {
				group.decrypt_group_keys(user, key, c).await?;
			}

			if key_len >= 50 {
				group.fetch_keys(user, c).await?;
			}

			//after all keys done, set the search and sort keys
			for search_key in out.hmac_keys {
				group.decrypt_search_key(user, search_key, c).await?;
			}

			for sortable_key in out.sortable_keys {
				group.decrypt_sort_key(user, sortable_key, c).await?;
			}

			//finally set the group into the cache
			c.insert_group(user_id, group_id, group).await?;

			Ok(())
		})
	}

	async fn get_group_ref(&self, user: &User, c: &L1Cache) -> Result<Arc<RwLock<Group>>, SentcError>
	{
		if self.from_parent {
			//check here if the group was accessed by group as member.
			// if so then the parent group is stored under the connected group id not the suer id
			let user_id = self
				.access_by_group_as_member
				.as_deref()
				.unwrap_or(user.get_user_id());

			let parent_group_id = self
				.parent_group_id
				.as_ref()
				.ok_or(SentcError::ParentGroupNotFoundButRequired)?;

			//get the requested group
			c.get_group(user_id, parent_group_id)
				.await
				.ok_or(SentcError::ParentGroupNotFoundButRequired)
		} else {
			//analog to the parent group fetch but this time with the direct user id
			let connected_group_id = self
				.access_by_group_as_member
				.as_ref()
				.ok_or(SentcError::ConnectedGroupNotFoundButRequired)?;

			c.get_group(user.get_user_id(), connected_group_id)
				.await
				.ok_or(SentcError::ConnectedGroupNotFoundButRequired)
		}
	}

	async fn decrypt_group_keys(&mut self, user: &mut User, fetched_keys: GroupKeyServerOutput, c: &L1Cache) -> Result<(), SentcError>
	{
		let key_id = &fetched_keys.user_public_key_id;
		get_private_key!(key_id, user, self, c, |private_key| {
			self.set_keys(private_key, fetched_keys)
		})
	}

	async fn decrypt_search_key(&mut self, user: &mut User, hmac_key: GroupHmacData, c: &L1Cache) -> Result<(), SentcError>
	{
		let key_id = &hmac_key.encrypted_hmac_encryption_key_id;

		if let Some(gk) = self.get_group_key(key_id) {
			decrypt_hmac_key!(&gk.group_key, self, hmac_key);
		} else {
			self.fetch_group_key_internally(key_id, user, false, c)
				.await?;

			let gk = self.get_group_key(key_id).ok_or(SentcError::KeyNotFound)?;
			decrypt_hmac_key!(&gk.group_key, self, hmac_key);
		}

		Ok(())
	}

	async fn decrypt_sort_key(&mut self, user: &mut User, sort_key: GroupSortableData, c: &L1Cache) -> Result<(), SentcError>
	{
		let key_id = &sort_key.encrypted_sortable_encryption_key_id;

		if let Some(gk) = self.get_group_key(key_id) {
			decrypt_sort_key!(&gk.group_key, self, sort_key);
		} else {
			self.fetch_group_key_internally(key_id, user, false, c)
				.await?;

			let gk = self.get_group_key(key_id).ok_or(SentcError::KeyNotFound)?;
			decrypt_sort_key!(&gk.group_key, self, sort_key);
		}

		Ok(())
	}

	async fn fetch_keys(&mut self, user: &mut User, c: &L1Cache) -> Result<(), SentcError>
	{
		let mut last_key = self.get_last_key()?;

		loop {
			let fetched_keys = get_group_keys(
				self.base_url.clone(),
				&self.app_token,
				user.get_jwt(c).await?,
				self.get_group_id(),
				last_key.time.to_string().as_str(),
				&last_key.group_key.key_id,
				self.get_access_group_as_member(),
			)
			.await?;

			let key_len = fetched_keys.len();

			self.prepare_for_more_keys(key_len);

			for fetched_key in fetched_keys {
				self.decrypt_group_keys(user, fetched_key, c).await?;
			}

			if key_len < 50 {
				break;
			}

			//get the new key
			last_key = self.get_last_key()?;
		}

		Ok(())
	}

	pub(super) fn fetch_group_key_internally<'a>(
		&'a mut self,
		group_key_id: &'a str,
		user: &'a mut User,
		new_keys: bool,
		c: &'a L1Cache,
	) -> Pin<Box<dyn Future<Output = Result<(), SentcError>> + 'a>>
	{
		//boxed because of the async recursion
		Box::pin(async move {
			//no check if the key exists needed here because this is only called internally
			let jwt = user.get_jwt(c).await?;

			let fetched_key = get_group_key(
				self.base_url.clone(),
				&self.app_token,
				jwt,
				self.get_group_id(),
				group_key_id,
				self.get_access_group_as_member(),
			)
			.await?;

			let group_key_id = fetched_key.group_key_id.clone();

			self.decrypt_group_keys(user, fetched_key, c).await?;

			if new_keys {
				self.set_newest_key_id(group_key_id);
			}

			let user_id = if let Some(gam) = &self.access_by_group_as_member {
				gam
			} else {
				user.get_user_id()
			};

			//update the other cache layer
			c.update_cache_layer_for_group(user_id, self.get_group_id())
				.await?;

			Ok(())
		})
	}
}
