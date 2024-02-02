use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use sentc_crypto_light::sdk_common::group::{GroupChildrenList, GroupInviteReqList, GroupJoinReqList, ListGroups};
use sentc_crypto_light_full::group::{
	accept_invite,
	accept_join_req,
	create_child_group,
	create_connected_group,
	delete_group,
	delete_sent_join_req,
	get_all_first_level_children,
	get_group_light,
	get_groups_for_user,
	get_invites_for_user,
	get_join_reqs,
	get_sent_join_req,
	invite_user,
	join_req,
	kick_user,
	leave_group,
	reject_invite,
	reject_join_req,
	stop_group_invites,
	update_rank,
};
use tokio::sync::RwLock;

use crate::cache::l_one::L1Cache;
use crate::error::SentcError;
use crate::group::Group;
use crate::user::User;

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

		let group_id = create_child_group(
			self.base_url.clone(),
			&self.app_token,
			jwt,
			&self.group_id,
			self.rank,
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

		let group_id = create_connected_group(
			self.base_url.clone(),
			&self.app_token,
			jwt,
			&self.group_id,
			self.rank,
			self.access_by_group_as_member.as_deref(),
		)
		.await?;

		Ok(group_id)
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
		self.invite_user_internally(user_id, rank, false, false, c)
			.await
	}

	pub async fn invite_auto(&self, user_id: &str, rank: Option<i32>, c: &L1Cache) -> Result<(), SentcError>
	{
		self.invite_user_internally(user_id, rank, true, false, c)
			.await
	}

	pub async fn invite_group(&self, user_id: &str, rank: Option<i32>, c: &L1Cache) -> Result<(), SentcError>
	{
		self.invite_user_internally(user_id, rank, false, true, c)
			.await
	}

	pub async fn invite_group_auto(&self, user_id: &str, rank: Option<i32>, c: &L1Cache) -> Result<(), SentcError>
	{
		self.invite_user_internally(user_id, rank, true, true, c)
			.await
	}

	async fn invite_user_internally(&self, user_id: &str, rank: Option<i32>, auto: bool, group: bool, c: &L1Cache) -> Result<(), SentcError>
	{
		let user = c
			.get_user(&self.used_user_id)
			.await
			.ok_or(SentcError::UserNotFound)?;

		let mut user = user.write().await;

		let jwt = user.get_jwt(c).await?;

		invite_user(
			self.base_url.clone(),
			&self.app_token,
			jwt,
			self.get_group_id(),
			user_id,
			rank,
			self.rank,
			auto,
			group,
			self.access_by_group_as_member.as_deref(),
		)
		.await?;

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

	pub async fn accept_join_request(&self, user_id: &str, rank: Option<i32>, c: &L1Cache) -> Result<(), SentcError>
	{
		let user = c
			.get_user(&self.used_user_id)
			.await
			.ok_or(SentcError::UserNotFound)?;

		let mut user = user.write().await;

		let jwt = user.get_jwt(c).await?;

		accept_join_req(
			self.base_url.clone(),
			&self.app_token,
			jwt,
			self.get_group_id(),
			user_id,
			rank,
			self.rank,
			self.access_by_group_as_member.as_deref(),
		)
		.await?;

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

			let out = get_group_light(
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

			let group_id = out.group_id;

			let group = Self::new_group(
				base_url,
				app_token,
				group_id.clone(),
				out.parent_group_id,
				parent,
				out.created_time,
				out.joined_time,
				out.rank,
				out.is_connected_group,
				used_user_id,
				out.access_by_parent_group,
				out.access_by_group_as_member,
			);

			//finally set the group into the cache
			c.insert_group(user_id, group_id, group).await?;

			Ok(())
		})
	}
}
