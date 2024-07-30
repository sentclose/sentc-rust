use std::future::Future;

use sentc_crypto_light::sdk_common::group::{GroupChildrenList, GroupInviteReqList, GroupJoinReqList, ListGroups};
use sentc_crypto_light::util_req_full::group::{
	accept_invite,
	accept_join_req,
	create_child_group,
	create_connected_group,
	delete_group,
	delete_sent_join_req,
	get_all_first_level_children,
	get_group_light,
	get_group_updates,
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

use crate::error::SentcError;
use crate::group::Group;
use crate::net_helper::check_jwt;

impl Group
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

	pub fn get_child_group<'a>(&'a self, group_id: &'a str, jwt: &'a str) -> impl Future<Output = Result<Self, SentcError>> + 'a
	{
		Group::fetch_group(
			group_id,
			self.base_url.clone(),
			self.app_token.clone(),
			jwt,
			true,
			self.access_by_group_as_member.as_deref(),
		)
	}

	pub fn get_connected_group<'a>(&'a self, group_id: &'a str, jwt: &'a str) -> impl Future<Output = Result<Self, SentcError>> + 'a
	{
		Group::fetch_group(
			group_id,
			self.base_url.clone(),
			self.app_token.clone(),
			jwt,
			false,
			Some(&self.group_id),
		)
	}

	pub async fn create_child_group(&self, jwt: &str) -> Result<String, SentcError>
	{
		check_jwt(jwt)?;

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

	pub async fn create_connected_group(&self, jwt: &str) -> Result<String, SentcError>
	{
		check_jwt(jwt)?;

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

		self.rank = update;

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

	pub async fn update_own_rank(&mut self, jwt: &str, new_rank: i32) -> Result<(), SentcError>
	{
		check_jwt(jwt)?;

		self.rank = new_rank;

		Ok(())
	}

	pub async fn update_rank(&self, jwt: &str, user_id: &str, new_rank: i32) -> Result<(), SentcError>
	{
		check_jwt(jwt)?;

		self.update_rank_internally(user_id, jwt, new_rank).await
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

	pub async fn delete_join_req(&self, jwt: &str, id: &str) -> Result<(), SentcError>
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

	pub fn invite<'a>(&'a self, jwt: &'a str, user_id: &'a str, rank: Option<i32>) -> impl Future<Output = Result<(), SentcError>> + 'a
	{
		self.invite_user_internally(jwt, user_id, rank, false, false)
	}

	pub fn invite_auto<'a>(&'a self, jwt: &'a str, user_id: &'a str, rank: Option<i32>) -> impl Future<Output = Result<(), SentcError>> + 'a
	{
		self.invite_user_internally(jwt, user_id, rank, true, false)
	}

	pub fn invite_group<'a>(&'a self, jwt: &'a str, user_id: &'a str, rank: Option<i32>) -> impl Future<Output = Result<(), SentcError>> + 'a
	{
		self.invite_user_internally(jwt, user_id, rank, false, true)
	}

	pub fn invite_group_auto<'a>(&'a self, jwt: &'a str, user_id: &'a str, rank: Option<i32>) -> impl Future<Output = Result<(), SentcError>> + 'a
	{
		self.invite_user_internally(jwt, user_id, rank, true, true)
	}

	async fn invite_user_internally(&self, jwt: &str, user_id: &str, rank: Option<i32>, auto: bool, group: bool) -> Result<(), SentcError>
	{
		check_jwt(jwt)?;

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

	pub async fn get_join_requests(&self, jwt: &str, last_item: Option<&GroupJoinReqList>) -> Result<Vec<GroupJoinReqList>, SentcError>
	{
		check_jwt(jwt)?;

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
		check_jwt(jwt)?;

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

	pub async fn accept_join_request(&self, jwt: &str, user_id: &str, rank: Option<i32>) -> Result<(), SentcError>
	{
		check_jwt(jwt)?;

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

	pub async fn delete_group(&self, jwt: &str) -> Result<(), SentcError>
	{
		check_jwt(jwt)?;

		delete_group(
			self.base_url.clone(),
			&self.app_token,
			jwt,
			self.get_group_id(),
			self.rank,
			self.access_by_group_as_member.as_deref(),
		)
		.await?;

		Ok(())
	}

	//==============================================================================================
	//internal fn

	#[allow(clippy::too_many_arguments)]
	pub(crate) async fn fetch_group(
		group_id: &str,
		base_url: String,
		app_token: String,
		jwt: &str,
		parent: bool,
		group_as_member: Option<&str>,
	) -> Result<Self, SentcError>
	{
		check_jwt(jwt)?;

		let out = get_group_light(base_url.clone(), &app_token, jwt, group_id, group_as_member).await?;

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
			out.access_by_parent_group,
			out.access_by_group_as_member,
		);

		Ok(group)
	}
}
