use std::collections::HashMap;
use std::sync::Arc;

use sentc_crypto_light::sdk_common::{GroupId, UserId};
use tokio::sync::RwLock;

use crate::error::SentcError;
use crate::group::Group;
use crate::user::User;

//each group
pub(crate) type GroupInnerMap = HashMap<GroupId, Arc<RwLock<Group>>>;
//groups for each user
pub(crate) type GroupMap = HashMap<UserId, GroupInnerMap>;

#[derive(Default)]
pub(crate) struct ActualUserId(pub(crate) UserId);

#[derive(Default)]
pub struct L1Cache
{
	groups: RwLock<GroupMap>,
	users: RwLock<HashMap<UserId, Arc<RwLock<User>>>>,
	actual_user: RwLock<ActualUserId>,
}

impl L1Cache
{
	pub fn new() -> Self
	{
		Self::default()
	}

	pub async fn get_group(&self, user_id: &str, group_id: &str) -> Option<Arc<RwLock<Group>>>
	{
		let groups = self.groups.read().await;

		groups.get(user_id).and_then(|o| o.get(group_id)).cloned()
	}

	pub async fn insert_group(&self, user_id: UserId, group_id: GroupId, group: Group) -> Result<(), SentcError>
	{
		let mut groups = self.groups.write().await;
		let groups_for_user = groups.entry(user_id).or_default();

		let group = RwLock::new(group);

		groups_for_user.insert(group_id, Arc::new(group));

		//insert in the other layer cache if any

		Ok(())
	}

	pub async fn update_cache_layer_for_group(&self, user_id: &str, group_id: &str) -> Result<(), SentcError>
	{
		//called everytime when a group was updated
		let groups = self.get_group(user_id, group_id).await;

		let _group = if let Some(g) = groups {
			g
		} else {
			return Ok(());
		};

		//update the other layer cache if any

		Ok(())
	}

	pub async fn delete_group(&self, user_id: &str, group_id: &str) -> Result<(), SentcError>
	{
		let mut groups = self.groups.write().await;

		if let Some(group_user) = groups.get_mut(user_id) {
			group_user.remove(group_id);
		}

		//update other cache layer

		Ok(())
	}

	//______________________________________________________________________________________________

	pub(crate) fn get_actual_user(&self) -> &RwLock<ActualUserId>
	{
		&self.actual_user
	}

	pub async fn set_actual_user(&self, user_id: String)
	{
		let mut lock = self.actual_user.write().await;

		lock.0 = user_id;
	}

	pub async fn get_user(&self, user_id: &str) -> Option<Arc<RwLock<User>>>
	{
		let users = self.users.read().await;

		users.get(user_id).cloned()
	}

	pub async fn insert_user(&self, user_id: UserId, user: User) -> Result<(), SentcError>
	{
		let mut users = self.users.write().await;

		let user = RwLock::new(user);

		users.insert(user_id, Arc::new(user));

		Ok(())
	}

	pub async fn update_cache_layer_for_user(&self, user_id: &str) -> Result<(), SentcError>
	{
		let user = self.get_user(user_id).await;

		let _user = if let Some(u) = user {
			u
		} else {
			return Ok(());
		};

		//update the other layer cache if any

		Ok(())
	}

	pub async fn delete_user(&self, user_id: &str) -> Result<(), SentcError>
	{
		let mut users = self.users.write().await;

		users.remove(user_id);

		//delete in other layer cache

		Ok(())
	}
}
