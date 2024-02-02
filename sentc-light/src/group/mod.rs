#[cfg(feature = "network")]
pub mod net;

use sentc_crypto_light::group::prepare_change_rank;
use sentc_crypto_light::sdk_common::{GroupId, UserId};
use sentc_crypto_light::sdk_utils::group::GroupOutDataLight;

use crate::error::SentcError;

pub struct Group
{
	group_id: GroupId,
	parent_group_id: Option<GroupId>,
	from_parent: bool,
	created_time: u128,
	joined_time: u128,
	rank: i32,
	is_connected_group: bool,
	access_by_parent: Option<GroupId>,
	access_by_group_as_member: Option<GroupId>,

	base_url: String,
	app_token: String,

	//To know what user should be fetched from the cache.
	// This could not be the same user as it is stored in the group cache
	// because in the group cache the groups are stored under either the user id or connected group id
	used_user_id: UserId,
}

impl Group
{
	#[allow(clippy::too_many_arguments)]
	fn new_group(
		base_url: String,
		app_token: String,
		group_id: GroupId,
		parent_group_id: Option<GroupId>,
		from_parent: bool,
		created_time: u128,
		joined_time: u128,
		rank: i32,
		is_connected_group: bool,
		used_user_id: UserId,
		access_by_parent: Option<GroupId>,
		access_by_group_as_member: Option<GroupId>,
	) -> Self
	{
		Self {
			base_url,
			app_token,
			group_id,
			parent_group_id,
			from_parent,
			created_time,
			joined_time,
			rank,
			is_connected_group,
			used_user_id,
			access_by_parent,
			access_by_group_as_member,
		}
	}

	pub fn from_server(base_url: String, app_token: String, server_data: GroupOutDataLight, actual_user_id: UserId) -> Self
	{
		let parent = server_data.access_by_parent_group.is_some();

		Self::new_group(
			base_url,
			app_token,
			server_data.group_id,
			server_data.parent_group_id,
			parent,
			server_data.created_time,
			server_data.joined_time,
			server_data.rank,
			server_data.is_connected_group,
			actual_user_id,
			server_data.access_by_parent_group,
			server_data.access_by_group_as_member,
		)
	}

	pub fn get_group_id(&self) -> &str
	{
		&self.group_id
	}

	pub fn get_parent_group_id(&self) -> Option<&GroupId>
	{
		self.parent_group_id.as_ref()
	}

	pub fn get_fetched_from_parent_group(&self) -> bool
	{
		self.from_parent
	}

	pub fn get_rank(&self) -> i32
	{
		self.rank
	}

	pub fn get_access_group_as_member(&self) -> Option<&str>
	{
		self.access_by_group_as_member.as_deref()
	}

	pub fn prepare_update_rank(&self, user_id: &str, new_rank: i32) -> Result<String, SentcError>
	{
		Ok(prepare_change_rank(user_id, new_rank, self.rank)?)
	}

	pub fn get_created_time(&self) -> u128
	{
		self.created_time
	}

	pub fn get_joined_time(&self) -> u128
	{
		self.joined_time
	}

	pub fn is_connected_group(&self) -> bool
	{
		self.is_connected_group
	}

	pub fn access_by_parent_group(&self) -> Option<&GroupId>
	{
		self.access_by_parent.as_ref()
	}

	pub fn access_by_group_as_member(&self) -> Option<&GroupId>
	{
		self.access_by_group_as_member.as_ref()
	}
}
