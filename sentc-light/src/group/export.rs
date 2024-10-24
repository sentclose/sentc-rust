use std::str::FromStr;

use sentc_crypto_light::sdk_common::GroupId;
use serde::{Deserialize, Serialize};

use crate::error::SentcError;
use crate::group::Group;

#[derive(Serialize, Deserialize)]
pub struct GroupExportData
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
}

impl From<Group> for GroupExportData
{
	fn from(value: Group) -> Self
	{
		Self {
			base_url: value.base_url,
			app_token: value.app_token,
			group_id: value.group_id,
			parent_group_id: value.parent_group_id,
			from_parent: value.from_parent,
			created_time: value.created_time,
			joined_time: value.joined_time,
			rank: value.rank,
			is_connected_group: value.is_connected_group,
			access_by_parent: value.access_by_parent,
			access_by_group_as_member: value.access_by_group_as_member,
		}
	}
}

impl<'a> From<&'a Group> for GroupExportData
{
	fn from(value: &'a Group) -> Self
	{
		Self {
			base_url: value.base_url.clone(),
			app_token: value.app_token.clone(),
			group_id: value.group_id.clone(),
			parent_group_id: value.parent_group_id.clone(),
			from_parent: value.from_parent,
			created_time: value.created_time,
			joined_time: value.joined_time,
			rank: value.rank,
			is_connected_group: value.is_connected_group,
			access_by_parent: value.access_by_parent.clone(),
			access_by_group_as_member: value.access_by_group_as_member.clone(),
		}
	}
}

#[allow(clippy::from_over_into)]
impl Into<Group> for GroupExportData
{
	fn into(self) -> Group
	{
		Group::new_group(
			self.base_url,
			self.app_token,
			self.group_id,
			self.parent_group_id,
			self.from_parent,
			self.created_time,
			self.joined_time,
			self.rank,
			self.is_connected_group,
			self.access_by_parent,
			self.access_by_group_as_member,
		)
	}
}

impl FromStr for Group
{
	type Err = SentcError;

	fn from_str(s: &str) -> Result<Self, Self::Err>
	{
		let data: GroupExportData = serde_json::from_str(s)?;

		Ok(data.into())
	}
}

impl Group
{
	pub fn to_string(self) -> Result<String, SentcError>
	{
		Ok(serde_json::to_string(&Into::<GroupExportData>::into(self))?)
	}

	pub fn to_string_ref(&self) -> Result<String, SentcError>
	{
		Ok(serde_json::to_string(&Into::<GroupExportData>::into(self))?)
	}
}
