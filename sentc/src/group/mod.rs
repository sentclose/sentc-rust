#[cfg(feature = "network")]
pub mod crypto_net;
pub mod crypto_sync;
#[cfg(feature = "file")]
pub mod file;
#[cfg(feature = "network")]
pub mod net;

use sentc_crypto::crypto_searchable::{create_searchable, create_searchable_raw, search};
use sentc_crypto::crypto_sortable::{encrypt_number, encrypt_raw_number, encrypt_raw_string, encrypt_string};
use sentc_crypto::entities::group::GroupKeyData;
use sentc_crypto::entities::keys::{HmacKeyFormatInt, PrivateKeyFormatInt, SortableKeyFormatInt, SymKeyFormatInt};
use sentc_crypto::group::{decrypt_group_keys, prepare_change_rank, prepare_group_keys_for_new_member};
use sentc_crypto::sdk_common::content_searchable::SearchableCreateOutput;
use sentc_crypto::sdk_common::content_sortable::SortableEncryptOutput;
use sentc_crypto::sdk_common::group::{GroupHmacData, GroupKeyServerOutput, GroupSortableData};
use sentc_crypto::sdk_common::user::UserPublicKeyData;
use sentc_crypto::sdk_common::{GroupId, SymKeyId, UserId};

use crate::error::SentcError;
use crate::{decrypt_hmac_key, decrypt_sort_key, KeyMap};

macro_rules! prepare_group_keys_ref {
	($keys:expr, $page:expr, $max:expr) => {{
		let offset = $page * $max;

		if offset >= $keys.len() {
			return (Vec::new(), false); // Return an empty vector if the page is out of bounds.
		}

		let end = offset + $max;

		let end = if end > $keys.len() { $keys.len() } else { end };

		(
			$keys[offset..end]
				.iter()
				.map(|k| &k.group_key)
				.collect::<Vec<&SymKeyFormatInt>>(),
			end < $keys.len() - 1,
		)
	}};
}

pub(crate) use prepare_group_keys_ref;

pub type GroupFromServerReturn = (
	Group,
	Vec<GroupKeyServerOutput>,
	Vec<GroupHmacData>,
	Vec<GroupSortableData>,
);

pub struct Group
{
	group_id: GroupId,
	parent_group_id: Option<GroupId>,
	from_parent: bool,
	key_update: bool,
	created_time: u128,
	joined_time: u128,
	rank: i32,
	is_connected_group: bool,
	access_by_parent: Option<GroupId>,
	access_by_group_as_member: Option<GroupId>,

	keys: Vec<GroupKeyData>,
	hmac_keys: Vec<HmacKeyFormatInt>,
	sortable_keys: Vec<SortableKeyFormatInt>,
	newest_key_id: SymKeyId,
	key_map: KeyMap,

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
		key_update: bool,
		created_time: u128,
		joined_time: u128,
		rank: i32,
		is_connected_group: bool,
		used_user_id: UserId,
		access_by_parent: Option<GroupId>,
		access_by_group_as_member: Option<GroupId>,
		key_len: usize,
		search_key_len: usize,
		sort_key_len: usize,
	) -> Self
	{
		Self {
			base_url,
			app_token,
			group_id,
			parent_group_id,
			from_parent,
			key_update,
			created_time,
			joined_time,
			rank,
			is_connected_group,
			used_user_id,
			access_by_parent,
			access_by_group_as_member,
			keys: Vec::with_capacity(key_len),
			hmac_keys: Vec::with_capacity(search_key_len),
			sortable_keys: Vec::with_capacity(sort_key_len),
			newest_key_id: "".to_string(),
			key_map: Default::default(),
		}
	}

	#[cfg(not(feature = "network"))]
	pub fn from_server(
		base_url: String,
		app_token: String,
		server_data: sentc_crypto::entities::group::GroupOutData,
		actual_user_id: UserId,
	) -> Result<GroupFromServerReturn, SentcError>
	{
		let parent = server_data.access_by_parent_group.is_some();

		let key_len = server_data.keys.len();

		if key_len == 0 {
			return Err(SentcError::NoGroupKeysFound);
		}

		let mut group = Self::new_group(
			base_url,
			app_token,
			server_data.group_id,
			server_data.parent_group_id,
			parent,
			server_data.key_update,
			server_data.created_time,
			server_data.joined_time,
			server_data.rank,
			server_data.is_connected_group,
			actual_user_id,
			server_data.access_by_parent_group,
			server_data.access_by_group_as_member,
			key_len,
			server_data.hmac_keys.len(),
			server_data.sortable_keys.len(),
		);

		group.set_newest_key_id(server_data.keys[0].group_key_id.clone());

		Ok((
			group,
			server_data.keys,
			server_data.hmac_keys,
			server_data.sortable_keys,
		))
	}

	pub fn get_group_id(&self) -> &str
	{
		&self.group_id
	}

	pub fn get_newest_hmac_key(&self) -> &HmacKeyFormatInt
	{
		&self.hmac_keys[0]
	}

	pub fn get_newest_sortable_key(&self) -> &SortableKeyFormatInt
	{
		&self.sortable_keys[0]
	}

	pub fn get_group_key(&self, group_key_id: &str) -> Option<&GroupKeyData>
	{
		self.key_map
			.get(group_key_id)
			.and_then(|o| self.keys.get(*o))
	}

	pub fn get_access_group_as_member(&self) -> Option<&str>
	{
		self.access_by_group_as_member.as_deref()
	}

	pub fn prepare_update_rank(&self, user_id: &str, new_rank: i32) -> Result<String, SentcError>
	{
		Ok(prepare_change_rank(user_id, new_rank, self.rank)?)
	}

	pub fn prepare_group_keys_for_new_member(&self, user_public_key: &UserPublicKeyData, new_user_rank: Option<i32>) -> Result<String, SentcError>
	{
		let (keys, _) = self.prepare_group_keys_ref(0);

		let key_session = self.keys.len() > 50;

		Ok(prepare_group_keys_for_new_member(
			user_public_key,
			&keys,
			key_session,
			new_user_rank,
		)?)
	}

	pub fn key_update(&self) -> bool
	{
		self.key_update
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

	pub fn get_newest_key(&self) -> Option<&GroupKeyData>
	{
		let index = self.key_map.get(&self.newest_key_id).unwrap_or(&0);

		self.keys.get(*index)
	}

	//______________________________________________________________________________________________
	//searchable encryption

	pub fn create_search_raw(&self, data: &str, full: bool, limit: Option<usize>) -> Result<Vec<String>, SentcError>
	{
		let key = self.get_newest_hmac_key();

		Ok(create_searchable_raw(key, data, full, limit)?)
	}

	pub fn create_search(&self, data: &str, full: bool, limit: Option<usize>) -> Result<SearchableCreateOutput, SentcError>
	{
		let key = self.get_newest_hmac_key();

		Ok(create_searchable(key, data, full, limit)?)
	}

	pub fn search(&self, data: &str) -> Result<String, SentcError>
	{
		let key = self.get_newest_hmac_key();

		Ok(search(key, data)?)
	}

	//______________________________________________________________________________________________
	//sortable

	pub fn encrypt_sortable_raw_number(&self, number: u64) -> Result<u64, SentcError>
	{
		let key = self.get_newest_sortable_key();

		Ok(encrypt_raw_number(key, number)?)
	}

	pub fn encrypt_sortable_number(&self, number: u64) -> Result<SortableEncryptOutput, SentcError>
	{
		let key = self.get_newest_sortable_key();

		Ok(encrypt_number(key, number)?)
	}

	pub fn encrypt_sortable_raw_string(&self, data: &str) -> Result<u64, SentcError>
	{
		let key = self.get_newest_sortable_key();

		Ok(encrypt_raw_string(key, data)?)
	}

	pub fn encrypt_sortable_string(&self, data: &str) -> Result<SortableEncryptOutput, SentcError>
	{
		let key = self.get_newest_sortable_key();

		Ok(encrypt_string(key, data)?)
	}

	//==============================================================================================
	//internal fn

	pub(crate) fn prepare_group_keys_ref(&self, page: usize) -> (Vec<&SymKeyFormatInt>, bool)
	{
		prepare_group_keys_ref!(self.keys, page, 50)
	}

	pub(crate) fn get_last_key(&self) -> Result<&GroupKeyData, SentcError>
	{
		//keys are always set otherwise there will be an error in the get group fn
		self.keys.last().ok_or(SentcError::KeyNotFound)
	}

	pub(crate) fn set_newest_key_id(&mut self, id: SymKeyId)
	{
		self.newest_key_id = id;
	}

	pub fn set_hmac_key(&mut self, key: &GroupKeyData, hmac_key: GroupHmacData) -> Result<(), SentcError>
	{
		decrypt_hmac_key!(&key.group_key, self, hmac_key);
		Ok(())
	}

	pub fn set_sortable_key(&mut self, key: &GroupKeyData, sortable_key: GroupSortableData) -> Result<(), SentcError>
	{
		decrypt_sort_key!(&key.group_key, self, sortable_key);
		Ok(())
	}

	fn prepare_for_more_keys(&mut self, keys_len: usize)
	{
		//extend the capacity for the next page (max. 50 keys)
		self.keys.reserve(keys_len);
		self.key_map.reserve(keys_len);
	}

	pub fn set_keys(&mut self, private_key: &PrivateKeyFormatInt, key: GroupKeyServerOutput) -> Result<(), SentcError>
	{
		let key = decrypt_group_keys(private_key, key)?;
		self.key_map
			.insert(key.group_key.key_id.clone(), self.keys.len());
		self.keys.push(key);

		Ok(())
	}
}

#[cfg(test)]
mod tests
{
	use std::sync::Arc;

	use tokio::sync::{OnceCell, RwLock};

	use super::*;
	use crate::cache::l_one::L1Cache;
	use crate::group_key;
	use crate::user::User;

	static GROUP: OnceCell<Arc<RwLock<Group>>> = OnceCell::const_new();

	//must be a result
	#[tokio::test]
	async fn test_init() -> Result<(), SentcError>
	{
		let c = L1Cache::new();

		let mut user = User::new();

		let group = user.get_group("abc", None, &c).await.unwrap();

		GROUP.get_or_init(|| async { group }).await;

		let mut g1 = GROUP.get().unwrap().write().await;

		g1.fetch_group_key("abc", &c).await.unwrap();

		let group = user.get_group("abc", None, &c).await.unwrap();

		let shared = Arc::new(group);

		let mut g2 = shared.write().await;

		let key = match g2.get_group_key("abc") {
			Some(k) => k,
			None => {
				g2.fetch_group_key("abc", &c).await.unwrap();
				g2.get_group_key("abc").unwrap()
			},
		};

		println!("{}", key.group_key.key_id);

		let key1 = group_key!(g2, "abc", &c)?;

		println!("{}", key1.group_key.key_id);

		let key2 = g2.get_and_fetch_key("abc", &c).await?;

		println!("{}", key2.group_key.key_id);

		Ok(())
	}
}
