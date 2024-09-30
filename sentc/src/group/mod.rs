#![doc=include_str!("../../doc/group.md")]
#![doc=include_str!("../../doc/encrypt_group.md")]
#![doc=include_str!("../../doc/searchable.md")]
#![doc=include_str!("../../doc/file.md")]

pub mod crypto_sync;
mod export;
#[cfg(feature = "file")]
pub mod file;
#[cfg(feature = "network")]
pub mod net;

use std::marker::PhantomData;

use sentc_crypto::entities::group::GroupKeyData;
use sentc_crypto::group::{prepare_change_rank, Group as SdkGroup};
use sentc_crypto::sdk_common::content_searchable::SearchableCreateOutput;
use sentc_crypto::sdk_common::content_sortable::SortableEncryptOutput;
use sentc_crypto::sdk_common::group::{GroupHmacData, GroupKeyServerOutput, GroupSortableData};
use sentc_crypto::sdk_common::user::UserPublicKeyData;
use sentc_crypto::sdk_common::{GroupId, SymKeyId};
use sentc_crypto::sdk_core::cryptomat::{PwHash, SearchableKeyGen, SortableKey as CoreSort, SortableKeyGen};
use sentc_crypto::sdk_utils::cryptomat::{
	PkFromUserKeyWrapper,
	PkWrapper,
	SearchableKeyComposerWrapper,
	SearchableKeyWrapper,
	SignComposerWrapper,
	SignKeyPairWrapper,
	SkWrapper,
	SortableKeyComposerWrapper,
	SortableKeyWrapper,
	StaticKeyComposerWrapper,
	StaticKeyPairWrapper,
	SymKeyComposerWrapper,
	SymKeyGenWrapper,
	SymKeyWrapper,
	VerifyKFromUserKeyWrapper,
};

use crate::crypto_common::UserId;
use crate::error::SentcError;
use crate::user::User;
use crate::KeyMap;

macro_rules! prepare_group_keys_ref {
	($keys:expr, $page:expr, $max:expr) => {{
		let offset = $page * $max;

		if offset >= $keys.len() {
			return (Vec::new(), false); // Return an empty vector if the page is out of bounds.
		}

		let end = offset + $max;

		let end = if end > $keys.len() { $keys.len() } else { end };

		(
			$keys[offset..end].iter().map(|k| &k.group_key).collect(),
			end < $keys.len() - 1,
		)
	}};
}

pub(crate) use prepare_group_keys_ref;

pub type GroupFromServerReturn<SGen, StGen, SignGen, SearchGen, SortGen, SC, StC, SignC, SearchC, SortC, PC, VC, PwH> = (
	Group<SGen, StGen, SignGen, SearchGen, SortGen, SC, StC, SignC, SearchC, SortC, PC, VC, PwH>,
	Vec<GroupKeyServerOutput>,
	Vec<GroupHmacData>,
	Vec<GroupSortableData>,
);

pub struct Group<SGen, StGen, SignGen, SearchGen, SortGen, SC, StC, SignC, SearchC, SortC, PC, VC, PwH>
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

	keys: Vec<GroupKeyData<SC::SymmetricKeyWrapper, StC::SkWrapper, StC::PkWrapper>>,
	hmac_keys: Vec<SearchC::SearchableKeyWrapper>,
	sortable_keys: Vec<SortC::SortableKeyWrapper>,
	newest_key_id: SymKeyId,
	key_map: KeyMap,

	base_url: String,
	app_token: String,

	_sgen: PhantomData<SGen>,
	_st_gen: PhantomData<StGen>,
	_sign_gen: PhantomData<SignGen>,
	_search_gen: PhantomData<SearchGen>,
	_sort_gen: PhantomData<SortGen>,
	_sc: PhantomData<SC>,
	_st_c: PhantomData<StC>,
	_sign_c: PhantomData<SignC>,
	_search_c: PhantomData<SearchC>,
	_sort_c: PhantomData<SortC>,
	_pc: PhantomData<PC>,
	_vc: PhantomData<VC>,
	_pwh: PhantomData<PwH>,
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
			access_by_parent,
			access_by_group_as_member,
			keys: Vec::with_capacity(key_len),
			hmac_keys: Vec::with_capacity(search_key_len),
			sortable_keys: Vec::with_capacity(sort_key_len),
			newest_key_id: "".to_string(),
			key_map: Default::default(),

			_sgen: Default::default(),
			_st_gen: Default::default(),
			_sign_gen: Default::default(),
			_search_gen: Default::default(),
			_sort_gen: Default::default(),
			_sc: Default::default(),
			_st_c: Default::default(),
			_sign_c: Default::default(),
			_search_c: Default::default(),
			_sort_c: Default::default(),
			_pc: Default::default(),
			_vc: Default::default(),
			_pwh: Default::default(),
		}
	}

	#[allow(clippy::type_complexity)]
	pub fn from_server(
		base_url: String,
		app_token: String,
		server_data: sentc_crypto::entities::group::GroupOutData,
	) -> Result<GroupFromServerReturn<SGen, StGen, SignGen, SearchGen, SortGen, SC, StC, SignC, SearchC, SortC, PC, VC, PwH>, SentcError>
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

	pub fn get_newest_hmac_key(&self) -> &SearchC::SearchableKeyWrapper
	{
		&self.hmac_keys[0]
	}

	pub fn get_newest_sortable_key(&self) -> &SortC::SortableKeyWrapper
	{
		&self.sortable_keys[0]
	}

	pub fn get_group_key(&self, group_key_id: &str) -> Option<&GroupKeyData<SC::SymmetricKeyWrapper, StC::SkWrapper, StC::PkWrapper>>
	{
		self.key_map
			.get(group_key_id)
			.and_then(|o| self.keys.get(*o))
	}

	pub fn has_group_key(&self, group_key_id: &str) -> Option<&usize>
	{
		self.key_map.get(group_key_id)
	}

	pub fn get_access_group_as_member(&self) -> Option<&str>
	{
		self.access_by_group_as_member.as_deref()
	}

	pub fn prepare_update_rank(&self, user_id: &str, new_rank: i32) -> Result<String, SentcError>
	{
		Ok(prepare_change_rank(user_id, new_rank, self.rank)?)
	}

	pub fn prepare_create_child_group(&self) -> Result<(String, String), SentcError>
	{
		let latest_key = self
			.get_newest_key()
			.map(|o| &o.public_group_key)
			.ok_or(SentcError::KeyNotFound)?;

		Ok((
			SdkGroup::<SGen, StGen, SignGen, SearchGen, SortGen, SC, StC, SignC, SearchC, SortC, PC, VC>::prepare_create(latest_key)?,
			latest_key.get_id().to_string(),
		))
	}

	#[allow(clippy::type_complexity)]
	pub fn manually_key_rotation(
		&self,
		sign: bool,
		user_id: UserId,
		user: Option<&User<SGen, StGen, SignGen, SearchGen, SortGen, SC, StC, SignC, SearchC, SortC, PC, VC, PwH>>,
		parent_group: Option<&Group<SGen, StGen, SignGen, SearchGen, SortGen, SC, StC, SignC, SearchC, SortC, PC, VC, PwH>>,
	) -> Result<String, SentcError>
	{
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

		Ok(SdkGroup::<
			SGen,
			StGen,
			SignGen,
			SearchGen,
			SortGen,
			SC,
			StC,
			SignC,
			SearchC,
			SortC,
			PC,
			VC,
		>::key_rotation(
			&self
				.get_newest_key()
				.ok_or(SentcError::KeyNotFound)?
				.group_key,
			pk,
			false,
			sign_key,
			user_id,
		)?)
	}

	pub fn prepare_group_keys_for_new_member(&self, user_public_key: &UserPublicKeyData, new_user_rank: Option<i32>) -> Result<String, SentcError>
	{
		let (keys, _) = self.prepare_group_keys_ref(0);

		let key_session = self.keys.len() > 50;

		Ok(SdkGroup::<
			SGen,
			StGen,
			SignGen,
			SearchGen,
			SortGen,
			SC,
			StC,
			SignC,
			SearchC,
			SortC,
			PC,
			VC,
		>::prepare_group_keys_for_new_member(
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

	pub fn get_newest_key(&self) -> Option<&GroupKeyData<SC::SymmetricKeyWrapper, StC::SkWrapper, StC::PkWrapper>>
	{
		let index = self.key_map.get(&self.newest_key_id).unwrap_or(&0);

		self.keys.get(*index)
	}

	//______________________________________________________________________________________________
	//searchable encryption

	pub fn create_search_raw(&self, data: &str, full: bool, limit: Option<usize>) -> Result<Vec<String>, SentcError>
	{
		let key = self.get_newest_hmac_key();

		Ok(key.create_searchable_raw(data, full, limit)?)
	}

	pub fn create_search(&self, data: &str, full: bool, limit: Option<usize>) -> Result<SearchableCreateOutput, SentcError>
	{
		let key = self.get_newest_hmac_key();

		Ok(key.create_searchable(data, full, limit)?)
	}

	pub fn search(&self, data: &str) -> Result<String, SentcError>
	{
		let key = self.get_newest_hmac_key();

		Ok(key.search(data)?)
	}

	//______________________________________________________________________________________________
	//sortable

	pub fn encrypt_sortable_raw_number(&self, number: u64) -> Result<u64, SentcError>
	{
		let key = self.get_newest_sortable_key();

		Ok(key.get_key().encrypt_sortable(number)?)
	}

	pub fn encrypt_sortable_number(&self, number: u64) -> Result<SortableEncryptOutput, SentcError>
	{
		let key = self.get_newest_sortable_key();

		Ok(key.encrypt_number(number)?)
	}

	pub fn encrypt_sortable_raw_string(&self, data: &str, max_len: Option<usize>) -> Result<u64, SentcError>
	{
		let key = self.get_newest_sortable_key();

		Ok(key.encrypt_raw_string(data, max_len)?)
	}

	pub fn encrypt_sortable_string(&self, data: &str, max_len: Option<usize>) -> Result<SortableEncryptOutput, SentcError>
	{
		let key = self.get_newest_sortable_key();

		Ok(key.encrypt_string(data, max_len)?)
	}

	//==============================================================================================
	//internal fn

	pub(crate) fn prepare_group_keys_ref(&self, page: usize) -> (Vec<&SC::SymmetricKeyWrapper>, bool)
	{
		prepare_group_keys_ref!(self.keys, page, 50)
	}

	#[allow(clippy::type_complexity)]
	pub fn get_last_key(&self) -> Result<&GroupKeyData<SC::SymmetricKeyWrapper, StC::SkWrapper, StC::PkWrapper>, SentcError>
	{
		//keys are always set otherwise there will be an error in the get group fn
		self.keys.last().ok_or(SentcError::KeyNotFound)
	}

	pub(crate) fn set_newest_key_id(&mut self, id: SymKeyId)
	{
		self.newest_key_id = id;
	}

	pub fn set_hmac_key(
		&mut self,
		key: &GroupKeyData<SC::SymmetricKeyWrapper, StC::SkWrapper, StC::PkWrapper>,
		hmac_key: GroupHmacData,
	) -> Result<(), SentcError>
	{
		let decrypted_hmac_key =
			SdkGroup::<SGen, StGen, SignGen, SearchGen, SortGen, SC, StC, SignC, SearchC, SortC, PC, VC>::decrypt_group_hmac_key(
				&key.group_key,
				hmac_key,
			)?;

		self.hmac_keys.push(decrypted_hmac_key);

		Ok(())
	}

	pub fn set_sortable_key(
		&mut self,
		key: &GroupKeyData<SC::SymmetricKeyWrapper, StC::SkWrapper, StC::PkWrapper>,
		sortable_key: GroupSortableData,
	) -> Result<(), SentcError>
	{
		let decrypted_sortable_key =
			SdkGroup::<SGen, StGen, SignGen, SearchGen, SortGen, SC, StC, SignC, SearchC, SortC, PC, VC>::decrypt_group_sortable_key(
				&key.group_key,
				sortable_key,
			)?;

		self.sortable_keys.push(decrypted_sortable_key);

		Ok(())
	}

	pub fn set_keys(&mut self, private_key: &impl SkWrapper, key: GroupKeyServerOutput) -> Result<(), SentcError>
	{
		let key = SdkGroup::<SGen, StGen, SignGen, SearchGen, SortGen, SC, StC, SignC, SearchC, SortC, PC, VC>::decrypt_group_keys(private_key, key)?;
		self.key_map
			.insert(key.group_key.get_id().to_string(), self.keys.len());
		self.keys.push(key);

		Ok(())
	}
}
