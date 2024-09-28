use std::str::FromStr;

use sentc_crypto::entities::group::GroupKeyDataExport;
use sentc_crypto::sdk_core::cryptomat::{PwHash, SearchableKeyGen, SortableKeyGen};
use sentc_crypto::sdk_utils::cryptomat::{
	KeyToString,
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
use sentc_crypto::sdk_utils::error::SdkUtilError;
use sentc_crypto::SdkError;
use serde::{Deserialize, Serialize};

use crate::crypto_common::GroupId;
use crate::error::SentcError;
use crate::group::Group;

#[derive(Serialize, Deserialize)]
pub struct GroupExportData
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

	keys: Vec<GroupKeyDataExport>,
	hmac_keys: Vec<String>,
	sortable_keys: Vec<String>,

	base_url: String,
	app_token: String,
}

impl<SGen, StGen, SignGen, SearchGen, SortGen, SC, StC, SignC, SearchC, SortC, PC, VC, PwH>
	TryFrom<Group<SGen, StGen, SignGen, SearchGen, SortGen, SC, StC, SignC, SearchC, SortC, PC, VC, PwH>> for GroupExportData
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
	type Error = SentcError;

	fn try_from(value: Group<SGen, StGen, SignGen, SearchGen, SortGen, SC, StC, SignC, SearchC, SortC, PC, VC, PwH>) -> Result<Self, Self::Error>
	{
		Ok(Self {
			group_id: value.group_id,
			parent_group_id: value.parent_group_id,
			from_parent: value.from_parent,
			key_update: value.key_update,
			created_time: value.created_time,
			joined_time: value.joined_time,
			rank: value.rank,
			is_connected_group: value.is_connected_group,
			access_by_parent: value.access_by_parent,
			access_by_group_as_member: value.access_by_group_as_member,
			keys: value
				.keys
				.into_iter()
				.map(|k| k.try_into())
				.collect::<Result<_, SdkError>>()?,
			hmac_keys: value
				.hmac_keys
				.into_iter()
				.map(|k| k.to_string())
				.collect::<Result<_, SdkUtilError>>()?,
			sortable_keys: value
				.sortable_keys
				.into_iter()
				.map(|k| k.to_string())
				.collect::<Result<_, SdkUtilError>>()?,
			base_url: value.base_url,
			app_token: value.app_token,
		})
	}
}

impl<'a, SGen, StGen, SignGen, SearchGen, SortGen, SC, StC, SignC, SearchC, SortC, PC, VC, PwH>
	TryFrom<&'a Group<SGen, StGen, SignGen, SearchGen, SortGen, SC, StC, SignC, SearchC, SortC, PC, VC, PwH>> for GroupExportData
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
	type Error = SentcError;

	fn try_from(value: &'a Group<SGen, StGen, SignGen, SearchGen, SortGen, SC, StC, SignC, SearchC, SortC, PC, VC, PwH>)
		-> Result<Self, Self::Error>
	{
		Ok(Self {
			group_id: value.group_id.clone(),
			parent_group_id: value.parent_group_id.clone(),
			from_parent: value.from_parent,
			key_update: value.key_update,
			created_time: value.created_time,
			joined_time: value.joined_time,
			rank: value.rank,
			is_connected_group: value.is_connected_group,
			access_by_parent: value.access_by_parent.clone(),
			access_by_group_as_member: value.access_by_group_as_member.clone(),
			keys: value
				.keys
				.iter()
				.map(|k| k.try_into())
				.collect::<Result<_, SdkError>>()?,
			hmac_keys: value
				.hmac_keys
				.iter()
				.map(|k| k.to_string_ref())
				.collect::<Result<_, SdkUtilError>>()?,
			sortable_keys: value
				.sortable_keys
				.iter()
				.map(|k| k.to_string_ref())
				.collect::<Result<_, SdkUtilError>>()?,
			base_url: value.base_url.clone(),
			app_token: value.app_token.clone(),
		})
	}
}

impl<SGen, StGen, SignGen, SearchGen, SortGen, SC, StC, SignC, SearchC, SortC, PC, VC, PwH>
	TryInto<Group<SGen, StGen, SignGen, SearchGen, SortGen, SC, StC, SignC, SearchC, SortC, PC, VC, PwH>> for GroupExportData
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
	type Error = SentcError;

	fn try_into(self) -> Result<Group<SGen, StGen, SignGen, SearchGen, SortGen, SC, StC, SignC, SearchC, SortC, PC, VC, PwH>, Self::Error>
	{
		let mut group = Group::new_group(
			self.base_url,
			self.app_token,
			self.group_id,
			self.parent_group_id,
			self.from_parent,
			self.key_update,
			self.created_time,
			self.joined_time,
			self.rank,
			self.is_connected_group,
			self.access_by_parent,
			self.access_by_group_as_member,
			self.keys.len(),
			self.hmac_keys.len(),
			self.sortable_keys.len(),
		);

		group.keys = self
			.keys
			.into_iter()
			.map(|k| k.try_into())
			.collect::<Result<_, SdkError>>()?;

		group.hmac_keys = self
			.hmac_keys
			.into_iter()
			.map(|k| {
				k.parse()
					.map_err(|_| SdkUtilError::ImportingKeyFromPemFailed)
			})
			.collect::<Result<_, SdkUtilError>>()?;

		group.sortable_keys = self
			.sortable_keys
			.into_iter()
			.map(|k| {
				k.parse()
					.map_err(|_| SdkUtilError::ImportingKeyFromPemFailed)
			})
			.collect::<Result<_, SdkUtilError>>()?;

		Ok(group)
	}
}

impl<SGen, StGen, SignGen, SearchGen, SortGen, SC, StC, SignC, SearchC, SortC, PC, VC, PwH> FromStr
	for Group<SGen, StGen, SignGen, SearchGen, SortGen, SC, StC, SignC, SearchC, SortC, PC, VC, PwH>
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
	type Err = SentcError;

	fn from_str(s: &str) -> Result<Self, Self::Err>
	{
		let data: GroupExportData = serde_json::from_str(s)?;

		data.try_into()
	}
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
	pub fn to_string(self) -> Result<String, SentcError>
	{
		Ok(serde_json::to_string(&TryInto::<GroupExportData>::try_into(self)?)?)
	}

	pub fn to_string_ref(&self) -> Result<String, SentcError>
	{
		Ok(serde_json::to_string(&TryInto::<GroupExportData>::try_into(self)?)?)
	}
}
