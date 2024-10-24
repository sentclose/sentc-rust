#![doc=include_str!("../../doc/user.md")]
#![doc=include_str!("../../doc/encrypt_user.md")]
#![doc=include_str!("../../doc/file.md")]

pub mod crypto_sync;
mod export;
#[cfg(feature = "file")]
pub mod file;
#[cfg(feature = "network")]
pub mod net;

use std::marker::PhantomData;

use sentc_crypto::entities::user::{UserDataInt, UserKeyDataInt};
use sentc_crypto::group::Group as SdkGroup;
use sentc_crypto::sdk_common::group::GroupHmacData;
use sentc_crypto::sdk_common::user::{UserPublicKeyData, UserVerifyKeyData};
use sentc_crypto::sdk_common::{DeviceId, SymKeyId, UserId};
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
	SymKeyWrapper,
	VerifyKFromUserKeyWrapper,
};
use sentc_crypto::user::{generate_user_register_data, User as SdkUser};

use crate::error::SentcError;
use crate::group::prepare_group_keys_ref;
use crate::KeyMap;

/// The user struct holds all information about the user.
///
/// A user got its user group and device keys.
pub struct User<SGen, StGen, SignGen, SearchGen, SortGen, SC, StC, SignC, SearchC, SortC, PC, VC, PwH>
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
	user_id: UserId,
	user_identifier: String,
	device_id: DeviceId,

	jwt: String,
	refresh_token: String,

	mfa: bool,

	//device keys
	private_device_key: StC::SkWrapper,
	public_device_key: StC::PkWrapper,
	sign_device_key: SignC::SignKWrapper,
	verify_device_key: SignC::VerifyKWrapper,
	exported_verify_device_key: UserVerifyKeyData,
	exported_public_device_key: UserPublicKeyData,

	//user keys
	#[allow(clippy::type_complexity)]
	user_keys: Vec<UserKeyDataInt<SC::SymmetricKeyWrapper, StC::SkWrapper, StC::PkWrapper, SignC::SignKWrapper, SignC::VerifyKWrapper>>,
	key_map: KeyMap,
	newest_key_id: SymKeyId,
	hmac_keys: Vec<SearchC::SearchableKeyWrapper>,

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
	_pw: PhantomData<PwH>,
}

impl<SGen, StGen, SignGen, SearchGen, SortGen, SC, StC, SignC, SearchC, SortC, PC, VC, PwH>
	User<SGen, StGen, SignGen, SearchGen, SortGen, SC, StC, SignC, SearchC, SortC, PC, VC, PwH>
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
	#[allow(clippy::type_complexity)]
	fn new_user(
		base_url: String,
		app_token: String,
		user_identifier: String,
		data: UserDataInt<SC::SymmetricKeyWrapper, StC::SkWrapper, StC::PkWrapper, SignC::SignKWrapper, SignC::VerifyKWrapper>,
		mfa: bool,
	) -> Result<(Self, Vec<GroupHmacData>), SentcError>
	{
		let newest_key_id = data
			.user_keys
			.first()
			.ok_or(SentcError::KeyNotFound)?
			.group_key
			.get_id()
			.to_string();

		let mut key_map: KeyMap = Default::default();

		for (i, key) in data.user_keys.iter().enumerate() {
			key_map.insert(key.group_key.get_id().to_string(), i);
		}

		Ok((
			Self {
				user_id: data.user_id,
				user_identifier,
				device_id: data.device_id,
				jwt: data.jwt,
				refresh_token: data.refresh_token,
				mfa,
				private_device_key: data.device_keys.private_key,
				public_device_key: data.device_keys.public_key,
				sign_device_key: data.device_keys.sign_key,
				verify_device_key: data.device_keys.verify_key,
				exported_verify_device_key: data.device_keys.exported_verify_key,
				exported_public_device_key: data.device_keys.exported_public_key,
				user_keys: data.user_keys,
				key_map,
				newest_key_id,
				hmac_keys: Vec::with_capacity(data.hmac_keys.len()),
				base_url,
				app_token,

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
				_pw: Default::default(),
			},
			data.hmac_keys,
		))
	}

	#[cfg(not(feature = "network"))]
	#[allow(clippy::too_many_arguments, clippy::type_complexity)]
	pub fn new(
		base_url: String,
		app_token: String,
		user_identifier: String,
		data: UserDataInt<SC::SymmetricKeyWrapper, StC::SkWrapper, StC::PkWrapper, SignC::SignKWrapper, SignC::VerifyKWrapper>,
		mfa: bool,
	) -> Result<Self, SentcError>
	{
		let (mut u, hmac_keys) = Self::new_user(base_url, app_token, user_identifier, data, mfa)?;

		u.decrypt_hmac_keys_sync(hmac_keys)?;

		Ok(u)
	}

	pub fn get_user_id(&self) -> &str
	{
		&self.user_id
	}

	pub fn get_identifier(&self) -> &str
	{
		&self.user_identifier
	}

	pub fn get_device_id(&self) -> &str
	{
		&self.device_id
	}

	pub fn get_jwt_sync(&self) -> &str
	{
		&self.jwt
	}

	pub fn get_refresh_token(&self) -> &str
	{
		&self.refresh_token
	}

	#[allow(clippy::type_complexity)]
	pub fn get_newest_key(
		&self,
	) -> Option<&UserKeyDataInt<SC::SymmetricKeyWrapper, StC::SkWrapper, StC::PkWrapper, SignC::SignKWrapper, SignC::VerifyKWrapper>>
	{
		let index = self.key_map.get(&self.newest_key_id).unwrap_or(&0);

		self.user_keys.get(*index)
	}

	pub fn get_newest_public_key(&self) -> Option<&StC::PkWrapper>
	{
		self.get_newest_key().map(|k| &k.public_key)
	}

	pub fn get_newest_exported_public_key(&self) -> Option<&UserPublicKeyData>
	{
		self.get_newest_key().map(|k| &k.exported_public_key)
	}

	pub fn get_newest_sign_key(&self) -> Option<&SignC::SignKWrapper>
	{
		self.get_newest_key().map(|k| &k.sign_key)
	}

	pub fn set_jwt(&mut self, jwt: String)
	{
		self.jwt = jwt;
	}

	pub fn set_refresh_token(&mut self, refresh_token: String)
	{
		self.refresh_token = refresh_token;
	}

	#[allow(clippy::type_complexity)]
	pub fn get_user_keys(
		&self,
		key_id: &str,
	) -> Option<&UserKeyDataInt<SC::SymmetricKeyWrapper, StC::SkWrapper, StC::PkWrapper, SignC::SignKWrapper, SignC::VerifyKWrapper>>
	{
		self.key_map
			.get(key_id)
			.and_then(|k| self.user_keys.get(*k))
	}

	pub fn has_user_keys(&self, key_id: &str) -> Option<&usize>
	{
		self.key_map.get(key_id)
	}

	pub fn prepare_register_device_keys(&self, sever_output: &str) -> Result<(String, UserPublicKeyData), SentcError>
	{
		let (keys, _) = self.prepare_group_keys_ref(0);

		let key_session = self.user_keys.len() > 50;

		Ok(SdkUser::<
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
			PwH,
		>::prepare_register_device(sever_output, &keys, key_session)?)
	}

	pub fn get_mfa(&self) -> bool
	{
		self.mfa
	}

	pub(crate) fn prepare_group_keys_ref(&self, page: usize) -> (Vec<&SC::SymmetricKeyWrapper>, bool)
	{
		prepare_group_keys_ref!(self.user_keys, page, 50)
	}

	pub fn get_private_device_key(&self) -> &StC::SkWrapper
	{
		&self.private_device_key
	}

	pub fn get_public_device_key(&self) -> &StC::PkWrapper
	{
		&self.public_device_key
	}

	pub fn get_verify_device_key(&self) -> &SignC::VerifyKWrapper
	{
		&self.verify_device_key
	}

	pub fn get_exported_verify_device_key(&self) -> &UserVerifyKeyData
	{
		&self.exported_verify_device_key
	}

	pub fn get_exported_public_device_key(&self) -> &UserPublicKeyData
	{
		&self.exported_public_device_key
	}

	#[cfg(not(feature = "network"))]
	fn decrypt_hmac_keys_sync(&mut self, hmac_keys: Vec<GroupHmacData>) -> Result<(), SentcError>
	{
		for hmac_key in hmac_keys {
			let key = self
				.get_user_keys(&hmac_key.encrypted_hmac_encryption_key_id)
				.ok_or(SentcError::KeyNotFound)?;

			let decrypted_hmac_key =
				SdkGroup::<SGen, StGen, SignGen, SearchGen, SortGen, SC, StC, SignC, SearchC, SortC, PC, VC>::decrypt_group_hmac_key(
					&key.group_key,
					hmac_key,
				)?;

			self.hmac_keys.push(decrypted_hmac_key);
		}

		Ok(())
	}

	#[allow(clippy::type_complexity)]
	pub fn set_hmac_key(
		&mut self,
		user_key: &UserKeyDataInt<SC::SymmetricKeyWrapper, StC::SkWrapper, StC::PkWrapper, SignC::SignKWrapper, SignC::VerifyKWrapper>,
		hmac_key: GroupHmacData,
	) -> Result<(), SentcError>
	{
		let decrypted_hmac_key =
			SdkGroup::<SGen, StGen, SignGen, SearchGen, SortGen, SC, StC, SignC, SearchC, SortC, PC, VC>::decrypt_group_hmac_key(
				&user_key.group_key,
				hmac_key,
			)?;

		self.hmac_keys.push(decrypted_hmac_key);

		Ok(())
	}

	pub fn prepare_create_group(&self, sign: bool) -> Result<String, SentcError>
	{
		let sign_key = if sign { self.get_newest_sign_key() } else { None };

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
		>::prepare_create(
			self.get_newest_public_key()
				.ok_or(SentcError::KeyNotFound)?,
			sign_key,
			self.user_id.to_string(),
		)?)
	}

	pub fn create_safety_number_sync(&self, other_user: Option<&str>, other_user_key: Option<&UserVerifyKeyData>) -> Result<String, SentcError>
	{
		Ok(SdkUser::<
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
			PwH,
		>::create_safety_number(
			&self
				.get_newest_key()
				.ok_or(SentcError::KeyNotFound)?
				.exported_verify_key,
			self.get_user_id(),
			other_user_key,
			other_user,
		)?)
	}

	pub fn set_newest_key_id(&mut self, id: SymKeyId)
	{
		self.newest_key_id = id;
	}

	#[allow(clippy::type_complexity)]
	pub fn extend_user_key(
		&mut self,
		user_keys: UserKeyDataInt<SC::SymmetricKeyWrapper, StC::SkWrapper, StC::PkWrapper, SignC::SignKWrapper, SignC::VerifyKWrapper>,
	)
	{
		//keys are already decrypted from the sentc full sdk and the private device key
		self.key_map
			.insert(user_keys.group_key.get_id().to_string(), self.user_keys.len());
		self.user_keys.push(user_keys);
	}

	//==============================================================================================

	pub fn prepare_register(user_identifier: &str, password: &str) -> Result<String, SentcError>
	{
		if user_identifier.is_empty() || password.is_empty() {
			return Err(SentcError::UsernameOrPasswordRequired);
		}

		Ok(SdkUser::<
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
			PwH,
		>::register(user_identifier, password)?)
	}

	pub fn prepare_register_device_start(device_identifier: &str, password: &str) -> Result<String, SentcError>
	{
		if device_identifier.is_empty() || password.is_empty() {
			return Err(SentcError::UsernameOrPasswordRequired);
		}

		Ok(SdkUser::<
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
			PwH,
		>::prepare_register_device_start(device_identifier, password)?)
	}
}

pub fn generate_register_data() -> Result<(String, String), SentcError>
{
	Ok(generate_user_register_data()?)
}

pub fn done_register(server_output: &str) -> Result<UserId, SentcError>
{
	Ok(sentc_crypto::user::done_register(server_output)?)
}

pub fn done_register_device_start(server_output: &str) -> Result<(), SentcError>
{
	Ok(sentc_crypto::user::done_register_device_start(server_output)?)
}
