pub use sentc_crypto::keys::std::{StdGroupKeyData, StdUserDataInt, StdUserKeyDataInt};
use sentc_crypto::std_keys::core::PwHasherGetter;
use sentc_crypto::std_keys::util::{HmacKey, PublicKey, SecretKey, SignKey, SortableKey, SymmetricKey, VerifyKey};

use crate::group::Group;
use crate::user::net::UserLoginReturn;
use crate::user::User;

pub type StdGroup = Group<
	SymmetricKey,
	SecretKey,
	SignKey,
	sentc_crypto::std_keys::core::HmacKey,
	sentc_crypto::std_keys::core::SortKeys,
	SymmetricKey,
	SecretKey,
	SignKey,
	HmacKey,
	SortableKey,
	PublicKey,
	VerifyKey,
	PwHasherGetter,
>;

pub type StdUser = User<
	SymmetricKey,
	SecretKey,
	SignKey,
	sentc_crypto::std_keys::core::HmacKey,
	sentc_crypto::std_keys::core::SortKeys,
	SymmetricKey,
	SecretKey,
	SignKey,
	HmacKey,
	SortableKey,
	PublicKey,
	VerifyKey,
	PwHasherGetter,
>;

pub type StdUserLoginReturn = UserLoginReturn<
	SymmetricKey,
	SecretKey,
	SignKey,
	sentc_crypto::std_keys::core::HmacKey,
	sentc_crypto::std_keys::core::SortKeys,
	SymmetricKey,
	SecretKey,
	SignKey,
	HmacKey,
	SortableKey,
	PublicKey,
	VerifyKey,
	PwHasherGetter,
>;
