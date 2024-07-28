use sentc_crypto::fips_keys::core::pw_hash::PwHasherGetter;
use sentc_crypto::fips_keys::core::sortable::NonSortableKeys;
use sentc_crypto::fips_keys::util::{HmacKey, PublicKey, SecretKey, SignKey, SortableKey, SymmetricKey, VerifyKey};
pub use sentc_crypto::keys::fips::{FipsGroupKeyData, FipsUserDataInt, FipsUserKeyDataInt};

use crate::group::Group;
use crate::user::net::UserLoginReturn;
use crate::user::User;

pub type FipsGroup = Group<
	SymmetricKey,
	SecretKey,
	SignKey,
	sentc_crypto::fips_keys::core::hmac::HmacKey,
	NonSortableKeys,
	SymmetricKey,
	SecretKey,
	SignKey,
	HmacKey,
	SortableKey,
	PublicKey,
	VerifyKey,
	PwHasherGetter,
>;

pub type FipsUser = User<
	SymmetricKey,
	SecretKey,
	SignKey,
	sentc_crypto::fips_keys::core::hmac::HmacKey,
	NonSortableKeys,
	SymmetricKey,
	SecretKey,
	SignKey,
	HmacKey,
	SortableKey,
	PublicKey,
	VerifyKey,
	PwHasherGetter,
>;

pub type FipsUserLoginReturn = UserLoginReturn<
	SymmetricKey,
	SecretKey,
	SignKey,
	sentc_crypto::fips_keys::core::hmac::HmacKey,
	NonSortableKeys,
	SymmetricKey,
	SecretKey,
	SignKey,
	HmacKey,
	SortableKey,
	PublicKey,
	VerifyKey,
	PwHasherGetter,
>;
