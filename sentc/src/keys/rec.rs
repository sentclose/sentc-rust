use sentc_crypto::fips_keys::util::HmacKey;
pub use sentc_crypto::keys::rec::{RecGroupKeyData, RecUserDataInt, RecUserKeyDataInt};
use sentc_crypto::rec_keys::core::pw_hash::PwHasher;
use sentc_crypto::rec_keys::util::{PublicKey, SecretKey, SignKey, SortableKey, SymmetricKey, VerifyKey};

use crate::group::Group;
use crate::user::net::UserLoginReturn;
use crate::user::User;

pub type RecGroup = Group<
	SymmetricKey,
	SecretKey,
	SignKey,
	sentc_crypto::rec_keys::core::hmac::HmacKey,
	sentc_crypto::rec_keys::core::sortable::OpeSortableKey,
	SymmetricKey,
	SecretKey,
	SignKey,
	HmacKey,
	SortableKey,
	PublicKey,
	VerifyKey,
	PwHasher,
>;

pub type RecUser = User<
	SymmetricKey,
	SecretKey,
	SignKey,
	sentc_crypto::rec_keys::core::hmac::HmacKey,
	sentc_crypto::rec_keys::core::sortable::OpeSortableKey,
	SymmetricKey,
	SecretKey,
	SignKey,
	HmacKey,
	SortableKey,
	PublicKey,
	VerifyKey,
	PwHasher,
>;

pub type RecUserLoginReturn = UserLoginReturn<
	SymmetricKey,
	SecretKey,
	SignKey,
	sentc_crypto::rec_keys::core::hmac::HmacKey,
	sentc_crypto::rec_keys::core::sortable::OpeSortableKey,
	SymmetricKey,
	SecretKey,
	SignKey,
	HmacKey,
	SortableKey,
	PublicKey,
	VerifyKey,
	PwHasher,
>;
