pub use sentc_crypto::keys::rec::{RecGroupKeyData, RecUserDataInt, RecUserKeyDataInt};
use sentc_crypto::rec_keys::core::pw_hash::PwHasher;
use sentc_crypto::rec_keys::util::{HmacKey, PublicKey, SecretKey, SignKey, SortableKey, SymmetricKey, VerifyKey};

use crate::group::Group;
#[cfg(feature = "network")]
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

#[cfg(feature = "network")]
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

#[cfg(feature = "network")]
pub type RecPrepareLoginOtpOutput = sentc_crypto::sdk_utils::full::user::PrepareLoginOtpOutput<sentc_crypto::rec_keys::core::hmac::HmacKey>;
