#![allow(unused)]

#[cfg(feature = "std_keys")]
pub type TestUser = sentc::keys::std::StdUser;
#[cfg(all(feature = "fips_keys", not(feature = "std_keys")))]
pub type TestUser = sentc::keys::fips::FipsUser;
#[cfg(all(feature = "rec_keys", not(feature = "std_keys")))]
pub type TestUser = sentc::keys::rec::RecUser;

#[cfg(feature = "std_keys")]
pub type TestUserDataInt = sentc::keys::std::StdUserDataInt;
#[cfg(all(feature = "fips_keys", not(feature = "std_keys")))]
pub type TestUserDataInt = sentc::keys::fips::FipsUserDataInt;
#[cfg(all(feature = "rec_keys", not(feature = "std_keys")))]
pub type TestUserDataInt = sentc::keys::rec::RecUserDataInt;

#[cfg(feature = "std_keys")]
pub type TestUserKeyDataInt = sentc::keys::std::StdUserKeyDataInt;
#[cfg(all(feature = "fips_keys", not(feature = "std_keys")))]
pub type TestUserKeyDataInt = sentc::keys::fips::FipsUserKeyDataInt;
#[cfg(all(feature = "rec_keys", not(feature = "std_keys")))]
pub type TestUserKeyDataInt = sentc::keys::rec::RecUserKeyDataInt;

#[cfg(feature = "std_keys")]
pub type TestUserLoginReturn = sentc::keys::std::StdUserLoginReturn;
#[cfg(all(feature = "fips_keys", not(feature = "std_keys")))]
pub type TestUserLoginReturn = sentc::keys::fips::FipsUserLoginReturn;
#[cfg(all(feature = "rec_keys", not(feature = "std_keys")))]
pub type TestUserLoginReturn = sentc::keys::rec::RecUserLoginReturn;

#[cfg(feature = "std_keys")]
pub type TestGroup = sentc::keys::std::StdGroup;
#[cfg(all(feature = "fips_keys", not(feature = "std_keys")))]
pub type TestGroup = sentc::keys::fips::FipsGroup;
#[cfg(all(feature = "rec_keys", not(feature = "std_keys")))]
pub type TestGroup = sentc::keys::rec::RecGroup;
