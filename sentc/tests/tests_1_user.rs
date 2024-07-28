use std::time::Duration;

use sentc::error::SentcError;
use sentc::net_helper::get_user_public_key_data;
use sentc::split_head_and_encrypted_string;
use sentc::user::generate_register_data;
use sentc::user::net::check_user_name_available;
use sentc_crypto::SdkError;
use tokio::sync::{OnceCell, RwLock};
use tokio::time::sleep;

use crate::test_mod::TestUser;

mod test_mod;

pub struct UserState(TestUser);

struct DeviceState
{
	identifier: String,
	pw: String,
	device_register_result: String,
}

static USER_TEST_STATE: OnceCell<RwLock<UserState>> = OnceCell::const_new();
static USER_2_TEST_STATE: OnceCell<RwLock<UserState>> = OnceCell::const_new();
static USER_3_TEST_STATE: OnceCell<RwLock<UserState>> = OnceCell::const_new();

static DEVICE_PRE_TEST_STATE: OnceCell<DeviceState> = OnceCell::const_new();
static DEVICE_TEST_STATE: OnceCell<RwLock<UserState>> = OnceCell::const_new();

static DEVICE_2_PRE_TEST_STATE: OnceCell<DeviceState> = OnceCell::const_new();
static DEVICE_2_TEST_STATE: OnceCell<RwLock<UserState>> = OnceCell::const_new();

const USERNAME: &str = "test";
const PW: &str = "12345";
const NEW_PW: &str = "12";

#[tokio::test]
async fn test_10_check_if_username_exists()
{
	let check = check_user_name_available(
		"http://127.0.0.1:3002".into(),
		"5zMb6zs3dEM62n+FxjBilFPp+j9e7YUFA+7pi6Hi",
		USERNAME,
	)
	.await
	.unwrap();

	assert!(check);
}

#[tokio::test]
async fn test_11_register_and_login_user()
{
	let user_id = TestUser::register(
		"http://127.0.0.1:3002".into(),
		"5zMb6zs3dEM62n+FxjBilFPp+j9e7YUFA+7pi6Hi",
		USERNAME,
		PW,
	)
	.await
	.unwrap();

	let user = TestUser::login_forced(
		"http://127.0.0.1:3002".into(),
		"5zMb6zs3dEM62n+FxjBilFPp+j9e7YUFA+7pi6Hi",
		USERNAME,
		PW,
	)
	.await
	.unwrap();

	assert_eq!(user_id, user.get_user_id());

	USER_TEST_STATE
		.get_or_init(|| async move { RwLock::new(UserState(user)) })
		.await;
}

#[tokio::test]
async fn test_12_change_password()
{
	let u = &USER_TEST_STATE.get().unwrap().read().await;

	u.0.change_password(PW, NEW_PW, None, None).await.unwrap();
}

#[tokio::test]
async fn test_13_not_login_with_old_pw()
{
	let err = TestUser::login_forced(
		"http://127.0.0.1:3002".into(),
		"5zMb6zs3dEM62n+FxjBilFPp+j9e7YUFA+7pi6Hi",
		USERNAME,
		PW,
	)
	.await;

	match err {
		Ok(_) => {
			panic!("Should be an error.")
		},
		Err(e) => {
			match e {
				SentcError::Sdk(SdkError::Util(sentc_crypto::sdk_utils::error::SdkUtilError::ServerErr(c, _))) => {
					assert_eq!(c, 112);
				},
				_ => panic!("should be server error"),
			}
		},
	}
}

#[tokio::test]
async fn test_14_login_with_new_password()
{
	let user = TestUser::login_forced(
		"http://127.0.0.1:3002".into(),
		"5zMb6zs3dEM62n+FxjBilFPp+j9e7YUFA+7pi6Hi",
		USERNAME,
		NEW_PW,
	)
	.await
	.unwrap();

	let mut u_s = USER_TEST_STATE.get().unwrap().write().await;

	u_s.0 = user;
}

#[tokio::test]
async fn test_15_reset_password()
{
	let u = USER_TEST_STATE.get().unwrap().read().await;
	u.0.reset_password(PW).await.unwrap();
}

#[tokio::test]
async fn test_16_not_login_with_new_password_after_reset()
{
	let err = TestUser::login_forced(
		"http://127.0.0.1:3002".into(),
		"5zMb6zs3dEM62n+FxjBilFPp+j9e7YUFA+7pi6Hi",
		USERNAME,
		NEW_PW,
	)
	.await;

	match err {
		Ok(_) => {
			panic!("Should be an error.")
		},
		Err(e) => {
			match e {
				SentcError::Sdk(SdkError::Util(sentc_crypto::sdk_utils::error::SdkUtilError::ServerErr(c, _))) => {
					assert_eq!(c, 112);
				},
				_ => panic!("should be server error"),
			}
		},
	}
}

#[tokio::test]
async fn test_17_login_with_new_password_after_reset()
{
	let user = TestUser::login_forced(
		"http://127.0.0.1:3002".into(),
		"5zMb6zs3dEM62n+FxjBilFPp+j9e7YUFA+7pi6Hi",
		USERNAME,
		PW,
	)
	.await
	.unwrap();

	let mut u_s = USER_TEST_STATE.get().unwrap().write().await;

	u_s.0 = user;
}

//__________________________________________________________________________________________________
//device test

#[tokio::test]
async fn test_20_register_new_device()
{
	let (identifier, pw) = generate_register_data().unwrap();

	let device_register_result = TestUser::register_device_start(
		"http://127.0.0.1:3002".into(),
		"5zMb6zs3dEM62n+FxjBilFPp+j9e7YUFA+7pi6Hi",
		&identifier,
		&pw,
	)
	.await
	.unwrap();

	DEVICE_PRE_TEST_STATE
		.get_or_init(|| {
			async move {
				DeviceState {
					identifier,
					pw,
					device_register_result,
				}
			}
		})
		.await;
}

#[tokio::test]
async fn test_21_not_login_without_done_register()
{
	let device_pre = DEVICE_PRE_TEST_STATE.get().unwrap();

	let err = TestUser::login_forced(
		"http://127.0.0.1:3002".into(),
		"5zMb6zs3dEM62n+FxjBilFPp+j9e7YUFA+7pi6Hi",
		&device_pre.identifier,
		&device_pre.pw,
	)
	.await;

	match err {
		Ok(_) => {
			panic!("Should be an error.")
		},
		Err(e) => {
			match e {
				SentcError::Sdk(SdkError::Util(sentc_crypto::sdk_utils::error::SdkUtilError::ServerErr(c, _))) => {
					assert_eq!(c, 100);
				},
				_ => panic!("should be server error"),
			}
		},
	}
}

#[tokio::test]
async fn test_22_done_device_register()
{
	let device_pre = DEVICE_PRE_TEST_STATE.get().unwrap();

	let u = USER_TEST_STATE.get().unwrap().read().await;

	u.0.register_device(&device_pre.device_register_result)
		.await
		.unwrap();
}

#[tokio::test]
async fn test_23_login_with_new_device()
{
	let device_pre = DEVICE_PRE_TEST_STATE.get().unwrap();

	let user = TestUser::login_forced(
		"http://127.0.0.1:3002".into(),
		"5zMb6zs3dEM62n+FxjBilFPp+j9e7YUFA+7pi6Hi",
		&device_pre.identifier,
		&device_pre.pw,
	)
	.await
	.unwrap();

	DEVICE_TEST_STATE
		.get_or_init(|| async { RwLock::new(UserState(user)) })
		.await;
}

//__________________________________________________________________________________________________
//device key rotation

#[tokio::test]
async fn test_30_start_key_rotation()
{
	let mut u = USER_TEST_STATE.get().unwrap().write().await;

	u.0.key_rotation().await.unwrap();

	sleep(Duration::from_millis(300)).await;
}

#[tokio::test]
async fn test_31_finish_key_rotation()
{
	let mut d = DEVICE_TEST_STATE.get().unwrap().write().await;

	let old_newest_key_id = d.0.get_newest_key().unwrap().group_key.key_id.clone();

	d.0.finish_key_rotation().await.unwrap();

	let new_newest_key_id = d.0.get_newest_key().unwrap().group_key.key_id.clone();

	assert_ne!(old_newest_key_id, new_newest_key_id);
}

//2nd device test

#[tokio::test]
async fn test_40_register_new_device_after_key_rotation()
{
	let (identifier, pw) = generate_register_data().unwrap();

	let device_register_result = TestUser::register_device_start(
		"http://127.0.0.1:3002".into(),
		"5zMb6zs3dEM62n+FxjBilFPp+j9e7YUFA+7pi6Hi",
		&identifier,
		&pw,
	)
	.await
	.unwrap();

	let u = USER_TEST_STATE.get().unwrap().read().await;
	u.0.register_device(&device_register_result).await.unwrap();

	let u = TestUser::login_forced(
		"http://127.0.0.1:3002".into(),
		"5zMb6zs3dEM62n+FxjBilFPp+j9e7YUFA+7pi6Hi",
		&identifier,
		&pw,
	)
	.await
	.unwrap();

	DEVICE_2_PRE_TEST_STATE
		.get_or_init(|| {
			async move {
				DeviceState {
					pw,
					identifier,
					device_register_result,
				}
			}
		})
		.await;

	DEVICE_2_TEST_STATE
		.get_or_init(|| async { RwLock::new(UserState(u)) })
		.await;
}

#[tokio::test]
async fn test_41_get_same_key_id_for_aa_devices()
{
	let u = USER_TEST_STATE.get().unwrap().read().await;
	let d = DEVICE_TEST_STATE.get().unwrap().read().await;
	let d2 = DEVICE_2_TEST_STATE.get().unwrap().read().await;

	assert_eq!(
		u.0.get_newest_key().unwrap().group_key.key_id,
		d.0.get_newest_key().unwrap().group_key.key_id
	);
	assert_eq!(
		u.0.get_newest_key().unwrap().group_key.key_id,
		d2.0.get_newest_key().unwrap().group_key.key_id
	);
}

#[tokio::test]
async fn test_42_list_all_devices()
{
	let u = USER_TEST_STATE.get().unwrap().read().await;

	let device_list = u.0.get_devices(None).await.unwrap();

	assert_eq!(device_list.len(), 3);

	//next page
	let device_list_next = u.0.get_devices(device_list.get(0)).await.unwrap();

	assert_eq!(device_list_next.len(), 2);
}

#[tokio::test]
async fn test_43_delete_device()
{
	let u = USER_TEST_STATE.get().unwrap().read().await;

	let d = DEVICE_2_TEST_STATE.get().unwrap().read().await;
	let d_id = d.0.get_device_id();

	u.0.delete_device(PW, d_id, None, None).await.unwrap();
}

#[tokio::test]
async fn test_44_not_login_with_deleted_device()
{
	let d2 = DEVICE_2_PRE_TEST_STATE.get().unwrap();

	let err = TestUser::login_forced(
		"http://127.0.0.1:3002".into(),
		"5zMb6zs3dEM62n+FxjBilFPp+j9e7YUFA+7pi6Hi",
		&d2.identifier,
		&d2.pw,
	)
	.await;

	match err {
		Ok(_) => {
			panic!("Should be an error.")
		},
		Err(e) => {
			match e {
				SentcError::Sdk(SdkError::Util(sentc_crypto::sdk_utils::error::SdkUtilError::ServerErr(c, _))) => {
					assert_eq!(c, 100);
				},
				_ => panic!("should be server error"),
			}
		},
	}
}

#[tokio::test]
async fn test_50_create_safety_number()
{
	let u = USER_TEST_STATE.get().unwrap().read().await;

	u.0.create_safety_number_sync(None, None).unwrap();
}

#[tokio::test]
async fn test_51_create_more_users()
{
	//create the 2nd user

	let user_id = TestUser::register(
		"http://127.0.0.1:3002".into(),
		"5zMb6zs3dEM62n+FxjBilFPp+j9e7YUFA+7pi6Hi",
		&(USERNAME.to_string() + "1"),
		PW,
	)
	.await
	.unwrap();

	let user = TestUser::login_forced(
		"http://127.0.0.1:3002".into(),
		"5zMb6zs3dEM62n+FxjBilFPp+j9e7YUFA+7pi6Hi",
		&(USERNAME.to_string() + "1"),
		PW,
	)
	.await
	.unwrap();

	assert_eq!(user_id, user.get_user_id());

	USER_2_TEST_STATE
		.get_or_init(|| async move { RwLock::new(UserState(user)) })
		.await;

	//create the 3rd user

	let user_id = TestUser::register(
		"http://127.0.0.1:3002".into(),
		"5zMb6zs3dEM62n+FxjBilFPp+j9e7YUFA+7pi6Hi",
		&(USERNAME.to_string() + "2"),
		PW,
	)
	.await
	.unwrap();

	let user = TestUser::login_forced(
		"http://127.0.0.1:3002".into(),
		"5zMb6zs3dEM62n+FxjBilFPp+j9e7YUFA+7pi6Hi",
		&(USERNAME.to_string() + "2"),
		PW,
	)
	.await
	.unwrap();

	assert_eq!(user_id, user.get_user_id());

	USER_3_TEST_STATE
		.get_or_init(|| async move { RwLock::new(UserState(user)) })
		.await;
}

#[tokio::test]
async fn test_52_create_combined_safety_number()
{
	//with user 2
	let u = USER_TEST_STATE.get().unwrap().read().await;

	let u1 = USER_2_TEST_STATE.get().unwrap().read().await;

	let u_vk =
		u1.0.get_user_verify_key_data(u.0.get_user_id(), &u.0.get_newest_key().unwrap().verify_key.key_id)
			.await
			.unwrap();

	let u1_vk =
		u.0.get_user_verify_key_data(u1.0.get_user_id(), &u1.0.get_newest_key().unwrap().verify_key.key_id)
			.await
			.unwrap();

	let n1 =
		u.0.create_safety_number_sync(Some(u1.0.get_user_id()), Some(&u1_vk))
			.unwrap();

	let n2 =
		u1.0.create_safety_number_sync(Some(u.0.get_user_id()), Some(&u_vk))
			.unwrap();

	assert_eq!(n1, n2);
}

#[tokio::test]
async fn test_53_not_create_the_same_number_with_different_user()
{
	let u = USER_TEST_STATE.get().unwrap().read().await;

	let u1 = USER_2_TEST_STATE.get().unwrap().read().await;

	let u2 = USER_3_TEST_STATE.get().unwrap().read().await;

	let u_vk =
		u1.0.get_user_verify_key_data(u.0.get_user_id(), &u.0.get_newest_key().unwrap().verify_key.key_id)
			.await
			.unwrap();

	let u1_vk =
		u.0.get_user_verify_key_data(u1.0.get_user_id(), &u1.0.get_newest_key().unwrap().verify_key.key_id)
			.await
			.unwrap();

	let u2_vk =
		u.0.get_user_verify_key_data(u2.0.get_user_id(), &u2.0.get_newest_key().unwrap().verify_key.key_id)
			.await
			.unwrap();

	let n1 =
		u.0.create_safety_number_sync(Some(u1.0.get_user_id()), Some(&u1_vk))
			.unwrap();

	let n2 =
		u1.0.create_safety_number_sync(Some(u.0.get_user_id()), Some(&u_vk))
			.unwrap();

	assert_eq!(n1, n2);

	let n3 =
		u2.0.create_safety_number_sync(Some(u.0.get_user_id()), Some(&u_vk))
			.unwrap();

	assert_ne!(n1, n3);

	let n4 =
		u.0.create_safety_number_sync(Some(u2.0.get_user_id()), Some(&u2_vk))
			.unwrap();

	assert_eq!(n3, n4);
}

#[tokio::test]
async fn test_54_verify_public_key()
{
	//create test user but not login because the own verify key would be set a verified
	let user_id = TestUser::register(
		"http://127.0.0.1:3002".into(),
		"5zMb6zs3dEM62n+FxjBilFPp+j9e7YUFA+7pi6Hi",
		&(USERNAME.to_string() + "3"),
		PW,
	)
	.await
	.unwrap();

	let public_key = get_user_public_key_data(
		"http://127.0.0.1:3002".into(),
		"5zMb6zs3dEM62n+FxjBilFPp+j9e7YUFA+7pi6Hi",
		&user_id,
	)
	.await
	.unwrap();

	//verify this key
	let verify = TestUser::verify_user_public_key(
		"http://127.0.0.1:3002".into(),
		"5zMb6zs3dEM62n+FxjBilFPp+j9e7YUFA+7pi6Hi",
		&user_id,
		&public_key,
	)
	.await
	.unwrap();

	assert!(verify);
}

//__________________________________________________________________________________________________
//encrypt tests

const STRING_DATA: &str = "hello there £ Я a a";

#[tokio::test]
async fn test_60_encrypt_data_for_other_user()
{
	let u = USER_TEST_STATE.get().unwrap().read().await;

	let u1 = USER_2_TEST_STATE.get().unwrap().read().await;

	let public_key_u1 =
		u.0.get_user_public_key_data(u1.0.get_user_id())
			.await
			.unwrap();

	let encrypted_string =
		u.0.encrypt_string_sync(STRING_DATA, &public_key_u1, false)
			.unwrap();

	//should not decrypt it again because it was decrypted by the other users public key

	let err = u.0.decrypt_string_sync(&encrypted_string, None);

	match err {
		Err(SentcError::KeyNotFound) => {},
		_ => panic!("should be error"),
	}

	//decrypt with the right user

	let str = u1.0.decrypt_string_sync(&encrypted_string, None).unwrap();

	assert_eq!(str, STRING_DATA);
}

#[tokio::test]
async fn test_61_encrypt_data_for_other_user_with_sign()
{
	let u = USER_TEST_STATE.get().unwrap().read().await;

	let u1 = USER_2_TEST_STATE.get().unwrap().read().await;

	let public_key_u1 =
		u.0.get_user_public_key_data(u1.0.get_user_id())
			.await
			.unwrap();

	let encrypted_string =
		u.0.encrypt_string_sync(STRING_DATA, &public_key_u1, true)
			.unwrap();

	//decrypt it without sign

	let str = u1.0.decrypt_string_sync(&encrypted_string, None).unwrap();

	assert_eq!(str, STRING_DATA);

	let head = split_head_and_encrypted_string(&encrypted_string).unwrap();

	let vk_u =
		u1.0.get_user_verify_key_data(u.0.get_user_id(), &head.sign.unwrap().id)
			.await
			.unwrap();

	//decrypt now with sign
	let str =
		u1.0.decrypt_string_sync(&encrypted_string, Some(&vk_u))
			.unwrap();

	assert_eq!(str, STRING_DATA);
}

#[tokio::test]
async fn zzz_clean_up()
{
	let u = USER_TEST_STATE.get().unwrap().read().await;

	u.0.delete(PW, None, None).await.unwrap();

	let u = USER_2_TEST_STATE.get().unwrap().read().await;

	u.0.delete(PW, None, None).await.unwrap();

	let u = USER_3_TEST_STATE.get().unwrap().read().await;

	u.0.delete(PW, None, None).await.unwrap();

	//delete the not logged in user
	let user = TestUser::login_forced(
		"http://127.0.0.1:3002".into(),
		"5zMb6zs3dEM62n+FxjBilFPp+j9e7YUFA+7pi6Hi",
		&(USERNAME.to_string() + "3"),
		PW,
	)
	.await
	.unwrap();

	user.delete(PW, None, None).await.unwrap();
}
