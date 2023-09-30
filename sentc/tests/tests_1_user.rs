use std::sync::Arc;

use sentc::error::SentcError;
use sentc::sentc::Sentc;
use sentc::user::User;
use sentc_crypto::SdkError;
use tokio::sync::{OnceCell, RwLock};

struct UserState(Arc<RwLock<User>>);

struct DeviceState
{
	identifier: String,
	pw: String,
	device_register_result: String,
}

static USER_TEST_STATE: OnceCell<RwLock<UserState>> = OnceCell::const_new();

static DEVICE_PRE_TEST_STATE: OnceCell<DeviceState> = OnceCell::const_new();
static DEVICE_TEST_STATE: OnceCell<RwLock<UserState>> = OnceCell::const_new();

static DEVICE_2_PRE_TEST_STATE: OnceCell<DeviceState> = OnceCell::const_new();
static DEVICE_2_TEST_STATE: OnceCell<RwLock<UserState>> = OnceCell::const_new();

static SENTC: OnceCell<Sentc> = OnceCell::const_new();

const USERNAME: &str = "test";
const PW: &str = "12345";
const NEW_PW: &str = "12";

#[tokio::test]
async fn aaa_init_global_test()
{
	let sentc = Sentc::init(
		"http://127.0.0.1:3002",
		"5zMb6zs3dEM62n+FxjBilFPp+j9e7YUFA+7pi6Hi",
		None,
		None,
	)
	.await;

	SENTC.get_or_init(|| async move { sentc }).await;
}

#[tokio::test]
async fn test_10_check_if_username_exists()
{
	let check = SENTC
		.get()
		.unwrap()
		.check_user_name_available(USERNAME)
		.await
		.unwrap();

	assert!(check);
}

#[tokio::test]
async fn test_11_register_and_login_user()
{
	let sentc = SENTC.get().unwrap();

	let user_id = sentc.register(USERNAME, PW).await.unwrap();

	let user = sentc.login_forced(USERNAME, PW).await.unwrap();

	let u_read = user.read().await;

	assert_eq!(user_id, u_read.get_user_id());

	drop(u_read);

	USER_TEST_STATE
		.get_or_init(|| async move { RwLock::new(UserState(user)) })
		.await;
}

#[tokio::test]
async fn test_12_change_password()
{
	let u = &USER_TEST_STATE.get().unwrap().read().await;
	let mut u_write = u.0.write().await;

	u_write
		.change_password(PW, NEW_PW, None, None)
		.await
		.unwrap();

	//TODO logout the user
}

#[tokio::test]
async fn test_13_not_login_with_old_pw()
{
	let err = SENTC.get().unwrap().login_forced(USERNAME, PW).await;

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
	let u = SENTC
		.get()
		.unwrap()
		.login_forced(USERNAME, NEW_PW)
		.await
		.unwrap();

	let mut u_s = USER_TEST_STATE.get().unwrap().write().await;

	u_s.0 = u;
}

#[tokio::test]
async fn test_15_reset_password()
{
	let u = USER_TEST_STATE.get().unwrap().read().await;
	let mut u_write = u.0.write().await;

	u_write
		.reset_password(PW, SENTC.get().unwrap().get_cache())
		.await
		.unwrap();

	//TODO log out again
}

#[tokio::test]
async fn test_16_not_login_with_new_password_after_reset()
{
	let err = SENTC.get().unwrap().login_forced(USERNAME, NEW_PW).await;

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
	let u = SENTC
		.get()
		.unwrap()
		.login_forced(USERNAME, PW)
		.await
		.unwrap();

	let mut u_s = USER_TEST_STATE.get().unwrap().write().await;

	u_s.0 = u;
}

//__________________________________________________________________________________________________
//device test

#[tokio::test]
async fn test_20_register_new_device()
{
	let (identifier, pw) = Sentc::generate_register_data().unwrap();

	let device_register_result = SENTC
		.get()
		.unwrap()
		.register_device_start(&identifier, &pw)
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

	let err = SENTC
		.get()
		.unwrap()
		.login_forced(&device_pre.identifier, &device_pre.pw)
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
	let mut u_write = u.0.write().await;

	u_write
		.register_device(&device_pre.device_register_result, SENTC.get().unwrap().get_cache())
		.await
		.unwrap();
}

#[tokio::test]
async fn test_23_login_with_new_device()
{
	let device_pre = DEVICE_PRE_TEST_STATE.get().unwrap();

	let u = SENTC
		.get()
		.unwrap()
		.login_forced(&device_pre.identifier, &device_pre.pw)
		.await
		.unwrap();

	DEVICE_TEST_STATE
		.get_or_init(|| async { RwLock::new(UserState(u)) })
		.await;
}

//__________________________________________________________________________________________________
//device key rotation

#[tokio::test]
async fn test_30_start_key_rotation()
{
	let u = USER_TEST_STATE.get().unwrap().read().await;

	u.0.write()
		.await
		.key_rotation(SENTC.get().unwrap().get_cache())
		.await
		.unwrap();
}

#[tokio::test]
async fn test_31_finish_key_rotation()
{
	let d = DEVICE_TEST_STATE.get().unwrap().read().await;
	let mut d_write = d.0.write().await;

	let old_newest_key_id = d_write.get_newest_key().unwrap().group_key.key_id.clone();

	d_write
		.finish_key_rotation(SENTC.get().unwrap().get_cache())
		.await
		.unwrap();

	let new_newest_key_id = d_write.get_newest_key().unwrap().group_key.key_id.clone();

	assert_ne!(old_newest_key_id, new_newest_key_id);
}

//2nd device test

#[tokio::test]
async fn test_40_register_new_device_after_key_rotation()
{
	let (identifier, pw) = Sentc::generate_register_data().unwrap();

	let device_register_result = SENTC
		.get()
		.unwrap()
		.register_device_start(&identifier, &pw)
		.await
		.unwrap();

	let u = USER_TEST_STATE.get().unwrap().read().await;
	let mut u_write = u.0.write().await;

	u_write
		.register_device(&device_register_result, SENTC.get().unwrap().get_cache())
		.await
		.unwrap();

	let u = SENTC
		.get()
		.unwrap()
		.login_forced(&identifier, &pw)
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
	let u_read = u.0.read().await;

	let d = DEVICE_TEST_STATE.get().unwrap().read().await;
	let d_read = d.0.read().await;

	let d2 = DEVICE_2_TEST_STATE.get().unwrap().read().await;
	let d2_read = d2.0.read().await;

	assert_eq!(
		u_read.get_newest_key().unwrap().group_key.key_id,
		d_read.get_newest_key().unwrap().group_key.key_id
	);
	assert_eq!(
		u_read.get_newest_key().unwrap().group_key.key_id,
		d2_read.get_newest_key().unwrap().group_key.key_id
	);
}

#[tokio::test]
async fn test_42_list_all_devices()
{
	let c = SENTC.get().unwrap().get_cache();

	let u = USER_TEST_STATE.get().unwrap().read().await;
	let mut u_write = u.0.write().await;

	let device_list = u_write.get_devices(None, c).await.unwrap();

	assert_eq!(device_list.len(), 3);

	//next page
	let device_list_next = u_write.get_devices(device_list.get(0), c).await.unwrap();

	assert_eq!(device_list_next.len(), 2);
}

#[tokio::test]
async fn test_43_delete_device()
{
	let u = USER_TEST_STATE.get().unwrap().read().await;
	let u_write = u.0.read().await;

	let d = DEVICE_2_TEST_STATE.get().unwrap().read().await;
	let d_r = d.0.read().await;
	let d_id = d_r.get_device_id();

	u_write.delete_device(PW, d_id, None, None).await.unwrap();
}

#[tokio::test]
async fn test_44_not_login_with_deleted_device()
{
	let d2 = DEVICE_2_PRE_TEST_STATE.get().unwrap();

	let err = SENTC
		.get()
		.unwrap()
		.login_forced(&d2.identifier, &d2.pw)
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

/*
TODO:
	- safety number (with multiple users
	- verify public key
 */

#[tokio::test]
async fn zzz_clean_up()
{
	let u = USER_TEST_STATE.get().unwrap().read().await;

	let ur = u.0.read().await;

	ur.delete(PW, None, None, SENTC.get().unwrap().get_cache())
		.await
		.unwrap();
}
