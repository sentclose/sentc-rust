use std::ops::{Deref, DerefMut};

use sentc_crypto_light::error::SdkLightError;
use sentc_light::error::SentcError;
use sentc_light::user::net::{check_user_name_available, login_forced, register, register_device_start};
use sentc_light::user::{generate_register_data, User};
use tokio::sync::{OnceCell, RwLock};

pub struct UserState(User);

impl Deref for UserState
{
	type Target = User;

	fn deref(&self) -> &Self::Target
	{
		&self.0
	}
}

impl DerefMut for UserState
{
	fn deref_mut(&mut self) -> &mut Self::Target
	{
		&mut self.0
	}
}

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
	let user_id = register(
		"http://127.0.0.1:3002".into(),
		"5zMb6zs3dEM62n+FxjBilFPp+j9e7YUFA+7pi6Hi",
		USERNAME,
		PW,
	)
	.await
	.unwrap();

	let user = login_forced(
		"http://127.0.0.1:3002".into(),
		"5zMb6zs3dEM62n+FxjBilFPp+j9e7YUFA+7pi6Hi".into(),
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

	u.change_password(PW, NEW_PW, None, None).await.unwrap();
}

#[tokio::test]
async fn test_13_not_login_with_old_pw()
{
	let err = login_forced(
		"http://127.0.0.1:3002".into(),
		"5zMb6zs3dEM62n+FxjBilFPp+j9e7YUFA+7pi6Hi".into(),
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
				SentcError::Sdk(SdkLightError::Util(sentc_crypto_light::sdk_utils::error::SdkUtilError::ServerErr(c, _))) => {
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
	let user = login_forced(
		"http://127.0.0.1:3002".into(),
		"5zMb6zs3dEM62n+FxjBilFPp+j9e7YUFA+7pi6Hi".into(),
		USERNAME,
		NEW_PW,
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

	let device_register_result = register_device_start(
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

	let err = login_forced(
		"http://127.0.0.1:3002".into(),
		"5zMb6zs3dEM62n+FxjBilFPp+j9e7YUFA+7pi6Hi".into(),
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
				SentcError::Sdk(SdkLightError::Util(sentc_crypto_light::sdk_utils::error::SdkUtilError::ServerErr(c, _))) => {
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

	let user = login_forced(
		"http://127.0.0.1:3002".into(),
		"5zMb6zs3dEM62n+FxjBilFPp+j9e7YUFA+7pi6Hi".into(),
		&device_pre.identifier,
		&device_pre.pw,
	)
	.await
	.unwrap();

	DEVICE_TEST_STATE
		.get_or_init(|| async { RwLock::new(UserState(user)) })
		.await;
}

#[tokio::test]
async fn test_24_register_new_device()
{
	let (identifier, pw) = generate_register_data().unwrap();

	let device_register_result = register_device_start(
		"http://127.0.0.1:3002".into(),
		"5zMb6zs3dEM62n+FxjBilFPp+j9e7YUFA+7pi6Hi",
		&identifier,
		&pw,
	)
	.await
	.unwrap();

	let u = USER_TEST_STATE.get().unwrap().read().await;
	u.0.register_device(&device_register_result).await.unwrap();

	let u = login_forced(
		"http://127.0.0.1:3002".into(),
		"5zMb6zs3dEM62n+FxjBilFPp+j9e7YUFA+7pi6Hi".into(),
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
async fn test_25_list_all_devices()
{
	let u = USER_TEST_STATE.get().unwrap().read().await;

	let device_list = u.0.get_devices(None).await.unwrap();

	assert_eq!(device_list.len(), 3);

	//next page
	let device_list_next = u.0.get_devices(device_list.first()).await.unwrap();

	assert_eq!(device_list_next.len(), 2);
}

#[tokio::test]
async fn test_26_delete_device()
{
	let u = USER_TEST_STATE.get().unwrap().read().await;

	let d = DEVICE_2_TEST_STATE.get().unwrap().read().await;
	let d_id = d.0.get_device_id();

	u.0.delete_device(NEW_PW, d_id, None, None).await.unwrap();
}

#[tokio::test]
async fn test_27_not_login_with_deleted_device()
{
	let d2 = DEVICE_2_PRE_TEST_STATE.get().unwrap();

	let err = login_forced(
		"http://127.0.0.1:3002".into(),
		"5zMb6zs3dEM62n+FxjBilFPp+j9e7YUFA+7pi6Hi".into(),
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
				SentcError::Sdk(SdkLightError::Util(sentc_crypto_light::sdk_utils::error::SdkUtilError::ServerErr(c, _))) => {
					assert_eq!(c, 100);
				},
				_ => panic!("should be server error"),
			}
		},
	}
}

#[tokio::test]
async fn zzz_clean_up()
{
	let u = USER_TEST_STATE.get().unwrap().read().await;

	u.0.delete(NEW_PW, None, None).await.unwrap();
}
