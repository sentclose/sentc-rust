use std::env;
use std::ops::Deref;

use tokio::sync::{OnceCell, RwLock};

use crate::test_mod::TestUser;

mod test_mod;

struct UserState(TestUser);

impl Deref for UserState
{
	type Target = TestUser;

	fn deref(&self) -> &Self::Target
	{
		&self.0
	}
}

struct FileTestState
{
	upload_file_path: String,
	download_file_path: String,
}

struct FileState(String);

impl Deref for FileState
{
	type Target = String;

	fn deref(&self) -> &Self::Target
	{
		&self.0
	}
}

static USER_0_TEST_STATE: OnceCell<RwLock<UserState>> = OnceCell::const_new();
static USER_1_TEST_STATE: OnceCell<RwLock<UserState>> = OnceCell::const_new();

static FILE_STATE: OnceCell<FileTestState> = OnceCell::const_new();

static FILE_TEST_STATE: OnceCell<RwLock<FileState>> = OnceCell::const_new();
static FILE_TEST_STATE_2: OnceCell<RwLock<FileState>> = OnceCell::const_new();

const USERNAME0: &str = "test0";
const USERNAME1: &str = "test1";
const PW: &str = "12345";

#[tokio::test]
async fn aaa_init_global_test()
{
	TestUser::register(
		"http://127.0.0.1:3002".into(),
		"5zMb6zs3dEM62n+FxjBilFPp+j9e7YUFA+7pi6Hi",
		USERNAME0,
		PW,
	)
	.await
	.unwrap();
	let user = TestUser::login_forced(
		"http://127.0.0.1:3002".into(),
		"5zMb6zs3dEM62n+FxjBilFPp+j9e7YUFA+7pi6Hi",
		USERNAME0,
		PW,
	)
	.await
	.unwrap();
	USER_0_TEST_STATE
		.get_or_init(|| async move { RwLock::new(UserState(user)) })
		.await;

	TestUser::register(
		"http://127.0.0.1:3002".into(),
		"5zMb6zs3dEM62n+FxjBilFPp+j9e7YUFA+7pi6Hi",
		USERNAME1,
		PW,
	)
	.await
	.unwrap();
	let user = TestUser::login_forced(
		"http://127.0.0.1:3002".into(),
		"5zMb6zs3dEM62n+FxjBilFPp+j9e7YUFA+7pi6Hi",
		USERNAME1,
		PW,
	)
	.await
	.unwrap();
	USER_1_TEST_STATE
		.get_or_init(|| async move { RwLock::new(UserState(user)) })
		.await;

	dotenv::dotenv().ok();

	let upload_file_path = env::var("UPLOAD_PATH").unwrap();
	let download_file_path = env::var("DOWNLOAD_PATH").unwrap();

	FILE_STATE
		.get_or_init(|| {
			async move {
				FileTestState {
					download_file_path,
					upload_file_path,
				}
			}
		})
		.await;
}

#[tokio::test]
async fn test_20_create_file_from_the_sdk()
{
	let f = FILE_STATE.get().unwrap();

	let u0 = USER_0_TEST_STATE.get().unwrap().read().await;

	let out = u0
		.create_file_with_path(&f.upload_file_path, None, None, None, false)
		.await
		.unwrap();

	FILE_TEST_STATE
		.get_or_init(|| async move { RwLock::new(FileState(out.file_id)) })
		.await;
}

#[tokio::test]
async fn test_21_download_created_file()
{
	let f = FILE_STATE.get().unwrap();
	let ff = FILE_TEST_STATE.get().unwrap().read().await;

	//download as a group member
	let u0 = USER_0_TEST_STATE.get().unwrap().read().await;

	u0.download_file_with_path(&f.download_file_path, &ff, None, None)
		.await
		.unwrap();
}

#[tokio::test]
async fn test_23_delete_file_as_owner()
{
	let u0 = USER_0_TEST_STATE.get().unwrap().read().await;

	let ff = FILE_TEST_STATE.get().unwrap().read().await;

	u0.delete_file(&ff).await.unwrap();
}

//to another user

#[tokio::test]
async fn test_30_create_file_from_the_sdk()
{
	let f = FILE_STATE.get().unwrap();

	let u0 = USER_0_TEST_STATE.get().unwrap().read().await;
	let u1 = USER_1_TEST_STATE.get().unwrap().read().await;

	let id = u1.get_user_id();
	let reply_key = u0.get_user_public_key_data(id).await.unwrap();

	let out = u0
		.create_file_with_path(&f.upload_file_path, Some(id), Some(&reply_key), None, false)
		.await
		.unwrap();

	FILE_TEST_STATE_2
		.get_or_init(|| async move { RwLock::new(FileState(out.file_id)) })
		.await;
}

#[tokio::test]
async fn test_31_download_created_file()
{
	let f = FILE_STATE.get().unwrap();
	let ff = FILE_TEST_STATE_2.get().unwrap().read().await;

	//download as a group member
	let u1 = USER_1_TEST_STATE.get().unwrap().read().await;

	u1.download_file_with_path(&f.download_file_path, &ff, None, None)
		.await
		.unwrap();
}

#[tokio::test]
async fn test_33_delete_file_as_owner()
{
	let u0 = USER_0_TEST_STATE.get().unwrap().read().await;

	let ff = FILE_TEST_STATE_2.get().unwrap().read().await;

	u0.delete_file(&ff).await.unwrap();
}

#[tokio::test]
async fn zzz_clean_up()
{
	let u0 = USER_0_TEST_STATE.get().unwrap().read().await;

	u0.delete(PW, None, None).await.unwrap();

	let u = USER_1_TEST_STATE.get().unwrap().read().await;
	u.delete(PW, None, None).await.unwrap();
}
