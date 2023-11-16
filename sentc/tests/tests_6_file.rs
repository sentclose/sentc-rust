use std::env;
use std::ops::Deref;
use std::sync::Arc;

use sentc::error::SentcError;
use sentc::group::Group;
use sentc::sentc::Sentc;
use sentc::user::User;
use sentc_crypto::SdkError;
use tokio::sync::{OnceCell, RwLock};

struct UserState(Arc<RwLock<User>>);

impl Deref for UserState
{
	type Target = Arc<RwLock<User>>;

	fn deref(&self) -> &Self::Target
	{
		&self.0
	}
}

struct GroupState(Arc<RwLock<Group>>);

impl Deref for GroupState
{
	type Target = Arc<RwLock<Group>>;

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
static GROUP_0_TEST_STATE: OnceCell<RwLock<GroupState>> = OnceCell::const_new();
static GROUP_1_TEST_STATE: OnceCell<RwLock<GroupState>> = OnceCell::const_new();

static SENTC: OnceCell<Sentc> = OnceCell::const_new();

static FILE_STATE: OnceCell<FileTestState> = OnceCell::const_new();

static FILE_TEST_STATE: OnceCell<RwLock<FileState>> = OnceCell::const_new();

const USERNAME0: &str = "test0";
const USERNAME1: &str = "test1";
const PW: &str = "12345";

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

	sentc.register(USERNAME0, PW).await.unwrap();
	let user = sentc.login_forced(USERNAME0, PW).await.unwrap();
	USER_0_TEST_STATE
		.get_or_init(|| async move { RwLock::new(UserState(user)) })
		.await;

	sentc.register(USERNAME1, PW).await.unwrap();
	let user = sentc.login_forced(USERNAME1, PW).await.unwrap();
	USER_1_TEST_STATE
		.get_or_init(|| async move { RwLock::new(UserState(user)) })
		.await;

	SENTC.get_or_init(|| async move { sentc }).await;

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
async fn test_10_create_and_fetch_a_group()
{
	let u = USER_0_TEST_STATE.get().unwrap().read().await;
	let mut uw = u.write().await;

	let group_id = uw
		.create_group(SENTC.get().unwrap().get_cache())
		.await
		.unwrap();

	let group = uw
		.get_group(&group_id, None, SENTC.get().unwrap().get_cache())
		.await
		.unwrap();

	let g_r = group.read().await;

	assert_eq!(group_id, g_r.get_group_id());

	drop(g_r);

	GROUP_0_TEST_STATE
		.get_or_init(|| async move { RwLock::new(GroupState(group)) })
		.await;
}

#[tokio::test]
async fn test_11_invite_2nd_user()
{
	let g = GROUP_0_TEST_STATE.get().unwrap().read().await;
	let g = g.read().await;

	let u = USER_1_TEST_STATE.get().unwrap().read().await;
	let mut uw = u.write().await;

	g.invite_auto(uw.get_user_id(), None, SENTC.get().unwrap().get_cache())
		.await
		.unwrap();

	let group = uw
		.get_group(g.get_group_id(), None, SENTC.get().unwrap().get_cache())
		.await
		.unwrap();

	GROUP_1_TEST_STATE
		.get_or_init(|| async move { RwLock::new(GroupState(group)) })
		.await;
}

#[tokio::test]
async fn test_20_create_file_from_the_sdk()
{
	let f = FILE_STATE.get().unwrap();

	let g = GROUP_0_TEST_STATE.get().unwrap().read().await;
	let g = g.read().await;

	let out = g
		.create_file_with_path(&f.upload_file_path, false, SENTC.get().unwrap().get_cache())
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
	let g = GROUP_1_TEST_STATE.get().unwrap().read().await;
	let mut g = g.write().await;

	g.download_file_with_path(&f.download_file_path, &ff, None, SENTC.get().unwrap().get_cache())
		.await
		.unwrap();
}

#[tokio::test]
async fn test_22_not_delete_file_without_rights()
{
	let g = GROUP_1_TEST_STATE.get().unwrap().read().await;
	let g = g.read().await;

	let ff = FILE_TEST_STATE.get().unwrap().read().await;

	let err = g.delete_file(&ff, SENTC.get().unwrap().get_cache()).await;

	match err {
		Err(SentcError::Sdk(SdkError::Util(sentc_crypto::sdk_utils::error::SdkUtilError::ServerErr(c, _)))) => {
			assert_eq!(c, 521);
		},
		_ => panic!("should be error"),
	}
}

#[tokio::test]
async fn test_23_delete_file_as_owner()
{
	let g = GROUP_0_TEST_STATE.get().unwrap().read().await;
	let g = g.read().await;

	let ff = FILE_TEST_STATE.get().unwrap().read().await;

	g.delete_file(&ff, SENTC.get().unwrap().get_cache())
		.await
		.unwrap();
}

#[tokio::test]
async fn test_24_upload_file_as_member()
{
	let f = FILE_STATE.get().unwrap();

	let g = GROUP_1_TEST_STATE.get().unwrap().read().await;
	let g = g.read().await;

	let out = g
		.create_file_with_path(&f.upload_file_path, false, SENTC.get().unwrap().get_cache())
		.await
		.unwrap();

	let mut f = FILE_TEST_STATE.get().unwrap().write().await;

	f.0 = out.file_id;
}

#[tokio::test]
async fn test_25_download_created_file()
{
	let f = FILE_STATE.get().unwrap();
	let ff = FILE_TEST_STATE.get().unwrap().read().await;

	//download as a group member
	let g = GROUP_0_TEST_STATE.get().unwrap().read().await;
	let mut g = g.write().await;

	g.download_file_with_path(&f.download_file_path, &ff, None, SENTC.get().unwrap().get_cache())
		.await
		.unwrap();
}

#[tokio::test]
async fn test_26_delete_file_as_group_owner()
{
	let g = GROUP_0_TEST_STATE.get().unwrap().read().await;
	let g = g.read().await;

	let ff = FILE_TEST_STATE.get().unwrap().read().await;

	//should work even if the user is not the file creator
	g.delete_file(&ff, SENTC.get().unwrap().get_cache())
		.await
		.unwrap();
}

#[tokio::test]
async fn zzz_clean_up()
{
	let g = GROUP_0_TEST_STATE.get().unwrap().read().await;
	let gr = g.read().await;
	gr.delete_group(SENTC.get().unwrap().get_cache())
		.await
		.unwrap();

	let u = USER_0_TEST_STATE.get().unwrap().read().await;
	let ur = u.read().await;
	ur.delete(PW, None, None, SENTC.get().unwrap().get_cache())
		.await
		.unwrap();

	let u = USER_1_TEST_STATE.get().unwrap().read().await;
	let ur = u.read().await;
	ur.delete(PW, None, None, SENTC.get().unwrap().get_cache())
		.await
		.unwrap();
}
