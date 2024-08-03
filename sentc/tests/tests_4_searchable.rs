use std::ops::Deref;

use sentc::group::net::GroupFetchResult;
use tokio::sync::{OnceCell, RwLock};

use crate::test_mod::{TestGroup, TestUser};

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

struct GroupState(TestGroup);

impl Deref for GroupState
{
	type Target = TestGroup;

	fn deref(&self) -> &Self::Target
	{
		&self.0
	}
}

static USER_0_TEST_STATE: OnceCell<RwLock<UserState>> = OnceCell::const_new();
static USER_1_TEST_STATE: OnceCell<RwLock<UserState>> = OnceCell::const_new();

static GROUP_0_TEST_STATE: OnceCell<RwLock<GroupState>> = OnceCell::const_new();
static GROUP_1_TEST_STATE: OnceCell<RwLock<GroupState>> = OnceCell::const_new();

static SEARCH_STR: OnceCell<Vec<String>> = OnceCell::const_new();
static SEARCH_FULL_STR: OnceCell<Vec<String>> = OnceCell::const_new();

const USERNAME0: &str = "test0";
const USERNAME1: &str = "test1";

const PW: &str = "12345";

const STR: &str = "123*+^êéèüöß@€&$ 👍 🚀 😎";

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
}

#[tokio::test]
async fn test_10_create_and_fetch_group()
{
	let u = USER_0_TEST_STATE.get().unwrap().read().await;

	let group_id = u.create_group().await.unwrap();

	let (data, res) = u.prepare_get_group(&group_id, None).await.unwrap();

	assert!(matches!(res, GroupFetchResult::Ok));

	let group = u.done_get_group(data, None).unwrap();

	let u1 = USER_1_TEST_STATE.get().unwrap().read().await;

	let pk = u.get_user_public_key_data(u1.get_user_id()).await.unwrap();

	group
		.invite_auto(u.get_jwt().unwrap(), u1.get_user_id(), &pk, None)
		.await
		.unwrap();

	let (data, res) = u1.prepare_get_group(&group_id, None).await.unwrap();

	assert!(matches!(res, GroupFetchResult::Ok));
	let group1 = u1.done_get_group(data, None).unwrap();

	GROUP_0_TEST_STATE
		.get_or_init(|| async move { RwLock::new(GroupState(group)) })
		.await;

	GROUP_1_TEST_STATE
		.get_or_init(|| async move { RwLock::new(GroupState(group1)) })
		.await;
}

#[tokio::test]
async fn test_11_create_full_search()
{
	let g = GROUP_0_TEST_STATE.get().unwrap().read().await;

	let str = g.create_search_raw(STR, true, None).unwrap();

	assert_eq!(str.len(), 1);

	SEARCH_FULL_STR.get_or_init(|| async move { str }).await;
}

#[tokio::test]
async fn test_12_create_search()
{
	let g = GROUP_0_TEST_STATE.get().unwrap().read().await;

	let str = g.create_search_raw(STR, false, None).unwrap();

	assert_eq!(str.len(), 39);

	SEARCH_STR.get_or_init(|| async { str }).await;
}

#[tokio::test]
async fn test_13_search_item()
{
	let g = GROUP_1_TEST_STATE.get().unwrap().read().await;

	let str = SEARCH_STR.get().unwrap();
	let str_full = SEARCH_FULL_STR.get().unwrap();

	let str_item = g.search(STR).unwrap();

	assert_eq!(*str_full.get(0).unwrap(), str_item);
	assert!(str.contains(&str_item));
}

#[tokio::test]
async fn test_14_search_item_in_parts()
{
	let g = GROUP_1_TEST_STATE.get().unwrap().read().await;

	let str = SEARCH_STR.get().unwrap();

	let str_item = g.search("123").unwrap();

	assert!(str.contains(&str_item));
}

#[tokio::test]
async fn zzz_clean_up()
{
	let u = USER_0_TEST_STATE.get().unwrap().read().await;

	let g = GROUP_0_TEST_STATE.get().unwrap().read().await;

	g.delete_group(u.get_jwt().unwrap()).await.unwrap();

	u.delete(PW, None, None).await.unwrap();

	let u = USER_1_TEST_STATE.get().unwrap().read().await;

	u.delete(PW, None, None).await.unwrap();
}
