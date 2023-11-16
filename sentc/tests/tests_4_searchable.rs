use std::ops::Deref;
use std::sync::Arc;

use sentc::group::Group;
use sentc::sentc::Sentc;
use sentc::user::User;
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

static USER_0_TEST_STATE: OnceCell<RwLock<UserState>> = OnceCell::const_new();
static USER_1_TEST_STATE: OnceCell<RwLock<UserState>> = OnceCell::const_new();

static GROUP_0_TEST_STATE: OnceCell<RwLock<GroupState>> = OnceCell::const_new();
static GROUP_1_TEST_STATE: OnceCell<RwLock<GroupState>> = OnceCell::const_new();

static SENTC: OnceCell<Sentc> = OnceCell::const_new();

static SEARCH_STR: OnceCell<Vec<String>> = OnceCell::const_new();
static SEARCH_FULL_STR: OnceCell<Vec<String>> = OnceCell::const_new();

const USERNAME0: &str = "test0";
const USERNAME1: &str = "test1";

const PW: &str = "12345";

const STR: &str = "123*+^êéèüöß@€&$ 👍 🚀 😎";

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
}

#[tokio::test]
async fn test_10_create_and_fetch_group()
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

	drop(uw);

	let g = group.read().await;

	let u = USER_1_TEST_STATE.get().unwrap().read().await;
	let mut ur = u.write().await;

	g.invite_auto(ur.get_user_id(), None, SENTC.get().unwrap().get_cache())
		.await
		.unwrap();

	drop(g);

	let group1 = ur
		.get_group(&group_id, None, SENTC.get().unwrap().get_cache())
		.await
		.unwrap();

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
	let gr = g.read().await;

	let str = gr.create_search_raw(STR, true, None).unwrap();

	assert_eq!(str.len(), 1);

	SEARCH_FULL_STR.get_or_init(|| async move { str }).await;
}

#[tokio::test]
async fn test_12_create_search()
{
	let g = GROUP_0_TEST_STATE.get().unwrap().read().await;
	let gr = g.read().await;

	let str = gr.create_search_raw(STR, false, None).unwrap();

	assert_eq!(str.len(), 39);

	SEARCH_STR.get_or_init(|| async { str }).await;
}

#[tokio::test]
async fn test_13_search_item()
{
	let g = GROUP_1_TEST_STATE.get().unwrap().read().await;
	let gr = g.read().await;

	let str = SEARCH_STR.get().unwrap();
	let str_full = SEARCH_FULL_STR.get().unwrap();

	let str_item = gr.search(STR).unwrap();

	assert_eq!(*str_full.get(0).unwrap(), str_item);
	assert!(str.contains(&str_item));
}

#[tokio::test]
async fn test_14_search_item_in_parts()
{
	let g = GROUP_1_TEST_STATE.get().unwrap().read().await;
	let gr = g.read().await;

	let str = SEARCH_STR.get().unwrap();

	let str_item = gr.search("123").unwrap();

	assert!(str.contains(&str_item));
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
