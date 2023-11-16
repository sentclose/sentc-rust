use std::ops::Deref;
use std::sync::Arc;

use sentc::cache::l_one::L1Cache;
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

static USER_0_TEST_STATE: OnceCell<RwLock<UserState>> = OnceCell::const_new();
static USER_1_TEST_STATE: OnceCell<RwLock<UserState>> = OnceCell::const_new();
static USER_2_TEST_STATE: OnceCell<RwLock<UserState>> = OnceCell::const_new();

static GROUP_0_TEST_STATE: OnceCell<RwLock<GroupState>> = OnceCell::const_new();
static GROUP_1_TEST_STATE: OnceCell<RwLock<GroupState>> = OnceCell::const_new();
static GROUP_2_TEST_STATE: OnceCell<RwLock<GroupState>> = OnceCell::const_new();

static CONNECTED_GROUP: OnceCell<RwLock<GroupState>> = OnceCell::const_new();
static CONNECTED_CHILD_GROUP: OnceCell<RwLock<GroupState>> = OnceCell::const_new();

static SENTC: OnceCell<Sentc> = OnceCell::const_new();

const USERNAME0: &str = "test0";
const USERNAME1: &str = "test1";
const USERNAME2: &str = "test2";

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

	sentc.register(USERNAME2, PW).await.unwrap();
	let user = sentc.login_forced(USERNAME2, PW).await.unwrap();
	USER_2_TEST_STATE
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

	GROUP_0_TEST_STATE
		.get_or_init(|| async move { RwLock::new(GroupState(group)) })
		.await;

	let u = USER_1_TEST_STATE.get().unwrap().read().await;
	let mut uw = u.write().await;

	let group_id = uw
		.create_group(SENTC.get().unwrap().get_cache())
		.await
		.unwrap();

	let group = uw
		.get_group(&group_id, None, SENTC.get().unwrap().get_cache())
		.await
		.unwrap();

	GROUP_1_TEST_STATE
		.get_or_init(|| async move { RwLock::new(GroupState(group)) })
		.await;

	let u = USER_2_TEST_STATE.get().unwrap().read().await;
	let mut uw = u.write().await;

	let group_id = uw
		.create_group(SENTC.get().unwrap().get_cache())
		.await
		.unwrap();

	let group = uw
		.get_group(&group_id, None, SENTC.get().unwrap().get_cache())
		.await
		.unwrap();

	GROUP_2_TEST_STATE
		.get_or_init(|| async move { RwLock::new(GroupState(group)) })
		.await;
}

#[tokio::test]
async fn test_11_create_connected_group()
{
	let g = GROUP_0_TEST_STATE.get().unwrap().read().await;
	let g = g.read().await;

	let id = g
		.create_connected_group(SENTC.get().unwrap().get_cache())
		.await
		.unwrap();

	let con_group = g
		.get_connected_group(&id, SENTC.get().unwrap().get_cache())
		.await
		.unwrap();

	let g1 = con_group.read().await;

	assert_eq!(g1.get_group_id(), id);
	assert_eq!(g1.access_by_group_as_member(), Some(&g.get_group_id().to_string()));

	drop(g1);

	CONNECTED_GROUP
		.get_or_init(|| async move { RwLock::new(GroupState(con_group)) })
		.await;
}

#[tokio::test]
async fn test_12_key_rotation_in_connected_group()
{
	let g = CONNECTED_GROUP.get().unwrap().read().await;
	let mut g = g.write().await;

	let old_key = g.get_newest_key().unwrap().group_key.key_id.clone();

	g.key_rotation(false, SENTC.get().unwrap().get_cache())
		.await
		.unwrap();

	let new_key = &g.get_newest_key().unwrap().group_key.key_id;

	assert_ne!(&old_key, new_key);
}

#[tokio::test]
async fn test_13_not_access_connected_group_directly()
{
	let g = CONNECTED_GROUP.get().unwrap().read().await;
	let g = g.read().await;

	//user got only access via connected group and not direct

	let u = USER_0_TEST_STATE.get().unwrap().read().await;
	let mut uw = u.write().await;

	//do not use group as member for this test
	let err = uw
		.get_group(g.get_group_id(), None, SENTC.get().unwrap().get_cache())
		.await;

	match err {
		Err(SentcError::Sdk(SdkError::Util(sentc_crypto::sdk_utils::error::SdkUtilError::ServerErr(c, _)))) => {
			assert_eq!(c, 310);
		},
		_ => panic!("should be error"),
	}
}

#[tokio::test]
async fn test_14_access_group_from_user_with_group()
{
	let g = CONNECTED_GROUP.get().unwrap().read().await;
	let g = g.read().await;

	let g1 = GROUP_0_TEST_STATE.get().unwrap().read().await;
	let g1 = g1.read().await;

	let u = USER_0_TEST_STATE.get().unwrap().read().await;
	let mut uw = u.write().await;

	let group = uw
		.get_group(
			g.get_group_id(),
			Some(g1.get_group_id()),
			SENTC.get().unwrap().get_cache(),
		)
		.await
		.unwrap();

	let group = group.read().await;

	assert_eq!(group.get_group_id(), g.get_group_id());
	assert_eq!(group.get_access_group_as_member(), g.get_access_group_as_member())
}

#[tokio::test]
async fn test_15_not_access_connected_group_without_group_access()
{
	let g = CONNECTED_GROUP.get().unwrap().read().await;
	let g = g.read().await;

	let g1 = GROUP_0_TEST_STATE.get().unwrap().read().await;
	let g1 = g1.read().await;

	let u = USER_1_TEST_STATE.get().unwrap().read().await;
	let mut uw = u.write().await;

	//use an empty cache because the cache of the connected group already exists
	let err = uw
		.get_group(g.get_group_id(), Some(g1.get_group_id()), &L1Cache::new())
		.await;

	match err {
		Err(SentcError::Sdk(SdkError::Util(sentc_crypto::sdk_utils::error::SdkUtilError::ServerErr(c, _)))) => {
			assert_eq!(c, 310);
		},
		_ => panic!("should be error"),
	}
}

#[tokio::test]
async fn test_16_create_child_group_from_connected_group()
{
	let g = CONNECTED_GROUP.get().unwrap().read().await;
	let g = g.read().await;

	let g1 = GROUP_0_TEST_STATE.get().unwrap().read().await;
	let g1 = g1.read().await;

	let id = g
		.create_child_group(SENTC.get().unwrap().get_cache())
		.await
		.unwrap();

	let group = g
		.get_child_group(&id, SENTC.get().unwrap().get_cache())
		.await
		.unwrap();

	let gr = group.read().await;

	assert_eq!(gr.get_access_group_as_member().unwrap(), g1.get_group_id());

	drop(gr);

	CONNECTED_CHILD_GROUP
		.get_or_init(|| async move { RwLock::new(GroupState(group)) })
		.await;
}

#[tokio::test]
async fn test_17_invite_user_to_main_group_to_check_access()
{
	let g = GROUP_0_TEST_STATE.get().unwrap().read().await;
	let g = g.read().await;

	let g1 = CONNECTED_CHILD_GROUP.get().unwrap().read().await;
	let g1 = g1.read().await;

	let u = USER_1_TEST_STATE.get().unwrap().read().await;
	let mut u = u.write().await;

	g.invite_auto(u.get_user_id(), None, SENTC.get().unwrap().get_cache())
		.await
		.unwrap();

	//access the child connected group without loading the other groups before (use an empty cache)
	let gc = u
		.get_group(g1.get_group_id(), Some(g.get_group_id()), &L1Cache::new())
		.await
		.unwrap();

	let gc = gc.read().await;

	assert_eq!(gc.get_access_group_as_member().unwrap(), g.get_group_id());
}

#[tokio::test]
async fn test_18_invite_group_as_member()
{
	let g = CONNECTED_GROUP.get().unwrap().read().await;
	let g = g.read().await;

	let g1 = GROUP_2_TEST_STATE.get().unwrap().read().await;
	let g1 = g1.read().await;

	g.invite_group_auto(g1.get_group_id(), None, SENTC.get().unwrap().get_cache())
		.await
		.unwrap();
}

#[tokio::test]
async fn test_19_re_invite_group_as_member()
{
	let g = CONNECTED_GROUP.get().unwrap().read().await;
	let g = g.read().await;

	let g1 = GROUP_2_TEST_STATE.get().unwrap().read().await;
	let g1 = g1.read().await;

	g.re_invite_group(g1.get_group_id(), SENTC.get().unwrap().get_cache())
		.await
		.unwrap();
}

#[tokio::test]
async fn test_20_access_group_after_invite()
{
	let g = CONNECTED_GROUP.get().unwrap().read().await;
	let g = g.read().await;

	let g1 = GROUP_2_TEST_STATE.get().unwrap().read().await;
	let g1 = g1.read().await;

	let g3 = g1
		.get_connected_group(g.get_group_id(), SENTC.get().unwrap().get_cache())
		.await
		.unwrap();

	let gr = g3.read().await;

	assert_eq!(gr.get_access_group_as_member().unwrap(), g1.get_group_id());
}

#[tokio::test]
async fn test_21_send_join_req_from_2nd_group_to_new_group()
{
	let g = CONNECTED_GROUP.get().unwrap().read().await;
	let g = g.read().await;

	let g1 = GROUP_1_TEST_STATE.get().unwrap().read().await;
	let g1 = g1.read().await;

	g1.group_join_request(g.get_group_id(), SENTC.get().unwrap().get_cache())
		.await
		.unwrap();

	let joins = g1
		.get_group_sent_join_req(SENTC.get().unwrap().get_cache(), None)
		.await
		.unwrap();

	assert_eq!(joins.len(), 1);
	assert_eq!(joins[0].group_id, g.get_group_id());
}

#[tokio::test]
async fn test_22_get_join_req_on_list_in_group()
{
	let g = CONNECTED_GROUP.get().unwrap().read().await;
	let g = g.read().await;

	let g1 = GROUP_1_TEST_STATE.get().unwrap().read().await;
	let g1 = g1.read().await;

	let joins = g
		.get_join_requests(None, SENTC.get().unwrap().get_cache())
		.await
		.unwrap();

	assert_eq!(joins.len(), 1);
	assert_eq!(joins[0].user_id, g1.get_group_id());
	assert_eq!(joins[0].user_type, 2);
}

#[tokio::test]
async fn test_23_reject_join_req()
{
	let g = CONNECTED_GROUP.get().unwrap().read().await;
	let g = g.read().await;

	let g1 = GROUP_1_TEST_STATE.get().unwrap().read().await;
	let g1 = g1.read().await;

	g.reject_join_request(g1.get_group_id(), SENTC.get().unwrap().get_cache())
		.await
		.unwrap();
}

#[tokio::test]
async fn test_24_send_join_again_and_accept()
{
	let g = CONNECTED_GROUP.get().unwrap().read().await;
	let g = g.read().await;

	let g1 = GROUP_1_TEST_STATE.get().unwrap().read().await;
	let g1 = g1.read().await;

	g1.group_join_request(g.get_group_id(), SENTC.get().unwrap().get_cache())
		.await
		.unwrap();

	g.accept_join_request(g1.get_group_id(), 2, None, SENTC.get().unwrap().get_cache())
		.await
		.unwrap();
}

#[tokio::test]
async fn test_25_fetch_connected_group()
{
	let g = CONNECTED_GROUP.get().unwrap().read().await;
	let g = g.read().await;

	let g1 = GROUP_1_TEST_STATE.get().unwrap().read().await;
	let g1 = g1.read().await;

	let gc = g1
		.get_connected_group(g.get_group_id(), SENTC.get().unwrap().get_cache())
		.await
		.unwrap();
	let gc = gc.read().await;

	assert_eq!(gc.get_access_group_as_member().unwrap(), g1.get_group_id());
}

#[tokio::test]
async fn test_26_get_all_connected_groups()
{
	let g1 = GROUP_1_TEST_STATE.get().unwrap().read().await;
	let g1 = g1.read().await;

	let list = g1
		.get_groups(SENTC.get().unwrap().get_cache(), None)
		.await
		.unwrap();

	assert_eq!(list.len(), 1);

	let list_2 = g1
		.get_groups(SENTC.get().unwrap().get_cache(), Some(list.get(0).unwrap()))
		.await
		.unwrap();

	assert_eq!(list_2.len(), 0);
}

#[tokio::test]
async fn zzz_clean_up()
{
	let g = CONNECTED_GROUP.get().unwrap().read().await;
	let gr = g.read().await;
	gr.delete_group(SENTC.get().unwrap().get_cache())
		.await
		.unwrap();

	let g = GROUP_0_TEST_STATE.get().unwrap().read().await;
	let gr = g.read().await;
	gr.delete_group(SENTC.get().unwrap().get_cache())
		.await
		.unwrap();

	let g = GROUP_1_TEST_STATE.get().unwrap().read().await;
	let gr = g.read().await;
	gr.delete_group(SENTC.get().unwrap().get_cache())
		.await
		.unwrap();

	let g = GROUP_2_TEST_STATE.get().unwrap().read().await;
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

	let u = USER_2_TEST_STATE.get().unwrap().read().await;
	let ur = u.read().await;
	ur.delete(PW, None, None, SENTC.get().unwrap().get_cache())
		.await
		.unwrap();
}
