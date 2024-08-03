use std::ops::{Deref, DerefMut};

use sentc_crypto_light::error::SdkLightError;
use sentc_light::error::SentcError;
use sentc_light::group::Group;
use sentc_light::user::net::{login_forced, register};
use sentc_light::user::User;
use tokio::sync::{OnceCell, RwLock};

struct UserState(User);

impl Deref for UserState
{
	type Target = User;

	fn deref(&self) -> &Self::Target
	{
		&self.0
	}
}

struct GroupState(Group);

impl Deref for GroupState
{
	type Target = Group;

	fn deref(&self) -> &Self::Target
	{
		&self.0
	}
}

impl DerefMut for GroupState
{
	fn deref_mut(&mut self) -> &mut Self::Target
	{
		&mut self.0
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

const USERNAME0: &str = "test0";
const USERNAME1: &str = "test1";
const USERNAME2: &str = "test2";

const PW: &str = "12345";

#[tokio::test]
async fn aaa_init_global_test()
{
	register(
		"http://127.0.0.1:3002".into(),
		"5zMb6zs3dEM62n+FxjBilFPp+j9e7YUFA+7pi6Hi",
		USERNAME0,
		PW,
	)
	.await
	.unwrap();
	let user = login_forced(
		"http://127.0.0.1:3002".into(),
		"5zMb6zs3dEM62n+FxjBilFPp+j9e7YUFA+7pi6Hi".into(),
		USERNAME0,
		PW,
	)
	.await
	.unwrap();

	USER_0_TEST_STATE
		.get_or_init(|| async move { RwLock::new(UserState(user)) })
		.await;

	register(
		"http://127.0.0.1:3002".into(),
		"5zMb6zs3dEM62n+FxjBilFPp+j9e7YUFA+7pi6Hi",
		USERNAME1,
		PW,
	)
	.await
	.unwrap();
	let user = login_forced(
		"http://127.0.0.1:3002".into(),
		"5zMb6zs3dEM62n+FxjBilFPp+j9e7YUFA+7pi6Hi".into(),
		USERNAME1,
		PW,
	)
	.await
	.unwrap();
	USER_1_TEST_STATE
		.get_or_init(|| async move { RwLock::new(UserState(user)) })
		.await;

	register(
		"http://127.0.0.1:3002".into(),
		"5zMb6zs3dEM62n+FxjBilFPp+j9e7YUFA+7pi6Hi",
		USERNAME2,
		PW,
	)
	.await
	.unwrap();
	let user = login_forced(
		"http://127.0.0.1:3002".into(),
		"5zMb6zs3dEM62n+FxjBilFPp+j9e7YUFA+7pi6Hi".into(),
		USERNAME2,
		PW,
	)
	.await
	.unwrap();
	USER_2_TEST_STATE
		.get_or_init(|| async move { RwLock::new(UserState(user)) })
		.await;
}

#[tokio::test]
async fn test_10_create_and_fetch_group()
{
	let u = USER_0_TEST_STATE.get().unwrap().read().await;

	let group_id = u.create_group().await.unwrap();

	let group = u.get_group(&group_id, None).await.unwrap();

	GROUP_0_TEST_STATE
		.get_or_init(|| async move { RwLock::new(GroupState(group)) })
		.await;

	let u = USER_1_TEST_STATE.get().unwrap().read().await;

	let group_id = u.create_group().await.unwrap();

	let group = u.get_group(&group_id, None).await.unwrap();

	GROUP_1_TEST_STATE
		.get_or_init(|| async move { RwLock::new(GroupState(group)) })
		.await;

	let u = USER_2_TEST_STATE.get().unwrap().read().await;

	let group_id = u.create_group().await.unwrap();

	let group = u.get_group(&group_id, None).await.unwrap();

	GROUP_2_TEST_STATE
		.get_or_init(|| async move { RwLock::new(GroupState(group)) })
		.await;
}

#[tokio::test]
async fn test_11_create_connected_group()
{
	let g = GROUP_0_TEST_STATE.get().unwrap().read().await;
	let u0 = USER_0_TEST_STATE.get().unwrap().read().await;

	let id = g
		.create_connected_group(u0.get_jwt().unwrap())
		.await
		.unwrap();

	let con_group = g
		.get_connected_group(&id, u0.get_jwt().unwrap())
		.await
		.unwrap();

	assert_eq!(con_group.get_group_id(), id);
	assert_eq!(
		con_group.access_by_group_as_member(),
		Some(&g.get_group_id().to_string())
	);

	CONNECTED_GROUP
		.get_or_init(|| async move { RwLock::new(GroupState(con_group)) })
		.await;
}

#[tokio::test]
async fn test_13_not_access_connected_group_directly()
{
	let g = CONNECTED_GROUP.get().unwrap().read().await;

	//user got only access via connected group and not direct

	let u = USER_0_TEST_STATE.get().unwrap().read().await;

	//do not use group as member for this test
	let err = u.get_group(g.get_group_id(), None).await;

	match err {
		Err(SentcError::Sdk(SdkLightError::Util(sentc_crypto_light::sdk_utils::error::SdkUtilError::ServerErr(c, _)))) => {
			assert_eq!(c, 310);
		},
		_ => panic!("should be error"),
	}
}

#[tokio::test]
async fn test_14_access_group_from_user_with_group()
{
	let g = CONNECTED_GROUP.get().unwrap().read().await;

	let g1 = GROUP_0_TEST_STATE.get().unwrap().read().await;

	let u = USER_0_TEST_STATE.get().unwrap().read().await;

	let group = u
		.get_group(g.get_group_id(), Some(g1.get_group_id()))
		.await
		.unwrap();

	assert_eq!(group.get_group_id(), g.get_group_id());
	assert_eq!(group.get_access_group_as_member(), g.get_access_group_as_member())
}

#[tokio::test]
async fn test_15_not_access_connected_group_without_group_access()
{
	let g = CONNECTED_GROUP.get().unwrap().read().await;

	let g1 = GROUP_0_TEST_STATE.get().unwrap().read().await;

	let u = USER_1_TEST_STATE.get().unwrap().read().await;

	let err = u.get_group(g.get_group_id(), Some(g1.get_group_id())).await;

	match err {
		Err(SentcError::Sdk(SdkLightError::Util(sentc_crypto_light::sdk_utils::error::SdkUtilError::ServerErr(c, _)))) => {
			assert_eq!(c, 310);
		},
		_ => panic!("should be error"),
	}
}

#[tokio::test]
async fn test_16_create_child_group_from_connected_group()
{
	let g = CONNECTED_GROUP.get().unwrap().read().await;
	let u0 = USER_0_TEST_STATE.get().unwrap().read().await;

	let g1 = GROUP_0_TEST_STATE.get().unwrap().read().await;

	let id = g.create_child_group(u0.get_jwt().unwrap()).await.unwrap();

	let group = g.get_child_group(&id, u0.get_jwt().unwrap()).await.unwrap();

	assert_eq!(group.get_access_group_as_member().unwrap(), g1.get_group_id());

	CONNECTED_CHILD_GROUP
		.get_or_init(|| async move { RwLock::new(GroupState(group)) })
		.await;
}

#[tokio::test]
async fn test_17_invite_user_to_main_group_to_check_access()
{
	let g = GROUP_0_TEST_STATE.get().unwrap().read().await;
	let u0 = USER_0_TEST_STATE.get().unwrap().read().await;

	let g1 = CONNECTED_CHILD_GROUP.get().unwrap().read().await;
	let gp = CONNECTED_GROUP.get().unwrap().read().await;

	let u = USER_1_TEST_STATE.get().unwrap().read().await;

	g.invite_auto(u0.get_jwt().unwrap(), u.get_user_id(), None)
		.await
		.unwrap();

	//__________________________________________________________

	let gu = u.get_group(g.get_group_id(), None).await.unwrap();

	let cgp = u
		.get_group(gp.get_group_id(), Some(gu.get_group_id()))
		.await
		.unwrap();

	let group = cgp
		.get_child_group(g1.get_group_id(), u.get_jwt().unwrap())
		.await
		.unwrap();

	assert_eq!(group.get_access_group_as_member().unwrap(), g.get_group_id());
}

#[tokio::test]
async fn test_18_invite_group_as_member()
{
	let g = CONNECTED_GROUP.get().unwrap().read().await;
	let u0 = USER_0_TEST_STATE.get().unwrap().read().await;

	let g1 = GROUP_2_TEST_STATE.get().unwrap().read().await;

	g.invite_group_auto(u0.get_jwt().unwrap(), g1.get_group_id(), None)
		.await
		.unwrap();
}

#[tokio::test]
async fn test_19_access_group_after_invite()
{
	let g = CONNECTED_GROUP.get().unwrap().read().await;

	let g1 = GROUP_2_TEST_STATE.get().unwrap().read().await;
	let u2 = USER_2_TEST_STATE.get().unwrap().read().await;

	let g3 = g1
		.get_connected_group(g.get_group_id(), u2.get_jwt().unwrap())
		.await
		.unwrap();

	assert_eq!(g3.get_access_group_as_member().unwrap(), g1.get_group_id());
}

#[tokio::test]
async fn test_21_send_join_req_from_2nd_group_to_new_group()
{
	let g = CONNECTED_GROUP.get().unwrap().read().await;

	let g1 = GROUP_1_TEST_STATE.get().unwrap().read().await;
	let u1 = USER_1_TEST_STATE.get().unwrap().read().await;

	g1.group_join_request(u1.get_jwt().unwrap(), g.get_group_id())
		.await
		.unwrap();

	let joins = g1
		.get_group_sent_join_req(u1.get_jwt().unwrap(), None)
		.await
		.unwrap();

	assert_eq!(joins.len(), 1);
	assert_eq!(joins[0].group_id, g.get_group_id());
}

#[tokio::test]
async fn test_22_get_join_req_on_list_in_group()
{
	let g = CONNECTED_GROUP.get().unwrap().read().await;
	let u0 = USER_0_TEST_STATE.get().unwrap().read().await;

	let g1 = GROUP_1_TEST_STATE.get().unwrap().read().await;

	let joins = g
		.get_join_requests(u0.get_jwt().unwrap(), None)
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
	let u0 = USER_0_TEST_STATE.get().unwrap().read().await;

	let g1 = GROUP_1_TEST_STATE.get().unwrap().read().await;

	g.reject_join_request(u0.get_jwt().unwrap(), g1.get_group_id())
		.await
		.unwrap();
}

#[tokio::test]
async fn test_24_send_join_again_and_accept()
{
	let g = CONNECTED_GROUP.get().unwrap().read().await;
	let u0 = USER_0_TEST_STATE.get().unwrap().read().await;

	let g1 = GROUP_1_TEST_STATE.get().unwrap().read().await;
	let u1 = USER_1_TEST_STATE.get().unwrap().read().await;

	g1.group_join_request(u1.get_jwt().unwrap(), g.get_group_id())
		.await
		.unwrap();

	g.accept_join_request(u0.get_jwt().unwrap(), g1.get_group_id(), None)
		.await
		.unwrap();
}

#[tokio::test]
async fn test_25_fetch_connected_group()
{
	let g = CONNECTED_GROUP.get().unwrap().read().await;

	let g1 = GROUP_1_TEST_STATE.get().unwrap().read().await;
	let u1 = USER_1_TEST_STATE.get().unwrap().read().await;

	let gc = g1
		.get_connected_group(g.get_group_id(), u1.get_jwt().unwrap())
		.await
		.unwrap();

	assert_eq!(gc.get_access_group_as_member().unwrap(), g1.get_group_id());
}

#[tokio::test]
async fn test_26_get_all_connected_groups()
{
	let g1 = GROUP_1_TEST_STATE.get().unwrap().read().await;
	let u1 = USER_1_TEST_STATE.get().unwrap().read().await;

	let list = g1.get_groups(u1.get_jwt().unwrap(), None).await.unwrap();

	assert_eq!(list.len(), 1);

	let list_2 = g1
		.get_groups(u1.get_jwt().unwrap(), Some(list.get(0).unwrap()))
		.await
		.unwrap();

	assert_eq!(list_2.len(), 0);
}

#[tokio::test]
async fn zzz_clean_up()
{
	let u = USER_0_TEST_STATE.get().unwrap().read().await;
	let u1 = USER_1_TEST_STATE.get().unwrap().read().await;
	let u2 = USER_2_TEST_STATE.get().unwrap().read().await;

	let g = CONNECTED_GROUP.get().unwrap().read().await;

	g.delete_group(u.get_jwt().unwrap()).await.unwrap();

	let g = GROUP_0_TEST_STATE.get().unwrap().read().await;

	g.delete_group(u.get_jwt().unwrap()).await.unwrap();

	let g = GROUP_1_TEST_STATE.get().unwrap().read().await;
	g.delete_group(u1.get_jwt().unwrap()).await.unwrap();

	let g = GROUP_2_TEST_STATE.get().unwrap().read().await;
	g.delete_group(u2.get_jwt().unwrap()).await.unwrap();

	u.delete(PW, None, None).await.unwrap();

	u1.delete(PW, None, None).await.unwrap();

	u2.delete(PW, None, None).await.unwrap();
}
