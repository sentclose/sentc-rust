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
static USER_3_TEST_STATE: OnceCell<RwLock<UserState>> = OnceCell::const_new();

static GROUP_0_TEST_STATE: OnceCell<RwLock<GroupState>> = OnceCell::const_new();
static GROUP_1_TEST_STATE: OnceCell<RwLock<GroupState>> = OnceCell::const_new();
static GROUP_2_TEST_STATE: OnceCell<RwLock<GroupState>> = OnceCell::const_new();

static CHILD_GROUP: OnceCell<RwLock<GroupState>> = OnceCell::const_new();
static CHILD_GROUP_USER_2: OnceCell<RwLock<GroupState>> = OnceCell::const_new();
static CHILD_GROUP_USER_3: OnceCell<RwLock<GroupState>> = OnceCell::const_new();

const USERNAME0: &str = "test0";
const USERNAME1: &str = "test1";
const USERNAME2: &str = "test2";
const USERNAME3: &str = "test3";
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

	register(
		"http://127.0.0.1:3002".into(),
		"5zMb6zs3dEM62n+FxjBilFPp+j9e7YUFA+7pi6Hi",
		USERNAME3,
		PW,
	)
	.await
	.unwrap();
	let user = login_forced(
		"http://127.0.0.1:3002".into(),
		"5zMb6zs3dEM62n+FxjBilFPp+j9e7YUFA+7pi6Hi".into(),
		USERNAME3,
		PW,
	)
	.await
	.unwrap();
	USER_3_TEST_STATE
		.get_or_init(|| async move { RwLock::new(UserState(user)) })
		.await;
}

#[tokio::test]
async fn test_10_create_and_fetch_a_group()
{
	let u = USER_0_TEST_STATE.get().unwrap().read().await;

	let group_id = u.create_group().await.unwrap();

	let group = u.get_group(&group_id, None).await.unwrap();

	assert_eq!(group_id, group.get_group_id());

	GROUP_0_TEST_STATE
		.get_or_init(|| async move { RwLock::new(GroupState(group)) })
		.await;
}

#[tokio::test]
async fn test_11_get_all_groups_to_user()
{
	let u = USER_0_TEST_STATE.get().unwrap().read().await;

	let out = u.get_groups(None).await.unwrap();

	assert_eq!(out.len(), 1);

	let out = u.get_groups(Some(&out[0])).await.unwrap();

	assert_eq!(out.len(), 0);
}

#[tokio::test]
async fn test_12_not_get_group_as_non_member()
{
	let u = USER_1_TEST_STATE.get().unwrap().read().await;

	let g = GROUP_0_TEST_STATE.get().unwrap().read().await;
	let g_id = g.get_group_id();

	let err = u.get_group(g_id, None).await;

	match err {
		Err(SentcError::Sdk(SdkLightError::Util(sentc_crypto_light::sdk_utils::error::SdkUtilError::ServerErr(c, _)))) => {
			assert_eq!(c, 310);
		},
		_ => panic!("should be server error"),
	}
}

#[tokio::test]
async fn test_13_invite_2nd_user()
{
	let g = GROUP_0_TEST_STATE.get().unwrap().read().await;

	let u0 = USER_0_TEST_STATE.get().unwrap().read().await;
	let u = USER_1_TEST_STATE.get().unwrap().read().await;

	g.invite(u0.get_jwt().unwrap(), u.get_user_id(), None)
		.await
		.unwrap();
}

#[tokio::test]
async fn test_14_get_invite_for_2nd_user()
{
	let g = GROUP_0_TEST_STATE.get().unwrap().read().await;

	let u = USER_1_TEST_STATE.get().unwrap().read().await;

	let list = u.get_group_invites(None).await.unwrap();

	assert_eq!(list.len(), 1);

	assert_eq!(list[0].group_id, g.get_group_id());

	//2nd page

	let list = u.get_group_invites(list.first()).await.unwrap();

	assert_eq!(list.len(), 0);
}

#[tokio::test]
async fn test_15_reject_invite()
{
	let g = GROUP_0_TEST_STATE.get().unwrap().read().await;

	let u = USER_1_TEST_STATE.get().unwrap().read().await;

	u.reject_group_invite(g.get_group_id()).await.unwrap();

	let list = u.get_group_invites(None).await.unwrap();

	assert_eq!(list.len(), 0);
}

#[tokio::test]
async fn test_16_invite_again_to_accept()
{
	let g = GROUP_0_TEST_STATE.get().unwrap().read().await;

	let u0 = USER_0_TEST_STATE.get().unwrap().read().await;
	let u = USER_1_TEST_STATE.get().unwrap().read().await;

	g.invite(u0.get_jwt().unwrap(), u.get_user_id(), None)
		.await
		.unwrap();
}

#[tokio::test]
async fn test_17_accept_the_invite()
{
	let u = USER_1_TEST_STATE.get().unwrap().read().await;

	let list = u.get_group_invites(None).await.unwrap();

	assert_eq!(list.len(), 1);

	u.accept_group_invite(&list[0].group_id).await.unwrap();
}

#[tokio::test]
async fn test_18_fetch_the_group_as_new_user()
{
	let u = USER_1_TEST_STATE.get().unwrap().read().await;

	let out = u.get_groups(None).await.unwrap();

	assert_eq!(out.len(), 1);

	let group = u.get_group(&out[0].group_id, None).await.unwrap();

	GROUP_1_TEST_STATE
		.get_or_init(|| async move { RwLock::new(GroupState(group)) })
		.await;
}

#[tokio::test]
async fn test_19_leave_the_group()
{
	let g = GROUP_1_TEST_STATE.get().unwrap().read().await;
	let u = USER_1_TEST_STATE.get().unwrap().read().await;

	g.leave(u.get_jwt().unwrap()).await.unwrap();

	let out = u.get_groups(None).await.unwrap();

	assert_eq!(out.len(), 0);
}

#[tokio::test]
async fn test_20_auto_invite_user()
{
	let g = GROUP_0_TEST_STATE.get().unwrap().read().await;
	let u0 = USER_0_TEST_STATE.get().unwrap().read().await;

	let u = USER_1_TEST_STATE.get().unwrap().read().await;

	g.invite_auto(u0.get_jwt().unwrap(), u.get_user_id(), None)
		.await
		.unwrap();

	//get the group in the list of the joined groups (because of auto invite)

	let out = u.get_groups(None).await.unwrap();

	assert_eq!(out.len(), 1);

	assert_eq!(g.get_group_id(), &out[0].group_id);

	let group = u.get_group(&out[0].group_id, None).await.unwrap();

	let mut g_state = GROUP_1_TEST_STATE.get().unwrap().write().await;

	g_state.0 = group;
}

//__________________________________________________________________________________________________
//join request

#[tokio::test]
async fn test_21_send_join_req()
{
	let u = USER_2_TEST_STATE.get().unwrap().read().await;

	let g = GROUP_0_TEST_STATE.get().unwrap().read().await;

	u.group_join_request(g.get_group_id()).await.unwrap();

	//get the sent join req

	let list = u.get_sent_join_req(None).await.unwrap();

	assert_eq!(list.len(), 1);

	assert_eq!(list[0].group_id, g.get_group_id());

	//2nd page

	let list = u.get_sent_join_req(list.get(0)).await.unwrap();

	assert_eq!(list.len(), 0);
}

#[tokio::test]
async fn test_22_get_join_req_in_group()
{
	let u = USER_2_TEST_STATE.get().unwrap().read().await;

	let g = GROUP_0_TEST_STATE.get().unwrap().read().await;
	let u0 = USER_0_TEST_STATE.get().unwrap().read().await;

	let list = g
		.get_join_requests(u0.get_jwt().unwrap(), None)
		.await
		.unwrap();

	assert_eq!(list.len(), 1);
	assert_eq!(list[0].user_id, u.get_user_id());

	//2nd page
	let list = g
		.get_join_requests(u0.get_jwt().unwrap(), list.get(0))
		.await
		.unwrap();

	assert_eq!(list.len(), 0);
}

#[tokio::test]
async fn test_23_not_reject_join_without_the_rights()
{
	let u = USER_2_TEST_STATE.get().unwrap().read().await;

	let g = GROUP_1_TEST_STATE.get().unwrap().read().await;
	let u0 = USER_1_TEST_STATE.get().unwrap().read().await;

	let err = g
		.reject_join_request(u0.get_jwt().unwrap(), u.get_user_id())
		.await;

	match err {
		Err(SentcError::Sdk(SdkLightError::GroupPermission)) => {},
		_ => panic!("should be error"),
	}
}

#[tokio::test]
async fn test_24_reject_join()
{
	let u = USER_2_TEST_STATE.get().unwrap().read().await;

	let g = GROUP_0_TEST_STATE.get().unwrap().read().await;
	let u0 = USER_0_TEST_STATE.get().unwrap().read().await;

	g.reject_join_request(u0.get_jwt().unwrap(), u.get_user_id())
		.await
		.unwrap();

	let list = g
		.get_join_requests(u0.get_jwt().unwrap(), None)
		.await
		.unwrap();

	assert_eq!(list.len(), 0);
}

#[tokio::test]
async fn test_25_send_join_again()
{
	let u = USER_2_TEST_STATE.get().unwrap().read().await;

	let g = GROUP_0_TEST_STATE.get().unwrap().read().await;

	u.group_join_request(g.get_group_id()).await.unwrap();
}

#[tokio::test]
async fn test_26_not_accept_without_rights()
{
	let u = USER_2_TEST_STATE.get().unwrap().read().await;

	let g = GROUP_1_TEST_STATE.get().unwrap().read().await;
	let u0 = USER_1_TEST_STATE.get().unwrap().read().await;

	let err = g
		.accept_join_request(u0.get_jwt().unwrap(), u.get_user_id(), None)
		.await;

	match err {
		Err(SentcError::Sdk(SdkLightError::GroupPermission)) => {},
		_ => panic!("should be error"),
	}
}

#[tokio::test]
async fn test_27_accept_join_req()
{
	let u = USER_2_TEST_STATE.get().unwrap().read().await;

	let g = GROUP_0_TEST_STATE.get().unwrap().read().await;
	let u0 = USER_0_TEST_STATE.get().unwrap().read().await;

	g.accept_join_request(u0.get_jwt().unwrap(), u.get_user_id(), None)
		.await
		.unwrap();
}

#[tokio::test]
async fn test_28_fetch_group()
{
	let u = USER_2_TEST_STATE.get().unwrap().read().await;

	let g = GROUP_0_TEST_STATE.get().unwrap().read().await;

	let group = u.get_group(g.get_group_id(), None).await.unwrap();

	GROUP_2_TEST_STATE
		.get_or_init(|| async { RwLock::new(GroupState(group)) })
		.await;
}

#[tokio::test]
async fn test_28_not_kick_without_rights()
{
	let u = USER_2_TEST_STATE.get().unwrap().read().await;

	let g = GROUP_1_TEST_STATE.get().unwrap().read().await;
	let u0 = USER_1_TEST_STATE.get().unwrap().read().await;

	let err = g.kick_user(u0.get_jwt().unwrap(), u.get_user_id()).await;

	match err {
		Err(SentcError::Sdk(SdkLightError::GroupPermission)) => {},
		_ => panic!("should be error"),
	}
}

#[tokio::test]
async fn test_29_increase_rank_for_user_1()
{
	let u = USER_1_TEST_STATE.get().unwrap().read().await;
	let u1 = USER_2_TEST_STATE.get().unwrap().read().await;
	let u0 = USER_0_TEST_STATE.get().unwrap().read().await;

	let g = GROUP_0_TEST_STATE.get().unwrap().read().await;

	g.update_rank(u0.get_jwt().unwrap(), u.get_user_id(), 1)
		.await
		.unwrap();

	g.update_rank(u0.get_jwt().unwrap(), u1.get_user_id(), 2)
		.await
		.unwrap();

	//update the locale structs
	let mut g = GROUP_1_TEST_STATE.get().unwrap().write().await;

	g.group_update_check(u.get_jwt().unwrap()).await.unwrap();

	let mut g = GROUP_2_TEST_STATE.get().unwrap().write().await;

	g.group_update_check(u1.get_jwt().unwrap()).await.unwrap();
}

#[tokio::test]
async fn test_30_not_kick_a_user_with_higher_rank()
{
	let u = USER_1_TEST_STATE.get().unwrap().read().await;

	let g = GROUP_2_TEST_STATE.get().unwrap().read().await;
	let u2 = USER_2_TEST_STATE.get().unwrap().read().await;

	let err = g.kick_user(u2.get_jwt().unwrap(), u.get_user_id()).await;

	match err {
		Err(SentcError::Sdk(SdkLightError::Util(sentc_crypto_light::sdk_utils::error::SdkUtilError::ServerErr(c, _)))) => {
			assert_eq!(c, 316);
		},
		_ => panic!("should be error"),
	}
}

#[tokio::test]
async fn test_31_kick_a_user()
{
	let u = USER_2_TEST_STATE.get().unwrap().read().await;
	let g = GROUP_1_TEST_STATE.get().unwrap().read().await;
	let u1 = USER_1_TEST_STATE.get().unwrap().read().await;

	g.kick_user(u1.get_jwt().unwrap(), u.get_user_id())
		.await
		.unwrap();
}

#[tokio::test]
async fn test_32_not_get_the_group_after_kick()
{
	let u = USER_2_TEST_STATE.get().unwrap().read().await;
	let g = GROUP_0_TEST_STATE.get().unwrap().read().await;

	let err = u.get_group(g.get_group_id(), None).await;

	match err {
		Err(SentcError::Sdk(SdkLightError::Util(sentc_crypto_light::sdk_utils::error::SdkUtilError::ServerErr(c, _)))) => {
			assert_eq!(c, 310);
		},
		_ => panic!("should be error"),
	}
}

//__________________________________________________________________________________________________
//child group

#[tokio::test]
async fn test_33_create_a_child_group()
{
	let g = GROUP_0_TEST_STATE.get().unwrap().read().await;
	let u0 = USER_0_TEST_STATE.get().unwrap().read().await;

	let id = g.create_child_group(u0.get_jwt().unwrap()).await.unwrap();

	let list = g.get_children(u0.get_jwt().unwrap(), None).await.unwrap();

	assert_eq!(list.len(), 1);
	assert_eq!(list[0].group_id, id);

	let page_two = g
		.get_children(u0.get_jwt().unwrap(), Some(list.get(0).unwrap()))
		.await
		.unwrap();

	assert_eq!(page_two.len(), 0);

	let child_group = g.get_child_group(&id, u0.get_jwt().unwrap()).await.unwrap();

	CHILD_GROUP
		.get_or_init(|| async move { RwLock::new(GroupState(child_group)) })
		.await;
}

#[tokio::test]
async fn test_34_get_child_group_as_member_of_the_parent_group()
{
	let cg = CHILD_GROUP.get().unwrap().read().await;

	let g = GROUP_1_TEST_STATE.get().unwrap().read().await;
	let u1 = USER_1_TEST_STATE.get().unwrap().read().await;

	let _child_group = g
		.get_child_group(cg.get_group_id(), u1.get_jwt().unwrap())
		.await
		.unwrap();
}

#[tokio::test]
async fn test_35_invite_a_user_to_the_child_group()
{
	let cg = CHILD_GROUP.get().unwrap().read().await;
	let u0 = USER_0_TEST_STATE.get().unwrap().read().await;

	let u = USER_2_TEST_STATE.get().unwrap().read().await;

	cg.invite_auto(u0.get_jwt().unwrap(), u.get_user_id(), Some(2))
		.await
		.unwrap();

	let child_group = u.get_group(cg.get_group_id(), None).await.unwrap();

	assert_eq!(child_group.get_rank(), 2);

	CHILD_GROUP_USER_2
		.get_or_init(|| async move { RwLock::new(GroupState(child_group)) })
		.await;
}

#[tokio::test]
async fn test_36_get_child_group_by_direct_access()
{
	//access the child group by user not by parent group -> the parent should be loaded too

	//auto invite the user to the parent but do not fetch the parent keys!
	let g = GROUP_0_TEST_STATE.get().unwrap().read().await;
	let u0 = USER_0_TEST_STATE.get().unwrap().read().await;

	let cg = CHILD_GROUP.get().unwrap().read().await;

	let u = USER_3_TEST_STATE.get().unwrap().read().await;

	g.invite_auto(u0.get_jwt().unwrap(), u.get_user_id(), None)
		.await
		.unwrap();

	let g3 = u.get_group(g.get_group_id(), None).await.unwrap();

	let child_group = g3
		.get_child_group(cg.get_group_id(), u.get_jwt().unwrap())
		.await
		.unwrap();

	CHILD_GROUP_USER_3
		.get_or_init(|| async move { RwLock::new(GroupState(child_group)) })
		.await;
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

	let u = USER_2_TEST_STATE.get().unwrap().read().await;
	u.delete(PW, None, None).await.unwrap();

	let u = USER_3_TEST_STATE.get().unwrap().read().await;
	u.delete(PW, None, None).await.unwrap();
}
