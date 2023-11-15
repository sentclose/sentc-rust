use std::ops::Deref;
use std::sync::Arc;
use std::time::Duration;

use sentc::cache::l_one::L1Cache;
use sentc::error::SentcError;
use sentc::group::Group;
use sentc::sentc::Sentc;
use sentc::user::User;
use sentc_crypto::SdkError;
use tokio::sync::{OnceCell, RwLock};
use tokio::time::sleep;

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

struct EncryptedString(String);

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

static SENTC: OnceCell<Sentc> = OnceCell::const_new();

static ENCRYPTED_STRING: OnceCell<RwLock<EncryptedString>> = OnceCell::const_new();
static ENCRYPTED_STRING_AFTER_KR: OnceCell<RwLock<EncryptedString>> = OnceCell::const_new();
static ENCRYPTED_STRING_WITH_SIGN: OnceCell<RwLock<EncryptedString>> = OnceCell::const_new();

const USERNAME0: &str = "test0";
const USERNAME1: &str = "test1";
const USERNAME2: &str = "test2";
const USERNAME3: &str = "test3";
const PW: &str = "12345";

const STRING_TO_ENCRYPT: &str = "hello there £ Я a a 👍";

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

	sentc.register(USERNAME3, PW).await.unwrap();
	let user = sentc.login_forced(USERNAME3, PW).await.unwrap();
	USER_3_TEST_STATE
		.get_or_init(|| async move { RwLock::new(UserState(user)) })
		.await;

	SENTC.get_or_init(|| async move { sentc }).await;
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
async fn test_11_get_all_groups_to_user()
{
	let u = USER_0_TEST_STATE.get().unwrap().read().await;
	let mut uw = u.write().await;

	let out = uw
		.get_groups(SENTC.get().unwrap().get_cache(), None)
		.await
		.unwrap();

	assert_eq!(out.len(), 1);

	let out = uw
		.get_groups(SENTC.get().unwrap().get_cache(), Some(&out[0]))
		.await
		.unwrap();

	assert_eq!(out.len(), 0);
}

#[tokio::test]
async fn test_12_not_get_group_as_non_member()
{
	let u = USER_1_TEST_STATE.get().unwrap().read().await;
	let mut uw = u.write().await;

	let g = GROUP_0_TEST_STATE.get().unwrap().read().await;
	let g_id = g.read().await;
	let g_id = g_id.get_group_id();

	let err = uw
		.get_group(g_id, None, SENTC.get().unwrap().get_cache())
		.await;

	match err {
		Err(SentcError::Sdk(SdkError::Util(sentc_crypto::sdk_utils::error::SdkUtilError::ServerErr(c, _)))) => {
			assert_eq!(c, 310);
		},
		_ => panic!("should be server error"),
	}
}

#[tokio::test]
async fn test_13_invite_2nd_user()
{
	let g = GROUP_0_TEST_STATE.get().unwrap().read().await;
	let g = g.read().await;

	let u = USER_1_TEST_STATE.get().unwrap().read().await;
	let uw = u.read().await;

	g.invite(uw.get_user_id(), None, SENTC.get().unwrap().get_cache())
		.await
		.unwrap();
}

#[tokio::test]
async fn test_14_get_invite_for_2nd_user()
{
	let g = GROUP_0_TEST_STATE.get().unwrap().read().await;
	let g = g.read().await;

	let u = USER_1_TEST_STATE.get().unwrap().read().await;
	let mut uw = u.write().await;

	let list = uw
		.get_group_invites(SENTC.get().unwrap().get_cache(), None)
		.await
		.unwrap();

	assert_eq!(list.len(), 1);

	assert_eq!(list[0].group_id, g.get_group_id());

	//2nd page

	let list = uw
		.get_group_invites(SENTC.get().unwrap().get_cache(), list.get(0))
		.await
		.unwrap();

	assert_eq!(list.len(), 0);
}

#[tokio::test]
async fn test_15_reject_invite()
{
	let g = GROUP_0_TEST_STATE.get().unwrap().read().await;
	let g = g.read().await;

	let u = USER_1_TEST_STATE.get().unwrap().read().await;
	let mut uw = u.write().await;

	uw.reject_group_invite(g.get_group_id(), SENTC.get().unwrap().get_cache())
		.await
		.unwrap();

	let list = uw
		.get_group_invites(SENTC.get().unwrap().get_cache(), None)
		.await
		.unwrap();

	assert_eq!(list.len(), 0);
}

#[tokio::test]
async fn test_16_invite_again_to_accept()
{
	let g = GROUP_0_TEST_STATE.get().unwrap().read().await;
	let g = g.read().await;

	let u = USER_1_TEST_STATE.get().unwrap().read().await;
	let uw = u.read().await;

	g.invite(uw.get_user_id(), None, SENTC.get().unwrap().get_cache())
		.await
		.unwrap();
}

#[tokio::test]
async fn test_17_accept_the_invite()
{
	let u = USER_1_TEST_STATE.get().unwrap().read().await;
	let mut uw = u.write().await;

	let list = uw
		.get_group_invites(SENTC.get().unwrap().get_cache(), None)
		.await
		.unwrap();

	assert_eq!(list.len(), 1);

	uw.accept_group_invite(&list[0].group_id, SENTC.get().unwrap().get_cache())
		.await
		.unwrap();
}

#[tokio::test]
async fn test_18_fetch_the_group_as_new_user()
{
	let u = USER_1_TEST_STATE.get().unwrap().read().await;
	let mut uw = u.write().await;

	let out = uw
		.get_groups(SENTC.get().unwrap().get_cache(), None)
		.await
		.unwrap();

	assert_eq!(out.len(), 1);

	let group = uw
		.get_group(&out[0].group_id, None, SENTC.get().unwrap().get_cache())
		.await
		.unwrap();

	GROUP_1_TEST_STATE
		.get_or_init(|| async move { RwLock::new(GroupState(group)) })
		.await;
}

#[tokio::test]
async fn test_19_leave_the_group()
{
	let g = GROUP_1_TEST_STATE.get().unwrap().read().await;
	let g = g.read().await;

	g.leave(SENTC.get().unwrap().get_cache()).await.unwrap();

	let u = USER_1_TEST_STATE.get().unwrap().read().await;
	let mut uw = u.write().await;

	let out = uw
		.get_groups(SENTC.get().unwrap().get_cache(), None)
		.await
		.unwrap();

	assert_eq!(out.len(), 0);
}

#[tokio::test]
async fn test_20_auto_invite_user()
{
	let g = GROUP_0_TEST_STATE.get().unwrap().read().await;
	let g = g.read().await;

	let u = USER_1_TEST_STATE.get().unwrap().read().await;
	let mut uw = u.write().await;

	g.invite_auto(uw.get_user_id(), None, SENTC.get().unwrap().get_cache())
		.await
		.unwrap();

	//get the group in the list of the joined groups (because of auto invite)

	let out = uw
		.get_groups(SENTC.get().unwrap().get_cache(), None)
		.await
		.unwrap();

	assert_eq!(out.len(), 1);

	assert_eq!(g.get_group_id(), &out[0].group_id);

	let group = uw
		.get_group(&out[0].group_id, None, SENTC.get().unwrap().get_cache())
		.await
		.unwrap();

	let mut g_state = GROUP_1_TEST_STATE.get().unwrap().write().await;

	g_state.0 = group;
}

//encryption

#[tokio::test]
async fn test_21_encrypt_string_for_the_group()
{
	let g = GROUP_0_TEST_STATE.get().unwrap().read().await;
	let mut g = g.write().await;

	let encrypted_string = g
		.encrypt_string(STRING_TO_ENCRYPT, false, SENTC.get().unwrap().get_cache())
		.await
		.unwrap();

	//decrypt the string with the same group
	let decrypted = g
		.decrypt_string(&encrypted_string, false, None, SENTC.get().unwrap().get_cache())
		.await
		.unwrap();

	assert_eq!(decrypted, STRING_TO_ENCRYPT);

	//store the value for later
	ENCRYPTED_STRING
		.get_or_init(|| async { RwLock::new(EncryptedString(encrypted_string)) })
		.await;
}

#[tokio::test]
async fn test_22_start_key_rotation()
{
	let g = GROUP_0_TEST_STATE.get().unwrap().read().await;
	let mut g = g.write().await;

	let old_newest_key = g.get_newest_key().unwrap().group_key.key_id.clone();

	g.key_rotation(false, SENTC.get().unwrap().get_cache())
		.await
		.unwrap();

	let new_newest_key = g.get_newest_key().unwrap().group_key.key_id.clone();

	assert_ne!(old_newest_key, new_newest_key);

	//get the group public key
	let gp = SENTC
		.get()
		.unwrap()
		.get_group_public_key(g.get_group_id())
		.await
		.unwrap();

	assert_eq!(gp.public_key_id, new_newest_key);

	//"wait" until the server is done with the rotation before moving on
	sleep(Duration::from_millis(300)).await;
}

#[tokio::test]
async fn test_23_encrypt_after_key_rotation()
{
	let g = GROUP_0_TEST_STATE.get().unwrap().read().await;
	let g = g.read().await;

	let encrypted_string = g
		.encrypt_string(STRING_TO_ENCRYPT, false, SENTC.get().unwrap().get_cache())
		.await
		.unwrap();

	//store the value for later
	ENCRYPTED_STRING_AFTER_KR
		.get_or_init(|| async { RwLock::new(EncryptedString(encrypted_string)) })
		.await;
}

#[tokio::test]
async fn test_24_not_decrypt_before_finish_key_rotation()
{
	let g = GROUP_1_TEST_STATE.get().unwrap().read().await;
	let mut g = g.write().await;

	let string = ENCRYPTED_STRING_AFTER_KR.get().unwrap().read().await;

	let err = g
		.decrypt_string(&string.0, false, None, SENTC.get().unwrap().get_cache())
		.await;

	match err {
		Err(SentcError::Sdk(SdkError::Util(sentc_crypto::sdk_utils::error::SdkUtilError::ServerErr(c, _)))) => {
			assert_eq!(c, 304);
		},
		_ => panic!("should be server error"),
	}
}

#[tokio::test]
async fn test_25_finish_key_rotation()
{
	let g = GROUP_1_TEST_STATE.get().unwrap().read().await;
	let mut g = g.write().await;

	let old_newest_key = g.get_newest_key().unwrap().group_key.key_id.clone();

	g.finish_key_rotation(false, SENTC.get().unwrap().get_cache())
		.await
		.unwrap();

	let new_newest_key = g.get_newest_key().unwrap().group_key.key_id.clone();

	assert_ne!(old_newest_key, new_newest_key);
}

#[tokio::test]
async fn test_26_decrypt_both_strings()
{
	let g = GROUP_1_TEST_STATE.get().unwrap().read().await;
	let mut g = g.write().await;

	let string = ENCRYPTED_STRING.get().unwrap().read().await;

	let decrypted = g
		.decrypt_string(&string.0, false, None, SENTC.get().unwrap().get_cache())
		.await
		.unwrap();

	assert_eq!(decrypted, STRING_TO_ENCRYPT);

	let string = ENCRYPTED_STRING_AFTER_KR.get().unwrap().read().await;

	let decrypted = g
		.decrypt_string(&string.0, false, None, SENTC.get().unwrap().get_cache())
		.await
		.unwrap();

	assert_eq!(decrypted, STRING_TO_ENCRYPT);
}

#[tokio::test]
async fn test_27_encrypt_with_sign()
{
	let u = USER_0_TEST_STATE.get().unwrap().read().await;
	let u_r = u.0.read().await;

	let u_id = u_r.get_user_id().to_string();

	drop(u_r);

	let g = GROUP_0_TEST_STATE.get().unwrap().read().await;
	let mut g = g.write().await;

	let encrypted_string = g
		.encrypt_string(STRING_TO_ENCRYPT, true, SENTC.get().unwrap().get_cache())
		.await
		.unwrap();

	//should decrypt it without verify
	let decrypted = g
		.decrypt_string(&encrypted_string, false, None, SENTC.get().unwrap().get_cache())
		.await
		.unwrap();

	assert_eq!(decrypted, STRING_TO_ENCRYPT);

	//now decrypt with verify
	let decrypted = g
		.decrypt_string(&encrypted_string, true, Some(&u_id), SENTC.get().unwrap().get_cache())
		.await
		.unwrap();

	assert_eq!(decrypted, STRING_TO_ENCRYPT);

	//store the value for later
	ENCRYPTED_STRING_WITH_SIGN
		.get_or_init(|| async { RwLock::new(EncryptedString(encrypted_string)) })
		.await;
}

#[tokio::test]
async fn test_28_decrypt_with_sign_for_other_user()
{
	let u = USER_0_TEST_STATE.get().unwrap().read().await;
	let u_r = u.0.read().await;

	let u_id = u_r.get_user_id().to_string();

	drop(u_r);

	let g = GROUP_1_TEST_STATE.get().unwrap().read().await;
	let mut g = g.write().await;

	let encrypt = ENCRYPTED_STRING_WITH_SIGN.get().unwrap().read().await;

	//should decrypt it without verify
	let decrypted = g
		.decrypt_string(&encrypt.0, false, None, SENTC.get().unwrap().get_cache())
		.await
		.unwrap();

	assert_eq!(decrypted, STRING_TO_ENCRYPT);

	//now decrypt with verify
	let decrypted = g
		.decrypt_string(&encrypt.0, true, Some(&u_id), SENTC.get().unwrap().get_cache())
		.await
		.unwrap();

	assert_eq!(decrypted, STRING_TO_ENCRYPT);
}

//__________________________________________________________________________________________________
//join request

#[tokio::test]
async fn test_29_send_join_req()
{
	let u = USER_2_TEST_STATE.get().unwrap().read().await;
	let mut u_r = u.0.write().await;

	let g = GROUP_0_TEST_STATE.get().unwrap().read().await;
	let g = g.read().await;

	u_r.group_join_request(g.get_group_id(), SENTC.get().unwrap().get_cache())
		.await
		.unwrap();

	//get the sent join req

	let list = u_r
		.get_sent_join_req(SENTC.get().unwrap().get_cache(), None)
		.await
		.unwrap();

	assert_eq!(list.len(), 1);

	assert_eq!(list[0].group_id, g.get_group_id());

	//2nd page

	let list = u_r
		.get_sent_join_req(SENTC.get().unwrap().get_cache(), list.get(0))
		.await
		.unwrap();

	assert_eq!(list.len(), 0);
}

#[tokio::test]
async fn test_30_get_join_req_in_group()
{
	let u = USER_2_TEST_STATE.get().unwrap().read().await;
	let u_r = u.0.read().await;

	let g = GROUP_0_TEST_STATE.get().unwrap().read().await;
	let g = g.read().await;

	let list = g
		.get_join_requests(None, SENTC.get().unwrap().get_cache())
		.await
		.unwrap();

	assert_eq!(list.len(), 1);
	assert_eq!(list[0].user_id, u_r.get_user_id());

	//2nd page
	let list = g
		.get_join_requests(list.get(0), SENTC.get().unwrap().get_cache())
		.await
		.unwrap();

	assert_eq!(list.len(), 0);
}

#[tokio::test]
async fn test_31_not_reject_join_without_the_rights()
{
	let u = USER_2_TEST_STATE.get().unwrap().read().await;
	let u_r = u.0.read().await;

	let g = GROUP_1_TEST_STATE.get().unwrap().read().await;
	let g = g.read().await;

	let err = g
		.reject_join_request(u_r.get_user_id(), SENTC.get().unwrap().get_cache())
		.await;

	match err {
		Err(SentcError::Sdk(SdkError::GroupPermission)) => {},
		_ => panic!("should be error"),
	}
}

#[tokio::test]
async fn test_31_reject_join()
{
	let u = USER_2_TEST_STATE.get().unwrap().read().await;
	let u_r = u.0.read().await;

	let g = GROUP_0_TEST_STATE.get().unwrap().read().await;
	let g = g.read().await;

	g.reject_join_request(u_r.get_user_id(), SENTC.get().unwrap().get_cache())
		.await
		.unwrap();

	let list = g
		.get_join_requests(None, SENTC.get().unwrap().get_cache())
		.await
		.unwrap();

	assert_eq!(list.len(), 0);
}

#[tokio::test]
async fn test_32_send_join_again()
{
	let u = USER_2_TEST_STATE.get().unwrap().read().await;
	let mut u_r = u.0.write().await;

	let g = GROUP_0_TEST_STATE.get().unwrap().read().await;
	let g = g.read().await;

	u_r.group_join_request(g.get_group_id(), SENTC.get().unwrap().get_cache())
		.await
		.unwrap();
}

#[tokio::test]
async fn test_33_not_accept_without_rights()
{
	let u = USER_2_TEST_STATE.get().unwrap().read().await;
	let u_r = u.0.read().await;

	let g = GROUP_1_TEST_STATE.get().unwrap().read().await;
	let g = g.read().await;

	let err = g
		.accept_join_request(u_r.get_user_id(), 0, None, SENTC.get().unwrap().get_cache())
		.await;

	match err {
		Err(SentcError::Sdk(SdkError::GroupPermission)) => {},
		_ => panic!("should be error"),
	}
}

#[tokio::test]
async fn test_34_accept_join_req()
{
	let u = USER_2_TEST_STATE.get().unwrap().read().await;
	let u_r = u.0.read().await;

	let g = GROUP_0_TEST_STATE.get().unwrap().read().await;
	let g = g.read().await;

	g.accept_join_request(u_r.get_user_id(), 0, None, SENTC.get().unwrap().get_cache())
		.await
		.unwrap();
}

#[tokio::test]
async fn test_35_fetch_group()
{
	let u = USER_2_TEST_STATE.get().unwrap().read().await;
	let mut uw = u.0.write().await;

	let g = GROUP_0_TEST_STATE.get().unwrap().read().await;
	let g = g.read().await;

	let group = uw
		.get_group(g.get_group_id(), None, SENTC.get().unwrap().get_cache())
		.await
		.unwrap();

	GROUP_2_TEST_STATE
		.get_or_init(|| async { RwLock::new(GroupState(group)) })
		.await;
}

#[tokio::test]
async fn test_36_decrypt_both_strings()
{
	//new user should got all keys after joining

	let g = GROUP_2_TEST_STATE.get().unwrap().read().await;
	let mut g = g.write().await;

	let string = ENCRYPTED_STRING.get().unwrap().read().await;

	let decrypted = g
		.decrypt_string(&string.0, false, None, SENTC.get().unwrap().get_cache())
		.await
		.unwrap();

	assert_eq!(decrypted, STRING_TO_ENCRYPT);

	let string = ENCRYPTED_STRING_AFTER_KR.get().unwrap().read().await;

	let decrypted = g
		.decrypt_string(&string.0, false, None, SENTC.get().unwrap().get_cache())
		.await
		.unwrap();

	assert_eq!(decrypted, STRING_TO_ENCRYPT);
}

#[tokio::test]
async fn test_37_not_kick_without_rights()
{
	let u = USER_2_TEST_STATE.get().unwrap().read().await;
	let u_r = u.read().await;

	let g = GROUP_1_TEST_STATE.get().unwrap().read().await;
	let g = g.read().await;

	let err = g
		.kick_user(u_r.get_user_id(), SENTC.get().unwrap().get_cache())
		.await;

	match err {
		Err(SentcError::Sdk(SdkError::GroupPermission)) => {},
		_ => panic!("should be error"),
	}
}

#[tokio::test]
async fn test_38_increase_rank_for_user_1()
{
	let u = USER_1_TEST_STATE.get().unwrap().read().await;
	let u_r = u.read().await;

	let u1 = USER_2_TEST_STATE.get().unwrap().read().await;
	let u1_r = u1.read().await;

	let g = GROUP_0_TEST_STATE.get().unwrap().read().await;
	let g = g.read().await;

	g.update_rank(u_r.get_user_id(), 1, SENTC.get().unwrap().get_cache())
		.await
		.unwrap();

	g.update_rank(u1_r.get_user_id(), 2, SENTC.get().unwrap().get_cache())
		.await
		.unwrap();

	drop(u_r);
	drop(u1_r);

	//update the locale structs
	let g = GROUP_1_TEST_STATE.get().unwrap().read().await;
	let mut g = g.write().await;

	g.group_update_check(SENTC.get().unwrap().get_cache())
		.await
		.unwrap();

	let g = GROUP_2_TEST_STATE.get().unwrap().read().await;
	let mut g = g.write().await;

	g.group_update_check(SENTC.get().unwrap().get_cache())
		.await
		.unwrap();
}

#[tokio::test]
async fn test_39_not_kick_a_user_with_higher_rank()
{
	let u = USER_1_TEST_STATE.get().unwrap().read().await;
	let u_r = u.read().await;

	let g = GROUP_2_TEST_STATE.get().unwrap().read().await;
	let g = g.read().await;

	let err = g
		.kick_user(u_r.get_user_id(), SENTC.get().unwrap().get_cache())
		.await;

	match err {
		Err(SentcError::Sdk(SdkError::Util(sentc_crypto::sdk_utils::error::SdkUtilError::ServerErr(c, _)))) => {
			assert_eq!(c, 316);
		},
		_ => panic!("should be error"),
	}
}

#[tokio::test]
async fn test_40_kick_a_user()
{
	let u = USER_2_TEST_STATE.get().unwrap().read().await;
	let u_r = u.read().await;

	let g = GROUP_1_TEST_STATE.get().unwrap().read().await;
	let g = g.read().await;

	g.kick_user(u_r.get_user_id(), SENTC.get().unwrap().get_cache())
		.await
		.unwrap();
}

#[tokio::test]
async fn test_41_not_get_the_group_after_kick()
{
	let u = USER_2_TEST_STATE.get().unwrap().read().await;
	let mut u_w = u.write().await;

	let g = GROUP_0_TEST_STATE.get().unwrap().read().await;
	let g = g.read().await;

	//use an empty cache here to not load the group from the cache
	let err = u_w.get_group(g.get_group_id(), None, &L1Cache::new()).await;

	match err {
		Err(SentcError::Sdk(SdkError::Util(sentc_crypto::sdk_utils::error::SdkUtilError::ServerErr(c, _)))) => {
			assert_eq!(c, 310);
		},
		_ => panic!("should be error"),
	}
}

//__________________________________________________________________________________________________
//child group

#[tokio::test]
async fn test_50_create_a_child_group()
{
	let g = GROUP_0_TEST_STATE.get().unwrap().read().await;
	let g = g.read().await;

	let id = g
		.create_child_group(SENTC.get().unwrap().get_cache())
		.await
		.unwrap();

	let list = g
		.get_children(None, SENTC.get().unwrap().get_cache())
		.await
		.unwrap();

	assert_eq!(list.len(), 1);
	assert_eq!(list[0].group_id, id);

	let page_two = g
		.get_children(Some(list.get(0).unwrap()), SENTC.get().unwrap().get_cache())
		.await
		.unwrap();

	assert_eq!(page_two.len(), 0);

	let child_group = g
		.get_child_group(&id, SENTC.get().unwrap().get_cache())
		.await
		.unwrap();

	CHILD_GROUP
		.get_or_init(|| async move { RwLock::new(GroupState(child_group)) })
		.await;
}

#[tokio::test]
async fn test_51_get_child_group_as_member_of_the_parent_group()
{
	let cg = CHILD_GROUP.get().unwrap().read().await;
	let cg = cg.read().await;

	let g = GROUP_1_TEST_STATE.get().unwrap().read().await;
	let g = g.read().await;

	let child_group = g
		.get_child_group(cg.get_group_id(), SENTC.get().unwrap().get_cache())
		.await
		.unwrap();

	let child_group = child_group.read().await;

	assert_eq!(
		child_group.get_newest_key().unwrap().group_key.key_id,
		cg.get_newest_key().unwrap().group_key.key_id
	);
}

#[tokio::test]
async fn test_52_invite_a_user_to_the_child_group()
{
	let cg = CHILD_GROUP.get().unwrap().read().await;
	let cg = cg.read().await;

	let u = USER_2_TEST_STATE.get().unwrap().read().await;
	let mut u_r = u.write().await;

	cg.invite_auto(u_r.get_user_id(), Some(2), SENTC.get().unwrap().get_cache())
		.await
		.unwrap();

	let child_group = u_r
		.get_group(cg.get_group_id(), None, SENTC.get().unwrap().get_cache())
		.await
		.unwrap();

	let child_group1 = child_group.read().await;

	assert_eq!(child_group1.get_rank(), 2);

	drop(child_group1);

	CHILD_GROUP_USER_2
		.get_or_init(|| async move { RwLock::new(GroupState(child_group)) })
		.await;
}

#[tokio::test]
async fn test_53_re_invite_user()
{
	let cg = CHILD_GROUP.get().unwrap().read().await;
	let cg = cg.read().await;

	let u = USER_2_TEST_STATE.get().unwrap().read().await;
	let u_r = u.read().await;

	cg.re_invite_user(u_r.get_user_id(), SENTC.get().unwrap().get_cache())
		.await
		.unwrap();
}

#[tokio::test]
async fn test_54_get_child_group_by_direct_access()
{
	//access the child group by user not by parent group -> the parent should be loaded too

	//auto invite the user to the parent but do not fetch the parent keys!
	let g = GROUP_0_TEST_STATE.get().unwrap().read().await;
	let g = g.read().await;

	let cg = CHILD_GROUP.get().unwrap().read().await;
	let cg = cg.read().await;

	let u = USER_3_TEST_STATE.get().unwrap().read().await;
	let mut u_r = u.write().await;

	g.invite_auto(u_r.get_user_id(), None, SENTC.get().unwrap().get_cache())
		.await
		.unwrap();

	//this should work because the parent is fetched before the child is fetched
	let child_group = u_r
		.get_group(cg.get_group_id(), None, SENTC.get().unwrap().get_cache())
		.await
		.unwrap();

	let child_group1 = child_group.read().await;

	assert_eq!(
		child_group1.get_newest_key().unwrap().group_key.key_id,
		cg.get_newest_key().unwrap().group_key.key_id
	);

	drop(child_group1);

	CHILD_GROUP_USER_3
		.get_or_init(|| async move { RwLock::new(GroupState(child_group)) })
		.await;
}

#[tokio::test]
async fn test_55_encrypt_in_child_group()
{
	let cg = CHILD_GROUP.get().unwrap().read().await;
	let cg = cg.read().await;

	let g = GROUP_1_TEST_STATE.get().unwrap().read().await;
	let g = g.read().await;

	let g1 = CHILD_GROUP_USER_2.get().unwrap().read().await;
	let mut g1 = g1.write().await;

	let g2 = CHILD_GROUP_USER_3.get().unwrap().read().await;
	let mut g2 = g2.write().await;

	let child_1 = g
		.get_child_group(cg.get_group_id(), SENTC.get().unwrap().get_cache())
		.await
		.unwrap();
	let mut child_1 = child_1.write().await;

	let encrypted = cg
		.encrypt_string(STRING_TO_ENCRYPT, false, SENTC.get().unwrap().get_cache())
		.await
		.unwrap();

	let decrypted_1 = child_1
		.decrypt_string(&encrypted, false, None, SENTC.get().unwrap().get_cache())
		.await
		.unwrap();

	let decrypt_2 = g1
		.decrypt_string(&encrypted, false, None, SENTC.get().unwrap().get_cache())
		.await
		.unwrap();

	let decrypt_3 = g2
		.decrypt_string(&encrypted, false, None, SENTC.get().unwrap().get_cache())
		.await
		.unwrap();

	assert_eq!(decrypted_1, STRING_TO_ENCRYPT);
	assert_eq!(decrypt_2, STRING_TO_ENCRYPT);
	assert_eq!(decrypt_3, STRING_TO_ENCRYPT);
}

#[tokio::test]
async fn test_56_key_rotation_in_child_group()
{
	let cg = CHILD_GROUP.get().unwrap().read().await;
	let mut cg = cg.write().await;

	let old_key = cg.get_newest_key().unwrap().group_key.key_id.clone();

	cg.key_rotation(false, SENTC.get().unwrap().get_cache())
		.await
		.unwrap();

	let new_key = cg.get_newest_key().unwrap().group_key.key_id.clone();

	assert_ne!(old_key, new_key);

	//finish the key rotation as direct user

	sleep(Duration::from_millis(300)).await;

	let cg = CHILD_GROUP_USER_2.get().unwrap().read().await;
	let mut cg = cg.write().await;

	let old_key1 = cg.get_newest_key().unwrap().group_key.key_id.clone();

	assert_eq!(old_key1, old_key);

	cg.finish_key_rotation(false, SENTC.get().unwrap().get_cache())
		.await
		.unwrap();

	let new_key1 = cg.get_newest_key().unwrap().group_key.key_id.clone();

	assert_ne!(old_key1, new_key1);

	assert_eq!(new_key1, new_key);
}

#[tokio::test]
async fn test_57_no_error_for_finishing_an_already_finished_rotation()
{
	let cg = CHILD_GROUP_USER_3.get().unwrap().read().await;
	let mut cg = cg.write().await;

	cg.finish_key_rotation(false, SENTC.get().unwrap().get_cache())
		.await
		.unwrap();
}

#[tokio::test]
async fn test_58_encrypt_with_new_key()
{
	let cg = CHILD_GROUP.get().unwrap().read().await;
	let cg = cg.read().await;

	let g = GROUP_1_TEST_STATE.get().unwrap().read().await;
	let g = g.read().await;

	let g1 = CHILD_GROUP_USER_2.get().unwrap().read().await;
	let mut g1 = g1.write().await;

	let g2 = CHILD_GROUP_USER_3.get().unwrap().read().await;
	let mut g2 = g2.write().await;

	let child_1 = g
		.get_child_group(cg.get_group_id(), SENTC.get().unwrap().get_cache())
		.await
		.unwrap();
	let mut child_1 = child_1.write().await;

	let encrypted = cg
		.encrypt_string(STRING_TO_ENCRYPT, false, SENTC.get().unwrap().get_cache())
		.await
		.unwrap();

	let decrypted_1 = child_1
		.decrypt_string(&encrypted, false, None, SENTC.get().unwrap().get_cache())
		.await
		.unwrap();

	let decrypt_2 = g1
		.decrypt_string(&encrypted, false, None, SENTC.get().unwrap().get_cache())
		.await
		.unwrap();

	let decrypt_3 = g2
		.decrypt_string(&encrypted, false, None, SENTC.get().unwrap().get_cache())
		.await
		.unwrap();

	assert_eq!(decrypted_1, STRING_TO_ENCRYPT);
	assert_eq!(decrypt_2, STRING_TO_ENCRYPT);
	assert_eq!(decrypt_3, STRING_TO_ENCRYPT);
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

	let u = USER_2_TEST_STATE.get().unwrap().read().await;
	let ur = u.read().await;
	ur.delete(PW, None, None, SENTC.get().unwrap().get_cache())
		.await
		.unwrap();

	let u = USER_3_TEST_STATE.get().unwrap().read().await;
	let ur = u.read().await;
	ur.delete(PW, None, None, SENTC.get().unwrap().get_cache())
		.await
		.unwrap();
}
