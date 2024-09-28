use std::ops::{Deref, DerefMut};
use std::time::Duration;

use sentc::error::SentcError;
use sentc::group::net::{GroupFetchResult, GroupFinishKeyRotation, GroupKeyFetchResult};
use sentc::split_head_and_encrypted_string;
use sentc_crypto::SdkError;
use tokio::sync::{OnceCell, RwLock};
use tokio::time::sleep;

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

impl DerefMut for GroupState
{
	fn deref_mut(&mut self) -> &mut Self::Target
	{
		&mut self.0
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

	TestUser::register(
		"http://127.0.0.1:3002".into(),
		"5zMb6zs3dEM62n+FxjBilFPp+j9e7YUFA+7pi6Hi",
		USERNAME2,
		PW,
	)
	.await
	.unwrap();
	let user = TestUser::login_forced(
		"http://127.0.0.1:3002".into(),
		"5zMb6zs3dEM62n+FxjBilFPp+j9e7YUFA+7pi6Hi",
		USERNAME2,
		PW,
	)
	.await
	.unwrap();
	USER_2_TEST_STATE
		.get_or_init(|| async move { RwLock::new(UserState(user)) })
		.await;

	TestUser::register(
		"http://127.0.0.1:3002".into(),
		"5zMb6zs3dEM62n+FxjBilFPp+j9e7YUFA+7pi6Hi",
		USERNAME3,
		PW,
	)
	.await
	.unwrap();
	let user = TestUser::login_forced(
		"http://127.0.0.1:3002".into(),
		"5zMb6zs3dEM62n+FxjBilFPp+j9e7YUFA+7pi6Hi",
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

	let (data, fetch_res) = u.prepare_get_group(&group_id, None).await.unwrap();

	assert!(matches!(fetch_res, GroupFetchResult::Ok));

	let group = u.done_get_group(data, None).unwrap();

	assert_eq!(group_id, group.get_group_id());

	GROUP_0_TEST_STATE
		.get_or_init(|| async move { RwLock::new(GroupState(group)) })
		.await;
}

#[tokio::test]
async fn test_10_x_export_group()
{
	let u = USER_0_TEST_STATE.get().unwrap().read().await;

	let g = GROUP_0_TEST_STATE.get().unwrap().read().await;
	let group_id = g.get_group_id();

	let (data, fetch_res) = u.prepare_get_group(&group_id, None).await.unwrap();

	assert!(matches!(fetch_res, GroupFetchResult::Ok));

	let group = u.done_get_group(data, None).unwrap();

	let group_str = group.to_string().unwrap();

	let _group: TestGroup = group_str.parse().unwrap();

	//now test with ref
	let group_str = g.to_string_ref().unwrap();

	let _group: TestGroup = group_str.parse().unwrap();
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

	let err = u.prepare_get_group(g_id, None).await;

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

	let u0 = USER_0_TEST_STATE.get().unwrap().read().await;
	let u = USER_1_TEST_STATE.get().unwrap().read().await;

	g.invite(
		u0.get_jwt().unwrap(),
		u.get_user_id(),
		u.get_newest_exported_public_key().unwrap(),
		None,
	)
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

	let list = u.get_group_invites(list.get(0)).await.unwrap();

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

	g.invite(
		u0.get_jwt().unwrap(),
		u.get_user_id(),
		u.get_newest_exported_public_key().unwrap(),
		None,
	)
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

	let (data, fetch_res) = u.prepare_get_group(&out[0].group_id, None).await.unwrap();

	assert!(matches!(fetch_res, GroupFetchResult::Ok));

	let group = u.done_get_group(data, None).unwrap();

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

	g.invite_auto(
		u0.get_jwt().unwrap(),
		u.get_user_id(),
		u.get_newest_exported_public_key().unwrap(),
		None,
	)
	.await
	.unwrap();

	//get the group in the list of the joined groups (because of auto invite)

	let out = u.get_groups(None).await.unwrap();

	assert_eq!(out.len(), 1);

	assert_eq!(g.get_group_id(), &out[0].group_id);

	let (data, fetch_res) = u.prepare_get_group(&out[0].group_id, None).await.unwrap();

	assert!(matches!(fetch_res, GroupFetchResult::Ok));

	let group = u.done_get_group(data, None).unwrap();

	let mut g_state = GROUP_1_TEST_STATE.get().unwrap().write().await;

	g_state.0 = group;
}

//encryption

#[tokio::test]
async fn test_21_encrypt_string_for_the_group()
{
	let g = GROUP_0_TEST_STATE.get().unwrap().read().await;

	let encrypted_string = g.encrypt_string_sync(STRING_TO_ENCRYPT).unwrap();

	//decrypt the string with the same group
	let decrypted = g.decrypt_string_sync(&encrypted_string, None).unwrap();

	assert_eq!(decrypted, STRING_TO_ENCRYPT);

	//store the value for later
	ENCRYPTED_STRING
		.get_or_init(|| async { RwLock::new(EncryptedString(encrypted_string)) })
		.await;
}

#[tokio::test]
async fn test_22_start_key_rotation()
{
	let mut g = GROUP_0_TEST_STATE.get().unwrap().write().await;
	let u0 = USER_0_TEST_STATE.get().unwrap().read().await;

	let old_newest_key = g.get_newest_key().unwrap().group_key.key_id.clone();

	let res = g
		.prepare_key_rotation(
			u0.get_jwt().unwrap(),
			false,
			u0.get_user_id().to_string(),
			Some(&u0.0),
			None,
		)
		.await
		.unwrap();

	//end the rotation by fetching the new key
	let data = match res {
		GroupKeyFetchResult::Ok(data) => data,
		_ => {
			panic!("should be no missing key or done");
		},
	};

	g.done_fetch_group_key_after_rotation(data, Some(&u0.0), None)
		.unwrap();

	let new_newest_key = g.get_newest_key().unwrap().group_key.key_id.clone();

	assert_ne!(old_newest_key, new_newest_key);

	//get the group public key
	let gp = u0
		.get_group_public_key_data(g.get_group_id())
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

	let encrypted_string = g.encrypt_string_sync(STRING_TO_ENCRYPT).unwrap();

	//store the value for later
	ENCRYPTED_STRING_AFTER_KR
		.get_or_init(|| async { RwLock::new(EncryptedString(encrypted_string)) })
		.await;
}

#[tokio::test]
async fn test_24_not_decrypt_before_finish_key_rotation()
{
	let g = GROUP_1_TEST_STATE.get().unwrap().read().await;

	let string = ENCRYPTED_STRING_AFTER_KR.get().unwrap().read().await;

	let err = g.decrypt_string_sync(&string.0, None);

	match err {
		Err(SentcError::KeyRequired(_)) => {},
		_ => panic!("should be server error"),
	}
}

#[tokio::test]
async fn test_25_finish_key_rotation()
{
	let mut g = GROUP_1_TEST_STATE.get().unwrap().write().await;
	let u1 = USER_1_TEST_STATE.get().unwrap().read().await;

	let old_newest_key = g.get_newest_key().unwrap().group_key.key_id.clone();

	let res = g
		.prepare_finish_key_rotation(u1.get_jwt().unwrap(), Some(&u1.0), None)
		.await
		.unwrap();

	let data = match res {
		GroupFinishKeyRotation::Ok(data) => data,
		_ => {
			panic!("Should be ok")
		},
	};

	let res = g
		.done_key_rotation(u1.get_jwt().unwrap(), data, None, Some(&u1.0), None)
		.await
		.unwrap();

	//fetch each new key after all rotations
	for key in res {
		let data = match key {
			GroupKeyFetchResult::Ok(data) => data,
			_ => panic!("should be ok"),
		};

		g.done_fetch_group_key_after_rotation(data, Some(&u1.0), None)
			.unwrap();
	}

	let new_newest_key = g.get_newest_key().unwrap().group_key.key_id.clone();

	assert_ne!(old_newest_key, new_newest_key);
}

#[tokio::test]
async fn test_26_decrypt_both_strings()
{
	let g = GROUP_1_TEST_STATE.get().unwrap().read().await;

	let string = ENCRYPTED_STRING.get().unwrap().read().await;

	let decrypted = g.decrypt_string_sync(&string.0, None).unwrap();

	assert_eq!(decrypted, STRING_TO_ENCRYPT);

	let string = ENCRYPTED_STRING_AFTER_KR.get().unwrap().read().await;

	let decrypted = g.decrypt_string_sync(&string.0, None).unwrap();

	assert_eq!(decrypted, STRING_TO_ENCRYPT);
}

#[tokio::test]
async fn test_27_encrypt_with_sign()
{
	let u = USER_0_TEST_STATE.get().unwrap().read().await;

	let u_id = u.get_user_id().to_string();

	let g = GROUP_0_TEST_STATE.get().unwrap().read().await;
	let u0 = USER_0_TEST_STATE.get().unwrap().read().await;

	let encrypted_string = g
		.encrypt_string_with_sign_sync(STRING_TO_ENCRYPT, u.get_newest_sign_key().unwrap())
		.unwrap();

	//should decrypt it without verify
	let decrypted = g.decrypt_string_sync(&encrypted_string, None).unwrap();

	assert_eq!(decrypted, STRING_TO_ENCRYPT);

	let head = split_head_and_encrypted_string(&encrypted_string).unwrap();

	//now decrypt with verify
	let vk = u0
		.get_user_verify_key_data(&u_id, &head.sign.unwrap().id)
		.await
		.unwrap();

	let decrypted = g.decrypt_string_sync(&encrypted_string, Some(&vk)).unwrap();

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

	let u_id = u.get_user_id().to_string();

	let g = GROUP_1_TEST_STATE.get().unwrap().read().await;
	let u0 = USER_1_TEST_STATE.get().unwrap().read().await;

	let encrypt = ENCRYPTED_STRING_WITH_SIGN.get().unwrap().read().await;

	//should decrypt it without verify
	let decrypted = g.decrypt_string_sync(&encrypt.0, None).unwrap();

	assert_eq!(decrypted, STRING_TO_ENCRYPT);

	//now decrypt with verify
	let head = split_head_and_encrypted_string(&encrypt.0).unwrap();

	let vk = u0
		.get_user_verify_key_data(&u_id, &head.sign.unwrap().id)
		.await
		.unwrap();

	let decrypted = g.decrypt_string_sync(&encrypt.0, Some(&vk)).unwrap();

	assert_eq!(decrypted, STRING_TO_ENCRYPT);
}

//__________________________________________________________________________________________________
//join request

#[tokio::test]
async fn test_29_send_join_req()
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
async fn test_30_get_join_req_in_group()
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
async fn test_31_not_reject_join_without_the_rights()
{
	let u = USER_2_TEST_STATE.get().unwrap().read().await;

	let g = GROUP_1_TEST_STATE.get().unwrap().read().await;
	let u0 = USER_1_TEST_STATE.get().unwrap().read().await;

	let err = g
		.reject_join_request(u0.get_jwt().unwrap(), u.get_user_id())
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
async fn test_32_send_join_again()
{
	let u = USER_2_TEST_STATE.get().unwrap().read().await;

	let g = GROUP_0_TEST_STATE.get().unwrap().read().await;

	u.group_join_request(g.get_group_id()).await.unwrap();
}

#[tokio::test]
async fn test_33_not_accept_without_rights()
{
	let u = USER_2_TEST_STATE.get().unwrap().read().await;

	let g = GROUP_1_TEST_STATE.get().unwrap().read().await;
	let u0 = USER_1_TEST_STATE.get().unwrap().read().await;

	let pk = u0.get_user_public_key_data(u.get_user_id()).await.unwrap();

	let err = g
		.accept_join_request(u0.get_jwt().unwrap(), &pk, u.get_user_id(), None)
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

	let g = GROUP_0_TEST_STATE.get().unwrap().read().await;
	let u0 = USER_0_TEST_STATE.get().unwrap().read().await;

	let pk = u0.get_user_public_key_data(u.get_user_id()).await.unwrap();

	g.accept_join_request(u0.get_jwt().unwrap(), &pk, u.get_user_id(), None)
		.await
		.unwrap();
}

#[tokio::test]
async fn test_35_fetch_group()
{
	let u = USER_2_TEST_STATE.get().unwrap().read().await;

	let g = GROUP_0_TEST_STATE.get().unwrap().read().await;

	let (data, res) = u.prepare_get_group(g.get_group_id(), None).await.unwrap();

	assert!(matches!(res, GroupFetchResult::Ok));

	let group = u.done_get_group(data, None).unwrap();

	GROUP_2_TEST_STATE
		.get_or_init(|| async { RwLock::new(GroupState(group)) })
		.await;
}

#[tokio::test]
async fn test_36_decrypt_both_strings()
{
	//new user should get all keys after joining

	let g = GROUP_2_TEST_STATE.get().unwrap().read().await;

	let string = ENCRYPTED_STRING.get().unwrap().read().await;

	let decrypted = g.decrypt_string_sync(&string.0, None).unwrap();

	assert_eq!(decrypted, STRING_TO_ENCRYPT);

	let string = ENCRYPTED_STRING_AFTER_KR.get().unwrap().read().await;

	let decrypted = g.decrypt_string_sync(&string.0, None).unwrap();

	assert_eq!(decrypted, STRING_TO_ENCRYPT);
}

#[tokio::test]
async fn test_37_not_kick_without_rights()
{
	let u = USER_2_TEST_STATE.get().unwrap().read().await;

	let g = GROUP_1_TEST_STATE.get().unwrap().read().await;
	let u0 = USER_1_TEST_STATE.get().unwrap().read().await;

	let err = g.kick_user(u0.get_jwt().unwrap(), u.get_user_id()).await;

	match err {
		Err(SentcError::Sdk(SdkError::GroupPermission)) => {},
		_ => panic!("should be error"),
	}
}

#[tokio::test]
async fn test_38_increase_rank_for_user_1()
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
async fn test_39_not_kick_a_user_with_higher_rank()
{
	let u = USER_1_TEST_STATE.get().unwrap().read().await;

	let g = GROUP_2_TEST_STATE.get().unwrap().read().await;
	let u2 = USER_2_TEST_STATE.get().unwrap().read().await;

	let err = g.kick_user(u2.get_jwt().unwrap(), u.get_user_id()).await;

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
	let g = GROUP_1_TEST_STATE.get().unwrap().read().await;
	let u1 = USER_1_TEST_STATE.get().unwrap().read().await;

	g.kick_user(u1.get_jwt().unwrap(), u.get_user_id())
		.await
		.unwrap();
}

#[tokio::test]
async fn test_41_not_get_the_group_after_kick()
{
	let u = USER_2_TEST_STATE.get().unwrap().read().await;
	let g = GROUP_0_TEST_STATE.get().unwrap().read().await;

	let err = u.prepare_get_group(g.get_group_id(), None).await;

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

	let (data, res) = g
		.prepare_get_child_group(&id, u0.get_jwt().unwrap())
		.await
		.unwrap();

	assert!(matches!(res, GroupFetchResult::Ok));

	let child_group = g.done_get_child_group(data).unwrap();

	CHILD_GROUP
		.get_or_init(|| async move { RwLock::new(GroupState(child_group)) })
		.await;
}

#[tokio::test]
async fn test_51_get_child_group_as_member_of_the_parent_group()
{
	let cg = CHILD_GROUP.get().unwrap().read().await;

	let g = GROUP_1_TEST_STATE.get().unwrap().read().await;
	let u1 = USER_1_TEST_STATE.get().unwrap().read().await;

	let (data, res) = g
		.prepare_get_child_group(cg.get_group_id(), u1.get_jwt().unwrap())
		.await
		.unwrap();

	assert!(matches!(res, GroupFetchResult::Ok));

	let child_group = g.done_get_child_group(data).unwrap();

	assert_eq!(
		child_group.get_newest_key().unwrap().group_key.key_id,
		cg.get_newest_key().unwrap().group_key.key_id
	);
}

#[tokio::test]
async fn test_52_invite_a_user_to_the_child_group()
{
	let cg = CHILD_GROUP.get().unwrap().read().await;
	let u0 = USER_0_TEST_STATE.get().unwrap().read().await;

	let u = USER_2_TEST_STATE.get().unwrap().read().await;

	let pk = u0.get_user_public_key_data(u.get_user_id()).await.unwrap();

	//test manually invite
	let _invite = cg.prepare_group_keys_for_new_member(&pk, Some(2)).unwrap();

	cg.invite_auto(u0.get_jwt().unwrap(), u.get_user_id(), &pk, Some(2))
		.await
		.unwrap();

	let (data, res) = u.prepare_get_group(cg.get_group_id(), None).await.unwrap();

	assert!(matches!(res, GroupFetchResult::Ok));

	let child_group = u.done_get_group(data, None).unwrap();

	assert_eq!(child_group.get_rank(), 2);

	CHILD_GROUP_USER_2
		.get_or_init(|| async move { RwLock::new(GroupState(child_group)) })
		.await;
}

#[tokio::test]
async fn test_53_re_invite_user()
{
	let cg = CHILD_GROUP.get().unwrap().read().await;
	let u0 = USER_0_TEST_STATE.get().unwrap().read().await;

	let u = USER_2_TEST_STATE.get().unwrap().read().await;

	let pk = u0.get_user_public_key_data(u.get_user_id()).await.unwrap();

	cg.re_invite_user(u0.get_jwt().unwrap(), u.get_user_id(), &pk)
		.await
		.unwrap();
}

#[tokio::test]
async fn test_54_get_child_group_by_direct_access()
{
	//access the child group by user not by parent group -> the parent should be loaded too

	//auto invite the user to the parent but do not fetch the parent keys!
	let g = GROUP_0_TEST_STATE.get().unwrap().read().await;
	let u0 = USER_0_TEST_STATE.get().unwrap().read().await;

	let cg = CHILD_GROUP.get().unwrap().read().await;

	let u = USER_3_TEST_STATE.get().unwrap().read().await;

	let pk = u0.get_user_public_key_data(u.get_user_id()).await.unwrap();

	g.invite_auto(u0.get_jwt().unwrap(), u.get_user_id(), &pk, None)
		.await
		.unwrap();

	let (data, res) = u.prepare_get_group(g.get_group_id(), None).await.unwrap();
	assert!(matches!(res, GroupFetchResult::Ok));

	let g3 = u.done_get_group(data, None).unwrap();

	let (data, res) = g3
		.prepare_get_child_group(cg.get_group_id(), u.get_jwt().unwrap())
		.await
		.unwrap();

	assert!(matches!(res, GroupFetchResult::Ok));

	let child_group = g3.done_get_child_group(data).unwrap();

	assert_eq!(
		child_group.get_newest_key().unwrap().group_key.key_id,
		cg.get_newest_key().unwrap().group_key.key_id
	);

	CHILD_GROUP_USER_3
		.get_or_init(|| async move { RwLock::new(GroupState(child_group)) })
		.await;
}

#[tokio::test]
async fn test_55_encrypt_in_child_group()
{
	let cg = CHILD_GROUP.get().unwrap().read().await;

	let g = GROUP_1_TEST_STATE.get().unwrap().read().await;
	let u1 = USER_1_TEST_STATE.get().unwrap().read().await;

	let g1 = CHILD_GROUP_USER_2.get().unwrap().read().await;

	let g2 = CHILD_GROUP_USER_3.get().unwrap().read().await;

	let (data, res) = g
		.prepare_get_child_group(cg.get_group_id(), u1.get_jwt().unwrap())
		.await
		.unwrap();

	assert!(matches!(res, GroupFetchResult::Ok));

	let child_1 = g.done_get_child_group(data).unwrap();

	let encrypted = cg.encrypt_string_sync(STRING_TO_ENCRYPT).unwrap();

	let decrypted_1 = child_1.decrypt_string_sync(&encrypted, None).unwrap();

	let decrypt_2 = g1.decrypt_string_sync(&encrypted, None).unwrap();

	let decrypt_3 = g2.decrypt_string_sync(&encrypted, None).unwrap();

	assert_eq!(decrypted_1, STRING_TO_ENCRYPT);
	assert_eq!(decrypt_2, STRING_TO_ENCRYPT);
	assert_eq!(decrypt_3, STRING_TO_ENCRYPT);
}

#[tokio::test]
async fn test_56_key_rotation_in_child_group()
{
	let mut cg = CHILD_GROUP.get().unwrap().write().await;
	let u0 = USER_0_TEST_STATE.get().unwrap().read().await;
	let g = GROUP_0_TEST_STATE.get().unwrap().read().await;

	let old_key = cg.get_newest_key().unwrap().group_key.key_id.clone();

	let res = cg
		.prepare_key_rotation(
			u0.get_jwt().unwrap(),
			false,
			u0.get_user_id().to_string(),
			None,
			Some(&g.0),
		)
		.await
		.unwrap();

	let data = match res {
		GroupKeyFetchResult::Ok(data) => data,
		_ => {
			panic!("should be no missing key or done");
		},
	};

	cg.done_fetch_group_key_after_rotation(data, None, Some(&g.0))
		.unwrap();

	let new_key = cg.get_newest_key().unwrap().group_key.key_id.clone();

	assert_ne!(old_key, new_key);

	//finish the key rotation as direct user

	sleep(Duration::from_millis(300)).await;

	let mut cg = CHILD_GROUP_USER_2.get().unwrap().write().await;
	let u2 = USER_2_TEST_STATE.get().unwrap().read().await;

	let old_key1 = cg.get_newest_key().unwrap().group_key.key_id.clone();

	assert_eq!(old_key1, old_key);

	let res = cg
		.prepare_finish_key_rotation(u2.get_jwt().unwrap(), Some(&u2), None)
		.await
		.unwrap();

	let data = match res {
		GroupFinishKeyRotation::Ok(data) => data,
		_ => {
			panic!("Should be ok")
		},
	};

	let res = cg
		.done_key_rotation(u2.get_jwt().unwrap(), data, None, Some(&u2.0), None)
		.await
		.unwrap();

	//fetch each new key after all rotations
	for key in res {
		let data = match key {
			GroupKeyFetchResult::Ok(data) => data,
			_ => panic!("should be ok"),
		};

		cg.done_fetch_group_key_after_rotation(data, Some(&u2.0), None)
			.unwrap();
	}

	let new_key1 = cg.get_newest_key().unwrap().group_key.key_id.clone();

	assert_ne!(old_key1, new_key1);

	assert_eq!(new_key1, new_key);
}

#[tokio::test]
async fn test_57_no_error_for_finishing_an_already_finished_rotation()
{
	let cg = CHILD_GROUP_USER_3.get().unwrap().read().await;
	let u3 = USER_3_TEST_STATE.get().unwrap().read().await;

	let res = cg
		.prepare_finish_key_rotation(u3.get_jwt().unwrap(), Some(&u3), None)
		.await
		.unwrap();

	assert!(matches!(res, GroupFinishKeyRotation::Empty));
}

#[tokio::test]
async fn test_58_encrypt_with_new_key()
{
	let cg = CHILD_GROUP.get().unwrap().read().await;

	let g = GROUP_1_TEST_STATE.get().unwrap().read().await;
	let u1 = USER_1_TEST_STATE.get().unwrap().read().await;

	let g1 = CHILD_GROUP_USER_2.get().unwrap().read().await;

	let mut g2 = CHILD_GROUP_USER_3.get().unwrap().write().await;
	let u3 = USER_3_TEST_STATE.get().unwrap().read().await;
	let g0 = GROUP_0_TEST_STATE.get().unwrap().read().await;

	let (data, res) = g
		.prepare_get_child_group(cg.get_group_id(), u1.get_jwt().unwrap())
		.await
		.unwrap();

	assert!(matches!(res, GroupFetchResult::Ok));

	let child_1 = g.done_get_child_group(data).unwrap();

	let encrypted = cg.encrypt_string_sync(STRING_TO_ENCRYPT).unwrap();

	let decrypted_1 = child_1.decrypt_string_sync(&encrypted, None).unwrap();

	let decrypt_2 = g1.decrypt_string_sync(&encrypted, None).unwrap();

	//get missing key from decryption and fetch the missing key
	let missing_key_id = match g2.decrypt_string_sync(&encrypted, None) {
		Err(SentcError::KeyRequired(key_id)) => key_id,
		_ => panic!("Should be error"),
	};

	let res = g2
		.prepare_fetch_group_key(&missing_key_id, u3.get_jwt().unwrap(), None, Some(&g0.0))
		.await
		.unwrap();

	let data = match res {
		GroupKeyFetchResult::Ok(data) => data,
		_ => panic!("should be ok"),
	};

	g2.done_fetch_group_key(data, None, Some(&g0.0)).unwrap();

	let decrypt_3 = g2.decrypt_string_sync(&encrypted, None).unwrap();

	assert_eq!(decrypted_1, STRING_TO_ENCRYPT);
	assert_eq!(decrypt_2, STRING_TO_ENCRYPT);
	assert_eq!(decrypt_3, STRING_TO_ENCRYPT);
}

//__________________________________________________________________________________________________________________
//key rotation with sign

#[tokio::test]
async fn test_60_start_key_rotation_with_sign()
{
	let mut g = GROUP_0_TEST_STATE.get().unwrap().write().await;
	let u0 = USER_0_TEST_STATE.get().unwrap().read().await;

	let old_newest_key = g.get_newest_key().unwrap().group_key.key_id.clone();

	let res = g
		.prepare_key_rotation(
			u0.get_jwt().unwrap(),
			true,
			u0.get_user_id().to_string(),
			Some(&u0),
			None,
		)
		.await
		.unwrap();

	let data = match res {
		GroupKeyFetchResult::Ok(data) => data,
		_ => {
			panic!("should be no missing key or done");
		},
	};

	g.done_fetch_group_key_after_rotation(data, Some(&u0.0), None)
		.unwrap();

	let new_newest_key = g.get_newest_key().unwrap().group_key.key_id.clone();

	assert_ne!(old_newest_key, new_newest_key);

	//"wait" until the server is done with the rotation before moving on
	sleep(Duration::from_millis(300)).await;
}

#[tokio::test]
async fn test_61_finish_key_rotation_without_verify()
{
	let mut g = GROUP_1_TEST_STATE.get().unwrap().write().await;
	let u1 = USER_1_TEST_STATE.get().unwrap().read().await;

	let old_newest_key = g.get_newest_key().unwrap().group_key.key_id.clone();

	let res = g
		.prepare_finish_key_rotation(u1.get_jwt().unwrap(), Some(&u1.0), None)
		.await
		.unwrap();

	let data = match res {
		GroupFinishKeyRotation::Ok(data) => data,
		_ => {
			panic!("Should be ok")
		},
	};

	let res = g
		.done_key_rotation(u1.get_jwt().unwrap(), data, None, Some(&u1.0), None)
		.await
		.unwrap();

	//fetch each new key after all rotations
	for key in res {
		let data = match key {
			GroupKeyFetchResult::Ok(data) => data,
			_ => panic!("should be ok"),
		};

		g.done_fetch_group_key_after_rotation(data, Some(&u1.0), None)
			.unwrap();
	}

	let new_newest_key = g.get_newest_key().unwrap().group_key.key_id.clone();

	assert_ne!(old_newest_key, new_newest_key);
}

#[tokio::test]
async fn test_62_start_key_rotation_with_sign()
{
	let mut g = GROUP_0_TEST_STATE.get().unwrap().write().await;
	let u0 = USER_0_TEST_STATE.get().unwrap().read().await;

	let old_newest_key = g.get_newest_key().unwrap().group_key.key_id.clone();

	let res = g
		.prepare_key_rotation(
			u0.get_jwt().unwrap(),
			true,
			u0.get_user_id().to_string(),
			Some(&u0.0),
			None,
		)
		.await
		.unwrap();

	//end the rotation by fetching the new key
	let data = match res {
		GroupKeyFetchResult::Ok(data) => data,
		_ => {
			panic!("should be no missing key or done");
		},
	};

	g.done_fetch_group_key_after_rotation(data, Some(&u0.0), None)
		.unwrap();

	let new_newest_key = g.get_newest_key().unwrap().group_key.key_id.clone();

	assert_ne!(old_newest_key, new_newest_key);

	//"wait" until the server is done with the rotation before moving on
	sleep(Duration::from_millis(300)).await;
}

#[tokio::test]
async fn test_63_finish_key_rotation_with_verify()
{
	let mut g = GROUP_1_TEST_STATE.get().unwrap().write().await;
	let u1 = USER_1_TEST_STATE.get().unwrap().read().await;

	let old_newest_key = g.get_newest_key().unwrap().group_key.key_id.clone();

	let res = g
		.prepare_finish_key_rotation(u1.get_jwt().unwrap(), Some(&u1.0), None)
		.await
		.unwrap();

	let data = match res {
		GroupFinishKeyRotation::Ok(data) => data,
		_ => {
			panic!("Should be ok")
		},
	};

	let res = g
		.done_key_rotation(u1.get_jwt().unwrap(), data, None, Some(&u1.0), None)
		.await
		.unwrap();

	//fetch each new key after all rotations
	for key in res {
		let data = match key {
			GroupKeyFetchResult::Ok(data) => data,
			_ => panic!("should be ok"),
		};

		g.done_fetch_group_key_after_rotation(data, Some(&u1.0), None)
			.unwrap();
	}

	let new_newest_key = g.get_newest_key().unwrap().group_key.key_id.clone();

	assert_ne!(old_newest_key, new_newest_key);
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
