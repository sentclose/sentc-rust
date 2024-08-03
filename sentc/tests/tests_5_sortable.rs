#[cfg(all(test, any(feature = "std_keys", feature = "rec_keys")))]
use std::ops::Deref;

#[cfg(all(test, any(feature = "std_keys", feature = "rec_keys")))]
use sentc::group::net::GroupFetchResult;
#[cfg(all(test, any(feature = "std_keys", feature = "rec_keys")))]
use tokio::sync::{OnceCell, RwLock};

#[cfg(all(test, any(feature = "std_keys", feature = "rec_keys")))]
use crate::test_mod::{TestGroup, TestUser};

#[cfg(all(test, any(feature = "std_keys", feature = "rec_keys")))]
mod test_mod;

#[cfg(all(test, any(feature = "std_keys", feature = "rec_keys")))]
struct UserState(TestUser);

#[cfg(all(test, any(feature = "std_keys", feature = "rec_keys")))]
impl Deref for UserState
{
	type Target = TestUser;

	fn deref(&self) -> &Self::Target
	{
		&self.0
	}
}

#[cfg(all(test, any(feature = "std_keys", feature = "rec_keys")))]
struct GroupState(TestGroup);

#[cfg(all(test, any(feature = "std_keys", feature = "rec_keys")))]
impl Deref for GroupState
{
	type Target = TestGroup;

	fn deref(&self) -> &Self::Target
	{
		&self.0
	}
}

#[cfg(all(test, any(feature = "std_keys", feature = "rec_keys")))]
static USER_0_TEST_STATE: OnceCell<RwLock<UserState>> = OnceCell::const_new();
#[cfg(all(test, any(feature = "std_keys", feature = "rec_keys")))]
static USER_1_TEST_STATE: OnceCell<RwLock<UserState>> = OnceCell::const_new();

#[cfg(all(test, any(feature = "std_keys", feature = "rec_keys")))]
static GROUP_0_TEST_STATE: OnceCell<RwLock<GroupState>> = OnceCell::const_new();
#[cfg(all(test, any(feature = "std_keys", feature = "rec_keys")))]
static GROUP_1_TEST_STATE: OnceCell<RwLock<GroupState>> = OnceCell::const_new();

#[cfg(all(test, any(feature = "std_keys", feature = "rec_keys")))]
const USERNAME0: &str = "test0";
#[cfg(all(test, any(feature = "std_keys", feature = "rec_keys")))]
const USERNAME1: &str = "test1";

#[cfg(all(test, any(feature = "std_keys", feature = "rec_keys")))]
const PW: &str = "12345";

#[cfg(all(test, any(feature = "std_keys", feature = "rec_keys")))]
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

#[cfg(all(test, any(feature = "std_keys", feature = "rec_keys")))]
#[tokio::test]
async fn test_10_create_and_fetch_group()
{
	let u0 = USER_0_TEST_STATE.get().unwrap().read().await;

	let group_id = u0.create_group().await.unwrap();

	let (data, res) = u0.prepare_get_group(&group_id, None).await.unwrap();

	assert!(matches!(res, GroupFetchResult::Ok));

	let group = u0.done_get_group(data, None).unwrap();

	let u1 = USER_1_TEST_STATE.get().unwrap().read().await;

	let pk = u0.get_user_public_key_data(u1.get_user_id()).await.unwrap();

	group
		.invite_auto(u0.get_jwt().unwrap(), u1.get_user_id(), &pk, None)
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

#[cfg(all(test, any(feature = "std_keys", feature = "rec_keys")))]
#[tokio::test]
async fn test_11_encrypt_number()
{
	let g = GROUP_0_TEST_STATE.get().unwrap().read().await;

	let g1 = GROUP_1_TEST_STATE.get().unwrap().read().await;

	let a = g.encrypt_sortable_raw_number(262).unwrap();
	let b = g.encrypt_sortable_raw_number(263).unwrap();
	let c = g.encrypt_sortable_raw_number(65321).unwrap();

	assert!(a < b);
	assert!(b < c);

	//now test if another user in the same group got the same results

	let a1 = g1.encrypt_sortable_raw_number(262).unwrap();
	let b1 = g1.encrypt_sortable_raw_number(263).unwrap();
	let c1 = g1.encrypt_sortable_raw_number(65321).unwrap();

	assert!(a1 < b1);
	assert!(b1 < c1);

	assert_eq!(a, a1);
	assert_eq!(b, b1);
	assert_eq!(c, c1);
}

#[cfg(all(test, any(feature = "std_keys", feature = "rec_keys")))]
#[tokio::test]
async fn test_12_encrypt_string()
{
	let g = GROUP_0_TEST_STATE.get().unwrap().read().await;

	let g1 = GROUP_1_TEST_STATE.get().unwrap().read().await;

	const STR_VALUES: [&str; 10] = ["a", "az", "azzz", "b", "ba", "baaa", "o", "oe", "z", "zaaa"];

	let mut encrypted_values = Vec::with_capacity(10);

	for v in STR_VALUES {
		encrypted_values.push(g.encrypt_sortable_raw_string(v, None).unwrap());
	}

	//check the numbers

	let mut past_item = 0;

	for item in encrypted_values.iter() {
		assert!(past_item < *item);
		past_item = *item;
	}

	//now test if another user in the same group got the same results
	let mut new_encrypted_values = Vec::with_capacity(10);

	for v in STR_VALUES {
		new_encrypted_values.push(g1.encrypt_sortable_raw_string(v, None).unwrap());
	}

	//check the numbers
	let mut past_item = 0;

	for (i, item) in new_encrypted_values.iter().enumerate() {
		assert!(past_item < *item);

		let check_item = encrypted_values.get(i).unwrap();

		assert_eq!(*item, *check_item);

		past_item = *item;
	}
}

#[cfg(all(test, any(feature = "std_keys", feature = "rec_keys")))]
#[tokio::test]
async fn zzz_clean_up()
{
	let u0 = USER_0_TEST_STATE.get().unwrap().read().await;

	let g = GROUP_0_TEST_STATE.get().unwrap().read().await;
	g.delete_group(u0.get_jwt().unwrap()).await.unwrap();

	u0.delete(PW, None, None).await.unwrap();

	let u = USER_1_TEST_STATE.get().unwrap().read().await;
	u.delete(PW, None, None).await.unwrap();
}
