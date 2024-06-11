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
async fn test_11_encrypt_number()
{
	let g = GROUP_0_TEST_STATE.get().unwrap().read().await;
	let g = g.read().await;

	let g1 = GROUP_1_TEST_STATE.get().unwrap().read().await;
	let g1 = g1.read().await;

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

#[tokio::test]
async fn test_12_encrypt_string()
{
	let g = GROUP_0_TEST_STATE.get().unwrap().read().await;
	let g = g.read().await;

	let g1 = GROUP_1_TEST_STATE.get().unwrap().read().await;
	let g1 = g1.read().await;

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
