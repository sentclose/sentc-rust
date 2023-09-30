use std::sync::Arc;

use sentc::error::SentcError;
use sentc::sentc::net::UserLoginReturn;
use sentc::sentc::Sentc;
use sentc::user::User;
use tokio::sync::{OnceCell, RwLock};
use totp_rs::{Algorithm, Secret, TOTP};

struct UserState
{
	inner: Arc<RwLock<User>>,
	otp_sec: String,
	recovery: Vec<String>,
}

static SENTC: OnceCell<Sentc> = OnceCell::const_new();
static USER_TEST_STATE: OnceCell<RwLock<UserState>> = OnceCell::const_new();

const USERNAME: &str = "test";
const PW: &str = "12345";

fn get_totp(sec: String) -> TOTP
{
	TOTP::new(Algorithm::SHA256, 6, 1, 30, Secret::Encoded(sec).to_bytes().unwrap()).unwrap()
}

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

	sentc.register(USERNAME, PW).await.unwrap();

	let user = sentc.login_forced(USERNAME, PW).await.unwrap();

	USER_TEST_STATE
		.get_or_init(|| {
			async move {
				RwLock::new(UserState {
					inner: user,

					otp_sec: "".to_string(),
					recovery: vec![],
				})
			}
		})
		.await;

	SENTC.get_or_init(|| async move { sentc }).await;
}

#[tokio::test]
async fn test_10_register_otp()
{
	let mut u = USER_TEST_STATE.get().unwrap().write().await;
	let mut uw = u.inner.write().await;

	let out = uw
		.register_raw_otp(PW, None, None, SENTC.get().unwrap().get_cache())
		.await
		.unwrap();

	drop(uw);

	u.otp_sec = out.secret;
	u.recovery = out.recover;
}

#[tokio::test]
async fn test_11_not_login_without_otp()
{
	let err = SENTC.get().unwrap().login_forced(USERNAME, PW).await;

	match err {
		Err(SentcError::UserMfaRequired) => {},
		_ => panic!("should be error"),
	}
}

#[tokio::test]
async fn test_12_login_with_otp()
{
	let u = SENTC.get().unwrap().login(USERNAME, PW).await.unwrap();

	match u {
		UserLoginReturn::Direct(_) => {
			panic!("should not be direct login")
		},
		UserLoginReturn::Otp(d) => {
			let u = USER_TEST_STATE.get().unwrap().read().await;
			//create a token
			let totp = get_totp(u.otp_sec.clone());
			let token = totp.generate_current().unwrap();

			let user = SENTC
				.get()
				.unwrap()
				.mfa_login(token, USERNAME, d)
				.await
				.unwrap();

			assert!(user.read().await.get_mfa());
		},
	}
}

#[tokio::test]
async fn test_13_get_all_recover_keys()
{
	let u = USER_TEST_STATE.get().unwrap().read().await;
	//create a token
	let totp = get_totp(u.otp_sec.clone());
	let token = totp.generate_current().unwrap();

	let uw = u.inner.read().await;

	let keys = uw
		.get_otp_recover_keys(PW, Some(token), Some(false))
		.await
		.unwrap();

	assert_eq!(keys.len(), 6);
}

#[tokio::test]
async fn test_14_login_with_recovery_key()
{
	let u = SENTC.get().unwrap().login(USERNAME, PW).await.unwrap();

	match u {
		UserLoginReturn::Direct(_) => {
			panic!("should not be direct login")
		},
		UserLoginReturn::Otp(d) => {
			let u = USER_TEST_STATE.get().unwrap().read().await;

			let user = SENTC
				.get()
				.unwrap()
				.mfa_recovery_login(u.recovery[0].clone(), USERNAME, d)
				.await
				.unwrap();

			assert!(user.read().await.get_mfa());
		},
	}
}

#[tokio::test]
async fn test_15_get_one_recovery_key_less()
{
	let u = USER_TEST_STATE.get().unwrap().read().await;
	//create a token
	let totp = get_totp(u.otp_sec.clone());
	let token = totp.generate_current().unwrap();

	let uw = u.inner.read().await;

	let keys = uw
		.get_otp_recover_keys(PW, Some(token), Some(false))
		.await
		.unwrap();

	assert_eq!(keys.len(), 5);
}

#[tokio::test]
async fn test_16_reset_otp()
{
	let mut u = USER_TEST_STATE.get().unwrap().write().await;
	//create a token
	let totp = get_totp(u.otp_sec.clone());
	let token = totp.generate_current().unwrap();

	let uw = u.inner.read().await;

	let out = uw
		.reset_raw_otp(PW, Some(token), Some(false))
		.await
		.unwrap();

	drop(uw);

	u.otp_sec = out.secret;
	u.recovery = out.recover;
}

#[tokio::test]
async fn test_17_get_all_keys_back()
{
	let u = USER_TEST_STATE.get().unwrap().read().await;
	//create a token
	let totp = get_totp(u.otp_sec.clone());
	let token = totp.generate_current().unwrap();

	let uw = u.inner.read().await;

	let keys = uw
		.get_otp_recover_keys(PW, Some(token), Some(false))
		.await
		.unwrap();

	assert_eq!(keys.len(), 6);
}

#[tokio::test]
async fn test_30_disable_otp()
{
	let u = USER_TEST_STATE.get().unwrap().read().await;
	//create a token
	let totp = get_totp(u.otp_sec.clone());
	let token = totp.generate_current().unwrap();

	let mut uw = u.inner.write().await;

	uw.disable_otp(PW, Some(token), Some(false)).await.unwrap();
}

#[tokio::test]
async fn test_31_login_without_otp()
{
	let u = SENTC.get().unwrap().login(USERNAME, PW).await.unwrap();

	match u {
		UserLoginReturn::Direct(_) => {},
		UserLoginReturn::Otp(_) => {
			panic!("should not be otp login")
		},
	}
}

#[tokio::test]
async fn zzz_clean_up()
{
	let u = USER_TEST_STATE.get().unwrap().read().await;

	let ur = u.inner.read().await;

	ur.delete(PW, None, None, SENTC.get().unwrap().get_cache())
		.await
		.unwrap();
}
