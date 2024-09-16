# User

A user can have more than one device with different device names which is also the login name.
A device got its own keys and is a member in the user group. The devices can communicate with each other or add new
devices.

The user uses the keys of the user group to communicate with other users or groups. This group can do a key rotation
too.

## Register a user

This is an async function to register a user. This will make a request with reqwest to the sentc api to register the
user. There is also an offline version to just generate the data.

````rust
use sentc::keys::StdUser;

async fn register()
{
	let user_id = StdUser::register("the-username", "the-password").unwrap();
}
````

To generate username and password:

````rust
use sentc::user::generate_register_data;

fn main()
{
	let (username, password) = generate_register_data().unwrap();
}
````

The username is 20 chars and the password is 40 char long string.

### Generate register data

To use it in offline mode or just create the data to register a user without sending the request:

````rust
use sentc::keys::StdUser;

fn main()
{
	let register_data = StdUser::prepare_register("the-username", "the-password").unwrap();
}
````

This function will create the user keys and return the result as a json string. This string is required for the api to
register a user.

## Login

Login is not supported offline because there are two different requests that been made.

````rust
use sentc::keys::StdUser;

async fn login()
{
	let login_res = StdUser::login("base_url".to_string(), "app_token", "username", "password").await.unwrap();
}
````

The login response is an enum. If the user didn't enable 2fa then the user struct is returned. But if it is enabled then
the data for the 2fa is returned.

To ignore 2fa use login_forced fn. This fn will return the user struct directly or return an error if the user enabled
2fa and must be handled. If you don't use 2fa then this fn is faster.

````rust
use sentc::keys::StdUser;

async fn login()
{
	let user = StdUser::login_forced("base_url".to_string(), "app_token", "username", "password").await.unwrap();
}
````

## 2fa Otp

Two-factor authentication (2fa) works with one-time passwords (OTP) in sentc. When the user activated 2fa, after the
login the data for the 2fa process are returned instead of the user keys. The user keys are only obtained after fulfill
the 2fa.

### Register otp

This is only available in online mode. Issuer, audience are set in the otpauth url. You can create a QR code with this
url and let the device scan the code with an otp app. The recover codes are used in case when the otp device is not
accessible anymore.

````rust
use sentc::keys::StdUser;

//get the user object after login
async fn register_otp(user: &mut StdUser)
{
	let (url, recover_codes) = user.register_otp("issuer", "audience", "password", None, None).await.unwrap();
}
````

To get the recover keys:

````rust
use sentc::keys::StdUser;

async fn get_recover_keys(user: &mut StdUser)
{
	let keys = user.get_otp_recover_keys("password", Some("token from auth app".to_string()), None).await.unwrap();
}
````

To reset it (new register):

This will return a new url and new recovery codes.

````rust
use sentc::keys::StdUser;

async fn reset_otp(user: &mut StdUser)
{
	let (url, recover_codes) = user.reset_otp("issuer", "audience", "password", Some("token from auth app".to_string()), None).await.unwrap();
}
````

To disable:

````rust
use sentc::keys::StdUser;

async fn disable_otp(user: &mut StdUser)
{
	user.disable_otp("password", Some("token from auth app".to_string()), None).await.unwrap();
}
````

### Login with otp

When user enabled the 2fa, after login the device data is returned but not the user keys. The device data is needed to
decrypt the user keys.

If after login the enum variant PreLoginOut::Otp is returned this function needs to be called to continue the login
process:

````rust
use sentc::keys::{StdUser, StdPrepareLoginOtpOutput};

async fn login()
{
	let login_res = StdUser::login("base_url".to_string(), "app_token", "username", "password").await.unwrap();

	//check if the enum is PreLoginOut::Otp, if so call mfa_login with the token from the user auth device
}

//token from the auth app
async fn mfa_login(token: String, login_data: StdPrepareLoginOtpOutput)
{
	let user = StdUser::mfa_login("base_url".to_string(), "app_token", token, "username", login_data).await.unwrap();
}
````

Or login with a recovery code instead an otp:

````rust
use sentc::keys::{StdUser, StdPrepareLoginOtpOutput};

async fn mfa_login(recover_token: String, login_data: StdPrepareLoginOtpOutput)
{
	let user = StdUser::mfa_recovery_login("base_url".to_string(), "app_token", recover_token, "username", login_data).await.unwrap();
}
````

## Auth

Sentc uses jsonwebtoken (jwt) to auth the user after login. The jwt must be sent on every request to the api. The jwt is
5 min valid. After this time it needs to be refreshed. If a function returned this error: SentcError::JwtExpired then
you have to refresh the jwt to make the request.

````rust
use sentc::keys::StdUser;

async fn refresh_jwt(user: &mut StdUser)
{
	let fresh_jwt = user.refresh_jwt().await.unwrap();
}
````

This function will refresh the jwt with the refresh token (long-lived token). This token should be stored securely.

A jwt got an argument of freshness: fresh true or false. A refreshed jwt is false a jwt from login is true. Some actions
require a fresh jwt like deleting user or changing mfa settings. This is to be sure that the user got access and not
just stolen the jwt.

To get a fresh jwt this functions will always ask for the user password and the mfa tokens if the user set it.