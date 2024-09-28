# User

Sentc provides secure registration and login capabilities out of the box,
but we do not store any additional data about the user.
If you require additional information, such as an email address or full name, you can register the user from your own
backend.

Users are required for encryption/decryption and group joining.
Each user has a public and private key, as well as a sign and verify key.
These keys are not available through the API, as they are encrypted using the provided password,
which the API does not have access to.

A user account can have multiple devices with different logins, but any device can access the user's keys.

Using Multi-factor auth with an authentication app is also possible.

## Register

The first registration is also considered the first device registration.
Please refer to the "Register a Device" section for more information.

The username/identifier can be anything, such as a name, email address, or random number.
The username is only required to log in to the correct device.

````rust
use sentc::keys::StdUser;

async fn register()
{
	let user_id = StdUser::register("the-username", "the-password").unwrap();
}
````

The username and password can also be generated to ensure a unique and secure login for each device.
The following function will create a random device name and password.
However, these values are not stored, so please ensure that they are securely stored on the user's device.

````rust
use sentc::user::generate_register_data;

fn main()
{
	let (username, password) = generate_register_data().unwrap();
}
````

The registration process will throw an error if the chosen username is already taken.
To check if a username is still available, you can use the following function,
which will return true if the username is still available:

````rust
use sentc::user::net::check_user_name_available;

async fn example()
{
	let available = check_user_name_available("base_url", "app_token", "user_identifier").await.unwrap();
}
````

### Own backend

If you are using your own backend to store additional user information,
you can use the prepare function to prepare the registration data.
Then, send the output to our API with a POST request to the following endpoint: `https://api.sentc.com/api/v1/register`

````rust
use sentc::keys::StdUser;

fn example()
{
	let input = StdUser::prepare_register("identifier", "password").unwrap();
}
````

## Login

To log in, you just need to provide the identifier (i.e., username, email, or random number) and the password that was
used during registration.
The user will then be logged in to the device associated with the given identifier.

The password is not sent to the API, so we cannot access or retrieve the user's password.
This is accomplished by using a password derivation function in the client instead of on the server.

If the identifier or the password is incorrect, this function will throw an error.

The Login function returns an either the user type or data for the mfa validation process.

If you disabled the Mfa in the app options then you can force login to get just the user object back.

### Login forced

With this method the sdk will just return the user object or throw an exception or error
if the user enabled mfa because this must be handled in order to get the user data.

````rust
use sentc::keys::StdUser;

async fn example()
{
	let user = StdUser::login_forced("base_url".to_string(), "app_token", "username", "password").await.unwrap();
}
````

### Login with mfa handling

For rust an enum is returned with either the User data or mfa data.

````rust
use sentc::keys::{StdUser, StdUserLoginReturn};

async fn login()
{
	let login_res = StdUser::login("base_url".to_string(), "app_token", "username", "password").await.unwrap();

	//check if the enum is PreLoginOut::Otp, if so call mfa_login with the token from the user auth device
	match login_res {
		StdUserLoginReturn::Direct(user) => {
			//the user
		}
		StdUserLoginReturn::Otp(data) => {
			//handle otp
		}
	}
}
````

### Login auth token

If the user enabled mfa, you must handle it so that the user can continue the login process.

In the above examples we already used the function that works with the auth app of the user.

````rust
use sentc::keys::{StdUser, StdPrepareLoginOtpOutput, StdUserLoginReturn};

async fn login()
{
	let login_res = StdUser::login("base_url".to_string(), "app_token", "username", "password").await.unwrap();

	let user = match login_res {
		StdUserLoginReturn::Direct(user) => {
			user
		}
		StdUserLoginReturn::Otp(data) => {
			//get the token first
			mfa_login("<token-from-mfa-app>".to_string(), data).await
		}
	};
}

//token from the auth app
async fn mfa_login(token: String, login_data: StdPrepareLoginOtpOutput) -> StdUser
{
	StdUser::mfa_login("base_url".to_string(), "app_token", token, "username", login_data).await.unwrap()
}
````

### Login with recovery key

If the user is not able to create the token (e.g. the device is broken or stolen), then the user can also log in with a
recovery key.
These keys are obtained after mfa was enabled. If the user uses one key then the key gets deleted and can't be used
again.

````rust
use sentc::keys::{StdUser, StdPrepareLoginOtpOutput, StdUserLoginReturn};

async fn login()
{
	let login_res = StdUser::login("base_url".to_string(), "app_token", "username", "password").await.unwrap();

	let user = match login_res {
		StdUserLoginReturn::Direct(user) => {
			user
		}
		StdUserLoginReturn::Otp(data) => {
			//get the token first
			mfa_recovery_login("<recovery-key>".to_string(), data).await
		}
	};
}

//token from the auth app
async fn mfa_recovery_login(recovery_key: String, login_data: StdPrepareLoginOtpOutput) -> StdUser
{
	StdUser::mfa_recovery_login("base_url".to_string(), "app_token", recovery_key, "username", login_data).await.unwrap()
}
````

### User object

After successfully logging in, you will receive a user object, which is required to perform all user actions, such as
creating a group.

You can export the user struct either when owning the struct or from its ref and import it with the parse fn from
String:

````rust
use sentc::keys::StdUser;

fn example(user: StdUser)
{
	let export = user.to_string().unwrap();

	//don't forget the type
	let imported_user: StdUser = export.parse().unwrap();
}

fn example_ref(user: &StdUser)
{
	let export = user.to_string_ref().unwrap();

	let imported_user: StdUser = export.parse().unwrap();
}
````

## The User Data

he data contains all information about the user account and the device that sentc needs.

For the device:

- Asymmetric key pairs only for the device.
- Device ID.

For user account:

- Asymmetric key pairs for the account (which are also used to join a group).
- The actual JWT for this session.
- The refresh token for this session.
- User ID

To get the data, just access the data in the user struct.

````rust
use sentc::keys::StdUser;

fn example_ref(user: &StdUser)
{
	let refresh_token = user.get_refresh_token();
	let user_id = user.get_user_id();
	let device_id = user.get_device_id();
}
````

## Authentication and JWT

After logging in, the user receives a JSON Web Token (JWT) to authenticate with the sentc API.
This JWT is only valid for 5 minutes.
But don't worry, the SDK will automatically refresh the JWT when the user tries to make a request with an invalid JWT.

To refresh the JWT, a refresh token is needed. This token is obtained during the login process.

There are three strategies to refresh a JWT.
However, this is only necessary if you must use HTTP-only cookies for the browser.
If you are using other implementations, stick with the default.

If a function returned this error: SentcError::JwtExpired then
you have to refresh the jwt to make the request.

````rust
use sentc::keys::StdUser;

async fn refresh_jwt(user: &mut StdUser)
{
	let fresh_jwt = user.refresh_jwt().await.unwrap();
}
````

## Multi-Factor authentication

Sentc uses Time-based one-time password (Totp) for Multi-factor auth. These tokens can easily be generated by any totp
generator app like google authenticator, authy or free otp.

A secret is generated alone side with six recovery keys (just in case if the user lost access to the auth device).
The user should print out or store the recovery keys to still get access to the account.

The auth app needs the secret and information about the used algorithm.
The simplest way is to get an otpauth url and transform it into a qr code, so the auth app can scan it.

The mfa is bind to all devices in the user account not just the actual one.

The user must be logged in, in order to activate mfa and has to enter the password again.
`issuer` and `audience` are needed for the auth app. Issuer can be your app name and audience the username email or
something else.

````rust
use sentc::keys::StdUser;

//get the user object after login
async fn example(user: &mut StdUser)
{
	let (url, recover_codes) = user.register_otp("issuer", "audience", "password", None, None).await.unwrap();
}
````

### Reset mfa

If the user only got one recovery key left or the device with the auth app ist stolen or lost then resetting the mfa is
the best practice

The old recovery keys and the old secret will be deleted and replaced by new one.
The return values are the same as in the register process.

The user also needs to enter a totp from an auth app or a recovery key in order to reset it.
This will make sure that only a person with access can change it.

The last parameter is for the function to know if a recovery key (Some(true)) or a normal top (None) is used.

````rust
use sentc::keys::StdUser;

async fn example(user: &StdUser)
{
	let (url, recover_codes) = user.reset_otp("issuer", "audience", "password", Some("token from auth app".to_string()), None).await.unwrap();
}
````

### Disable mfa

To disable the mfa use this function:

A totp or recovery key is also needed.

````rust
use sentc::keys::StdUser;

async fn example(user: &mut StdUser)
{
	user.disable_otp("password", Some("token from auth app".to_string()), None).await.unwrap();
}
````

### Get totp recovery keys

To get the recovery keys so the user can later store them:

A totp or recovery key is also needed.

````rust
use sentc::keys::StdUser;

async fn example(user: &StdUser)
{
	let keys = user.get_otp_recover_keys("password", Some("token from auth app".to_string()), None).await.unwrap();
}
````

Alternative you can disable the mfa from your backend, e.g. if the user looses the recovery keys and the device access.

## Register Device

To register a new device, the user must be logged in on another device.
The process has three parts: preparing the data on the new device, sending the data to the logged-in device, and adding
the new device.

To produce the input on the new device, follow these steps. The identifier and password could be generated the same way
as during user registration.

````rust
use sentc::keys::StdUser;

async fn example()
{
	let server_res = StdUser::register_device_start("base_url".to_string(), "app_token", "device_identifier", "device_password").await.unwrap();
}
````

This function will also throw an error if the **username still exists for your app**

Send the Input to the Logged-In Device (possibly through a QR code, which the logged-in device can scan), and call this
function with the input.

````rust
use sentc::keys::StdUser;

async fn example(user: &StdUser, server_res: String)
{
	user.register_device(server_res).await.unwrap();
}
````

This will ensure that only the user's devices have access to the user's data.

After this, the user can log in on the new device.

## Get devices

The device list can be fetched through pagination.

````rust
use sentc::keys::StdUser;

async fn example(user: &StdUser)
{
	let list = user.get_devices(None).await.unwrap();

	//To get more devices use:
	let list = user.get_devices(Some(&list.last().unwrap())).await.unwrap();
}
````

## Change password

The user must enter the old and new passwords.

````rust
use sentc::keys::StdUser;

async fn example(user: &StdUser)
{
	user.change_password("old_password", "new_password", None, None).await.unwrap();
}
````

This function will also throw an error if **the old password was not correct**

If the user enabled mfa then you also need to enter the token or a recovery key.

````rust
use sentc::keys::StdUser;

async fn example(user: &StdUser)
{
	user.change_password("old_password", "new_password", Some("auth_token_if_any".to_string()), None).await.unwrap();

	//with recovery key
	user.change_password("old_password", "new_password", Some("recovery_key".to_string()), Some(true)).await.unwrap();
}
````

## Reset password

To reset a password, the user must be logged in on the device.
A normal reset without being logged in is not possible without losing access to all data because the user must have
access to the device keys.
If the user doesn't have access, they can no longer decrypt the information because the sentc API doesn't have access to
the keys either.

When resetting the password, the secret keys of the device will be encrypted again with the new password.

````rust
use sentc::keys::StdUser;

async fn example(user: &StdUser)
{
	user.reset_password("new_password").await.unwrap();
}
````

## Reset user password with data loss

To reset the user password from your backend call this endpoint.

- `https://api.sentc.com/api/v1/user/forced/reset_user` with a put request
- the data is the same string that the user got from the `prepareRegister` function.
- All user devices will be deleted and the user can't decrypt any of the old data or any of the data inside groups but
  the user stays in all groups.
- The user has to be re invited to all groups

## Update user or device identifier

This will change the user identifier. The function will throw an error if the identifier is not available.
Only the identifier of the actual device will be changed.

````rust
use sentc::keys::StdUser;

async fn example(user: &mut StdUser)
{
	user.update_user("new_user_name".to_string()).await.unwrap();
}
````

This function will also throw an error if **the identifier still exists for your app**

## Delete device

To delete a device, a device password from any device and the device ID are needed.
The ID can be obtained from the user data or by fetching the device list.

````rust
use sentc::keys::StdUser;

async fn example(user: &StdUser, device_id: &str)
{
	user.delete_device("password", device_id, None, None).await.unwrap();
}
````

This function will also throw an error if **the password was not correct**

If the user enabled mfa then you also need to enter the token or a recovery key.

````rust
use sentc::keys::StdUser;

async fn example(user: &StdUser, device_id: &str)
{
	user.delete_device("password", device_id, Some("auth_token_if_any".to_string()), None).await.unwrap();

	//with recovery key
	user.delete_device("password", device_id, Some("recovery_key".to_string()), Some(true)).await.unwrap();
}
````

Get the device id from the user data:

````rust
use sentc::keys::StdUser;

fn example(user: &StdUser)
{
	let device_id = user.get_device_id();
}
````

## Delete account

To delete the entire account, use any device password.

````rust
use sentc::keys::StdUser;

async fn example(user: &StdUser)
{
	user.delete("password", None, None).await.unwrap();
}
````

This function will also throw an error if **the password was not correct**

If the user enabled mfa then you also need to enter the token or a recovery key.

````rust
use sentc::keys::StdUser;

async fn example(user: &StdUser)
{
	user.delete("password", Some("auth_token_if_any".to_string()), None).await.unwrap();

	//with recovery key
	user.delete("password", Some("recovery_key".to_string()), Some(true)).await.unwrap();
}
````

## Public user information

Only the newest public key is used. You can just fetch the newest public key or a verify key by id.

Public key:

````rust
use sentc::keys::StdUser;

async fn example(user: &StdUser, user_id: &str)
{
	let public_key = user.get_user_public_key_data(user_id).await.unwrap();
}
````

Verify Key:

This key can only be fetched by id because to verify data you need a specific verify key.

````rust
use sentc::keys::StdUser;
use sentc::crypto_common::user::UserVerifyKeyData;

async fn example(user: &StdUser, user_id: &str, verify_key_id: &str)
{
	let verify_key: UserVerifyKeyData = user.get_user_verify_key_data(user_id, verify_key_id).await.unwrap();
}
````

## Create safety number

A safety number (or public fingerprint) can be used to check if another user is the real user.
Both users can create a safety number with each other and can then check if the number is the same.
This check should be done live in person or via video chat.

````rust
use sentc::keys::StdUser;
use sentc::crypto_common::user::UserVerifyKeyData;

fn example(user: &StdUser, other_user_id: &str, other_user_key: &UserVerifyKeyData)
{
	let number = user.create_safety_number_sync(Some(other_user_id), Some(other_user_key)).unwrap();
}
````

The other side:

````rust
use sentc::keys::StdUser;
use sentc::crypto_common::user::UserVerifyKeyData;

fn example(user: &StdUser, first_user_id: &str, first_user_key: &UserVerifyKeyData)
{
	let number2 = user.create_safety_number_sync(Some(first_user_id), Some(first_user_key)).unwrap();
}
````

## Verify a users public key

To make sure that the public key which is used to encrypt the group keys really belongs to the user, this key can be
verified.
A safety number can be helpful to check if the verify key is the right one.

````rust
use sentc::keys::StdUser;

async fn example(user: &StdUser, user_id: &str)
{
	//fetch a public key of a user
	let public_key = user.get_user_public_key_data(user_id).await.unwrap();

	let verify = StdUser::verify_user_public_key("base_url".to_string(), "app_token", user_id, &public_key).await.unwrap();
}
````

To check the right verify key of this public key the user can get it:

````rust
use sentc::keys::StdUser;
use sentc::crypto_common::user::{UserVerifyKeyData, UserPublicKeyData};

async fn example(user: &StdUser, user_id: &str)
{
	//fetch a public key of a user
	let public_key: UserPublicKeyData = user.get_user_public_key_data(user_id).await.unwrap();

	//is an Option
	let verify_key_id = public_key.public_key_sig_key_id.unwrap();

	let verify_key: UserVerifyKeyData = user.get_user_verify_key_data(user_id, verify_key_id).await.unwrap();

	//create a safety number with this key
	let number = user.create_safety_number_sync(Some(user_id), Some(&verify_key)).unwrap();

	let verify = StdUser::verify_user_public_key("base_url".to_string(), "app_token", user_id, &public_key).await.unwrap();
}
````

## Key rotation

Just like in groups, users can also do a key rotation. New keys are generated and used and the old will only use the
decrypt all data.

The rotation can be started from any device and needs to finish on the other devices so that they got the new keys too.

To start it:

````rust
async fn start_rotation(user: &mut StdUser)
{
	user.key_rotation().await.unwrap();
}
````

After the rotation use this function to get the new keys for the other devices:

````rust
async fn finish_rotation(user: &mut StdUser)
{
	user.finish_key_rotation().await.unwrap();
}
````