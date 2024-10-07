# Sentc sdk

It supports user- and group management as well as key rotation and its build to serve large amount of users without any
problems.

## Why a new protocol?

- focus on groups
- focus on archive, encrypt once and everyone with access can decrypt it without expensive and complex key exchange
- serverside encrypted key rotation. Much faster than client side rotation.

## Sentc got two components:

- the client sdks to encrypt and decrypt
- the server to handle user auth and groups + key management

### Difference between rust sdk and the other

The other sdk's like javascript or flutter are designed with datastore in mind.
In js it uses the indexeddb in the browser and in flutter the device storage or encrypted storage.

This sdk was designed to use your own storage. This means you need to provide more information for each function than in
the other sdk's.
But this gives you the flexibility to use it in your programs without compromises.

There is no init function anymore. You can just use the functions you need.

## Usage

In all doc examples we are using the StdKeys implementation. You can switch it by changing the features and use other
implementation or even write your own.

### Create an account and an app

To use the sdk, you need a public and secret token.

The public token will be used in your sdk at the frontend and the secret token should only be used at your backend.
You can set what function should be called with which token.

1. Got to [https://api.sentc.com/dashboard/register](https://api.sentc.com/dashboard/register) and create an account.
   You will be redirected to the account dashboard.
2. Verify the email. We email you to make sure that your email address belongs to you.
3. In your dashboard click on the blue button: New App. You will get the app tokens and the first jwt keys.

Now you are ready to use the sdk.

### Install the sdk.

Please choose an implementation of the algorithms. There are StdKeys, FIPS or Rec keys. The impl can not work together.

- StdKeys (feature = std_keys) are a pure rust implementation of the algorithms. They can be used in the web with wasm
  and on mobile.
- FIPS keys (feature = fips_keys) are FIPS approved algorithms used from Openssl Fips. This impl does not support post
  quantum.
- Rec keys (feature = rec_keys) or recommended keys are a mix of FIPS keys for the classic algorithms and oqs (for post
  quantum).

The net feature is necessary for the requests to the backend. The library reqwest is used to do it.

```bash
cargo add sentc
```

````rust
use sentc::keys::{StdUser, StdGroup};

async fn example()
{
	//register a user
	let user_id = StdUser::register("base_url".to_string(), "app_token".to_string(), "the-username", "the-password").await.unwrap();

	//login a user, ignoring possible Multi-factor auth
	let user = StdUser::login_forced("base_url".to_string(), "app_token", "username", "password").await.unwrap();

	//create a group
	let group_id = user.create_group().await.unwrap();

	//get a group. first check if there are any data that the user need before decrypting the group keys.
	let (data, res) = user.prepare_get_group("group_id", None).await.unwrap();

	//if no data then just decrypt the group keys
	assert!(matches!(res, GroupFetchResult::Ok));

	let group = user.done_get_group(data, None).unwrap();

	//invite another user to the group. Not here in the example because we only got one user so far
	group.invite_auto(user.get_jwt().unwrap(), "user_id_to_invite", user_public_key, None).await.unwrap();

	//encrypt a string for the group
	let encrypted = group.encrypt_string_sync("hello there!").unwrap();

	//now every user in the group can decrypt the string
	let decrypted = group.decrypt_string_sync(encrypted, None).unwrap();

	//delete a group
	group.delete_group(user.get_jwt().unwrap()).await.unwrap();

	//delete a user
	user.delete("password", None, None).await.unwrap();
}
````

## Limitations

The protocol is designed for async long-running communication between groups.

- A group member should be able to decrypt the whole communication even if they joined years after the beginning.
- Group member should get decrypt all messages even if they were offline for years.

The both requirements make perfect forward secrecy impossible. See more at the Protocol how we solved it.

## Contact

If you want to learn more, just contact me [contact@sentclose.com](mailto:contact@sentclose.com).
