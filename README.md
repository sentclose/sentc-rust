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

## Install

Please choose an implementation of the algorithms. There are StdKeys, FIPS or Rec keys. The impl can not work together.

- StdKeys (feature = std_keys) are a pure rust implementation of the algorithms. They can be used in the web with wasm
  and on mobile.
- FIPS keys (feature = fips_keys) are FIPS approved algorithms used from Openssl Fips. This impl does not support post
  quantum.
- Rec keys (feature = rec_keys) or recommended keys are a mix of FIPS keys for the classic algorithms and oqs (for post
  quantum).

The net feature is necessary for the requests to the backend. The library reqwest is used to do it.

## Usage

In all doc examples we are using the StdKeys implementation. You can switch it by changing the features and use other
implementation or even write your own.

### Register a user

````rust
use sentc::keys::StdUser;

async fn register()
{
	let user_id = StdUser::register("the-username", "the-password").unwrap();
}
````

### Login a user

````rust
use sentc::keys::StdUser;

async fn login()
{
	let login_res = StdUser::login("base_url".to_string(), "app_token", "username", "password").await.unwrap();
}
````

### Login with ignoring 2fa

````rust
use sentc::keys::StdUser;

async fn login()
{
	let user = StdUser::login_forced("base_url".to_string(), "app_token", "username", "password").await.unwrap();
}
````