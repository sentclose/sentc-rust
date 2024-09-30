# Encrypt for a user

When encrypting content for a user, the content is encrypted using the user's public key.
However, it is important to note that public/private key encryption may not be suitable for handling large amounts of
data.
To address this, best practice is to use a symmetric key to encrypt the content,
and then encrypt the symmetric key with the user's public key (as with groups).

When encrypting content for a user, the reply user ID is required.

We highly recommend creating a group even for one-on-one user communication.
This allows the user who encrypts the data to also decrypt it later without any additional configuration.
To achieve this, simply auto-invite the other user and use the "stop invite" feature for this group.

For more information on auto-invite functionality, please see the auto invite section.

## Encrypt raw data

Raw data are bytes (&[u8]).

````rust
use sentc::keys::StdUser;

fn example(user: &StdUser, data: &[u8])
{
	let encrypted = user.encrypt_sync(data, user_public_key, false).unwrap();
}
````

## Decrypt raw data

For user this is a little more complicated. Only the user which user id was used in encrypt can decrypt the content.

Raw data are bytes (&[u8]).

````rust
use sentc::keys::StdUser;

fn example(user: &StdUser, encrypted: &[u8])
{
	let decrypted = user.decrypt_sync(encrypted, None).unwrap();
}
````

## Encrypt strings

Encrypting strings is a special case, as it requires converting the text to bytes using an UTF-8 reader before
encryption.

To simplify this process, Sentc offers string encryption functions that handle this conversion for you.

````rust
use sentc::keys::StdUser;

fn example(user: &StdUser, data: &str)
{
	let encrypted = user.encrypt_string_sync(data, user_public_key, false).unwrap();
}
````

## Decrypt strings

The same as decrypt raw data but this time with a string as encrypted data.

````rust
use sentc::keys::StdUser;

fn example(user: &StdUser, encrypted: &str)
{
	let decrypted = user.decrypt_string_sync(encrypted, None).unwrap();
}
````

## Sign and verify the encrypted data

Sentc offers the ability to sign data after encryption and verify data before decryption.
This ensures the authenticity of the encrypted data and protects against potential tampering.

### Sign

For sign, the newest sign key of the user is used.

````rust
use sentc::keys::StdUser;

fn example(user: &StdUser, data: &str)
{
	let encrypted = user.encrypt_string_sync(data, user_public_key, true).unwrap();
}
````

### Verify

For verify, the right verify key needs to be fetched first.

````rust
use sentc::keys::StdUser;

fn example(user: &StdUser, encrypted: &str)
{
	let decrypted = user.decrypt_string_sync(encrypted, Some(user_verify_key)).unwrap();
}
````