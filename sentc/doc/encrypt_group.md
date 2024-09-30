# Encrypt for a group

When encrypting content for a group, the content will be encrypted using the group's current key.
In the event of a key rotation, the new group key will be used to encrypt new content,
while the previous key can still be used to decrypt previously encrypted content.

Sentc will handle key management for you, determining which key should be used for encryption and which key should be
used for decryption.

## Encrypt raw data

Raw data are bytes (&[u8]).

````rust
use sentc::keys::StdGroup;

fn example(group: &StdGroup, data: &[u8])
{
	let encrypted = group.encrypt_sync(data).unwrap();
}
````

## Decrypt raw data

For groups this is the same way around like encrypting data. Every group member can encrypt the data.

````rust
use sentc::keys::StdGroup;

fn example(group: &StdGroup, data: &[u8])
{
	let decrypted = group.decrypt_sync(data, None).unwrap();
}
````

## Encrypt strings

Encrypting strings is a special case, as it requires converting the text to bytes using an UTF-8 reader before
encryption.

To simplify this process, Sentc offers string encryption functions that handle this conversion for you.

````rust
use sentc::keys::StdGroup;

fn example(group: &StdGroup, data: &str)
{
	let encrypted = group.encrypt_string_sync(data).unwrap();
}
````

## Decrypt strings

The same as decrypt raw data but this time with a string as encrypted data.

````rust
use sentc::keys::StdGroup;

fn example(group: &StdGroup, data: &str)
{
	let decrypted = group.decrypt_string_sync(data, None).unwrap();
}
````

## Sign and verify the encrypted data

Sentc offers the ability to sign data after encryption and verify data before decryption.
This ensures the authenticity of the encrypted data and protects against potential tampering.

### Sign

For sign, the newest sign key of the user is used.

For the rust version you need to get the sign key from the user.

````rust
use sentc::keys::StdGroup;

fn example(group: &StdGroup, data: &str)
{
	let encrypted = group.encrypt_string_with_sign_sync(data, user_sign_key).unwrap();
}
````

### Verify

For verify, the right verify key needs to be fetched first.

````rust
use sentc::keys::StdGroup;

fn example(group: &StdGroup, data: &str)
{
	let decrypted = group.decrypt_string_sync(data, Some(user_verify_key)).unwrap();
}
````