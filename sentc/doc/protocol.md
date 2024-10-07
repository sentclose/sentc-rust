# The Sentc Protocol

The Sentc protocol is designed for asynchronous, long-running communication, specifically optimized for groups of users.
It ensures that users in groups can decrypt the entire communication, even if they join years after it has started.

### Perfect Forward Secrecy (PFS)

In the Sentc protocol, Perfect Forward Secrecy (PFS) is not implemented in the core for specific reasons.

The first challenge with PFS is that it requires synchronous communication, where all users need to be online
simultaneously.
While this approach works well for live-streaming video or TLS (Transport Layer Security),
where every member must be online at the same time, it poses difficulties for asynchronous communication.
The Signal-protocol solve this problem by using pre generated key pairs and use them if the user is offline.

The second challenge with PFS is that new members of a group are unable to decrypt past communications,
or at least cannot decrypt them at a given time.
This can be problematic, especially in scenarios such as a knowledge wiki within a company or chat communication,
where new employees may be unable to access important information for months.

Sentc tackles this problem by implementing key rotation in groups.
Each member of the group receives new keys while retaining the ability to decrypt using the old keys.
When encrypting, the new key is used.
While this solution may not be perfect for one-on-one or live communication, it provides a suitable approach for
asynchronous groups.

## Overview

Sentc utilizes a combination of symmetric and asymmetric encryption algorithms, as well as signing and verification
mechanisms.

It's worth noting that the underlying algorithm used in Sentc can be changed in the future.
Despite such changes, data encrypted with the previous algorithm will still be able to decrypt, ensuring backward
compatibility.
However, any new data will be encrypted using the new algorithm.
This flexibility is particularly valuable as it allows for future-proofing the system against potential quantum attacks.

### The structure

Here are the actual used algorithm.

- symmetric for the data encryption and decryption.
    - aes-gcm 256 bit
- asymmetric for the symmetric key exchange with static key pairs.
    - ecies with x25519
    - CRYSTALS Kyber 768
    - Hybrid with ecies and Kyber (default)
- sign and verify for data integrity
    - ed25519
    - CRYSTALS Dilithium 3
    - Hybrid with ed25519 and Dilithium (default)
- hmac for searchable encryption
    - hmac-sha 256
- password hashing
    - argon2 with argon2id
- sortable encryption
    - ope

## User

A user is defined as a group of devices.
The user-group operates using the same mechanism as a regular group, which will be explained in detail below.
The device's public key is utilized during the creation of the group.

## Device

### Register

A device in Sentc is associated with an identifier, also known as a username, and a password.
The password can be either user-generated or securely generated and stored on the client device.

To protect user information, the identifier is hashed on the API side, ensuring that no sensitive user data is exposed.
Additionally, the password is designed never to leave the device.

Each device is equipped with the following components:

1. Symmetric Master Key: This key is static but can be changed when necessary.
2. Asymmetric Key Pair: Each device possesses a static (yet changeable) asymmetric key pair, comprising a public key and
   a private key.
3. Sign and Verify Key Pair: Similarly, each device has a static (but changeable) sign and verify key pair.

Both the private asymmetric key and the sign key are encrypted using the device's master key, providing an additional
layer of security.

Regarding the password, it is hashed using password hashing algorithms, with the current algorithm being argon2.

#### Argon2 password hashing

1. Create a client random value (crv) (16 bytes for argon2)
2. Generate a salt with crv.
    - The salt contains a padded string (length 200 chars) and the crv.
    - Hash the salt with sha 256
3. Derived a 512 bit long key from the password and the salt
    - use the first half of the derived key as encryption key and the second half as auth key
    - the auth key will be hashed as well
4. Finally, encrypt the master key with the first half of the derived key, the encryption key, via aes-gcm

The following is sent to the server:

- user group data (more see group creation)
- encrypted master key
- device identifier (not hashed at this moment)
- what derived key algorithms was used
- client random value
- hashed auth key
- public key
- encrypted private key
- what algorithms has the asymmetric encryption key pair
- verify key
- encrypted sign key
- what algorithms has the sign/verify key pair

The identifier is hashed on the server via sha 256

### Login

Login is split into three tasks.

#### Prepare the login

During the login process in Sentc, the user first sends the device identifier to the server and receives the
corresponding salt.
The salt is generated on the server side. Here's how the process works:

1. Device Identifier Submission: The user submits the device identifier to the server.

2. Salt Retrieval: If the identifier exists in the server's records, the server generates the salt using the client's
   random value.
    - Existing Identifier: If the identifier exists, the server generates the salt based on the client's random value
      and the matching device registration data.
    - Non-existing Identifier: If the identifier does not exist, a false identifier (for security purposes) is used in
      the padded string, and a generic client random value is utilized to generate a false salt.

3. Salt Transmission: Once generated, the salt is sent back to the client, completing the login preparation stage.

#### Finish the login

At the client the salt is used to derive the encryption and auth key via the password hashing algorithms.
The auth key is not hashed and will be sent to the server. The server hashes the auth key and checks if the hashed key
exists.
If not then the identifier or the password may be wrong.

It is important to not just return false if the identifier not exists to impede password brute force attacks.

If the auth key exists then the server will create a login challenge.
This is a randomly created string which is encrypted by the users device public key (not the user public key) on the
server.
The device keys including: encrypted private keys and the encrypted master key and the challenge are returned to the
client.

The master key will be decrypted by the encryption key from the password and the decrypted master key decrypts the
private keys.

The login challenge will then be decrypted with the decrypted private device key and send back to the server
to verify that the user not only got access to the auth key but also to the master key.

#### Verify Login

After the api verifies the login the server will create a json web token (jwt) and return the jwt, a refresh token and
the user group keys.

With the device private key, the group keys are decrypted.

The jwt can be used to authenticate with the server.

There is no key rotation for a single device but if a device get lost or compromised the device can be deleted
and a key rotation can be done in the user-group for the other devices.

### Safety number / public fingerprint

A user can create a safety number (commonly known as public fingerprint) from its own verify key and another user.
The verify-keys get combined and hashed. The hash is then shown as base64 encoded string.

The user which id comes first in the alphabet will always be the first in the hash.

### Verify public key

The public key of a user is used to encrypt the group keys. To make sure to use the right public key of the real user a
public key can be verified.
The safety number can identify the right verify key and the verify key can verify the public key.

When a user was registered, the user group verifies the public key of the user.
After a user key rotation the new public key will also be verified by the new verify key (in this case a new safety
number is needed).

It is stored on each device if a public key was verified before.
To only allow verified user public keys for groups it can be checked in the client before inviting a new user.

## Groups

Groups use symmetric keys to encrypt content among the members. Every user inside a group can encrypt and decrypt.

There are also a public/private key pair for each group. For user groups there is also a sign/verify key pair.
The private key is encrypted by the group key.

The symmetric group key is encrypted by the public key of the creator of the group.

### Adding more user to a group

Adding more users to a group can be done via join req from the user to the group or invite from the group to the user.
For inviting a user or accepting a join req,
all group symmetric keys are encrypted by the users public key in the client and then send encrypted to the server.
When the new member wants to load the group, the group keys are decrypted by the users private key.

When a user gets kicked out a group, all the encrypted group keys for this user will be deleted as well.
It is recommended to do a key rotation after a user leaves to encrypt newer content with keys that the old user not
have.

### Child and connected groups

When inviting a user, the newest user public key is used to encrypt the group keys.
When creating a child group, the parent group public key is used to encrypt the group keys.
All users for the parent group got access to the private key (by the group key) to decrypt the child group key.
A parent group is like a member in the child group.

For connected groups the group is also a member in the connected group.

### Key rotation

Using just one static symmetric key is not secure.
Sentc provides a key rotation mechanism which is done on the server to relieve the clients.

#### Starting the rotation

This is all done in the client.

1. A new symmetric key, public/private key pair, and for user groups a new sign/verify key pair will be created.
2. Like group create, the private key will be encrypted by the new group key
3. An ephemeral key will be created to encrypt the new group symmetric key
4. The ephemeral key is then encrypted by the previous group key
5. Optional sign the encrypted group key with the user sign key
6. For the invoker the group key is also encrypted by its public key like group invite
7. Send the following to the server:
    - encrypted private key
    - public group key
    - encrypted group symmetric key by the ephemeral key
    - encrypted group key by the invoker public key

#### Server key rotation

This section is done on the server.

1. Insert the group keys
2. Start a background worker to do the key rotation
3. At the worker, fetch the encrypted ephemeral key
4. Fetch the newest public key of first 100 group member (order by joined time)
5. Encrypt the ephemeral key (which was encrypted by the previous group key before) with the public key of each user and
   store the encrypted ephemeral key by the public key.
6. Continue until all member and parent / connected groups are done
7. Delete the encrypted ephemeral key which was encrypted by the previous group key to not leak it for ex-member.

#### Finish the key rotation for the other member in the client

This process is done in the client of the other member.

1. Get the user private key (or group private key in case of parent or connected group), the user public key and the
   previous group key
2. If the encrypted group key was signed then the member can verify the group key
3. Decrypt the encrypted ephemeral key with the users private key (the pair key from the used public key at the server)
4. Decrypt the already decrypted ephemeral key but this time with the previous group key
5. Decrypt the new encrypted group key with the now decrypted ephemeral key
6. Encrypt the new group key with the users public key
7. Send the new encrypted group key by the public key to the server to store it like the keys before

The process for parent and connected groups is the same as for member, but the group public key is used instead of a
user public key.

## File

A file is chunked into parts (each 4 m-bytes). Each part got its own symmetric key.

1. Create a symmetric key. This key is the starting key and is directly linked to the file and will be deleted when file
   is deleted. This key is encrypted by a group key if the file is created in a group, or with the user public key if
   not.
2. Encrypt the first chunk with the new key and create a new symmetric key. Use the initial key to encrypt the created
   file key.
3. Use the next key to encrypt the next part and also create another key and encrypt this key with the key from the part
   before.
4. Do this until all chunks are done

To decrypt a file:

1. Use the initial file key to decrypt the first part and the key for the next part
2. Use the decrypted key to decrypt the next part and its key for the following part
3. Do this until all chunks are decrypted

The file part keys are stored encrypted in the file chunk to load the files independent of sentc backend.