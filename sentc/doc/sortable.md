# Sortable encryption

When the data is fully end-to-end encrypted, nobody even the server can decrypt and read / analyse the data.
To do range queries like sort table by last name the server must know the decrypted value. The encryption only works in
groups.

With the sortable encryption it is not needed anymore.
The encrypted produces numbers which follows the order of the plaintext and can be used with any database or backend.

Like: `encrypt(1)` < `encrypt(2)` < `encrypt(3)` < `encrypt(5000)`

Now it is possible to do range queries or sort rows without decrypt it.

The encryption is not as secure as the symmetric or asymmetric encryption.
This is why sentc never encrypt the whole plaintext.

You can encrypt numbers or strings. Numbers are fully encrypted, for strings only the first 4 characters will be
encrypted and the rest gets ignored.

Use this technic only in combination with the symmetric encryption to encrypt a
value symmetrically so the user can decrypt it and also encrypt it with the sortable encryption to do range queries in
your backend.

## Encrypt a number

The maximum number to encrypt is `65532`.

````rust
use sentc::keys::StdGroup;

fn example(group: &StdGroup)
{
	let a = group.encrypt_sortable_raw_number(262).unwrap();
	let b = group.encrypt_sortable_raw_number(263).unwrap();
	let c = group.encrypt_sortable_raw_number(65321).unwrap();

	//a < b < c
}
````

To get more information about how the value is encrypted, you can use this function instead:

````rust
use sentc::keys::StdGroup;

fn example(group: &StdGroup)
{
	let out = group.encrypt_sortable_number(262).unwrap();
}
````

## Encrypt a string

Only the first 4 characters will be used to encrypt the string the rest will be ignored.

Strings with umlauts or other non english character are not supported. Alternative you can use the english version
like `ö` ot `oe`

But you can write your own function that creates a number and encrypt the number.

````rust
use sentc::keys::StdGroup;

fn example(group: &StdGroup)
{
	let a = group.encrypt_sortable_raw_string("abc", None).unwrap();
	let b = group.encrypt_sortable_raw_string("dfg", None).unwrap();
	let c = group.encrypt_sortable_raw_string("hij", None).unwrap();

	//a < b < c
}
````

To get more information from the encrypted strings use this function:

````rust
use sentc::keys::StdGroup;

fn example(group: &StdGroup)
{
	let out = group.encrypt_sortable_string("abc").unwrap();
}
````