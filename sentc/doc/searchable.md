# Searchable encryption

When the data is fully end-to-end encrypted, nobody even the server can decrypt and read / analyse the data.
This makes it very hard to query the data without loading everything all at once, decrypt in the client and then fulfill
the query.

With Sentc you can create searchable encryption from your keywords.

Hmac is used to create hashes from the keywords in the client, which can then be searched.
Hmac makes it also harder to re calculate the hash.

Searchable is only possible for groups.

You can choose if you want to hash the full keyword or each character.

Hashing the full word can be helpful if you want to store credit-card numbers.
In this case you will only find a match if you pass in the full number

When hashing each character you can search for similar results.
You can also set a limit of how many characters will be hashed.
For no limit, all characters will be hashed.
It will only find words from the start to bottom, the word smart and smith will be

- matched for: `s` or `sm`
- but not for: `m` or `t`.

Unlike the sortable encryption, this technic can also be used to encrypt sensible data.
For sortable encryption, only the first 4 letters are encrypted, here the full string can be encrypted.

This is only a one-way process. You can't get the plain text back.
You can use it alongside with symmetric group encryption, encrypt the data with the group key and also hash the data.
The group members are still able to decrypt the data, and you can search it in your backend.

## Create

You get a list or any array of hashes back. This contains the hash of each letter combination of your string.

You can store the hashes in your database in a different table like this:

| item_id                   | hash                       |
|---------------------------|----------------------------|
| `your id to an item`      | `hash of the item`         |
| `your id to an item`      | `another hash of the item` |
| `your id to another item` | `hash of the other item`   |

The relationship should be 1:n (one to many) because one hash should only belong to one item but an item can have
multiple hashes.

The length of a hash is 32 bytes, so a varchar(32) should be great.

For sql databases, bulk insert (multiple rows at once insert) should be used for the hashes.

````rust
use sentc::keys::StdGroup;

fn example(group: &StdGroup, data: &str)
{
	let hashes = group.create_search_raw(data, false, None).unwrap();
}
````

To get more information about how the value is encrypted, you can use this function instead:

````rust
use sentc::keys::StdGroup;

fn example(group: &StdGroup, data: &str)
{
	let out = group.create_search(data, false, None).unwrap();
}
````

## Search a value

The sdk will create a hash with the same group key for your search term, and now you can check it in your database with
the hashes table.
If you are using primary keys for the hash and the item id the search is very quick.

````rust
use sentc::keys::StdGroup;

fn example(group: &StdGroup, data: &str)
{
	let hash = group.search(data).unwrap();
}
````

Now you can search it in your db like this:

```sql
SELECT <your_columns>
FROM <your_item_table> i, <your_hash_table> ih
WHERE
	ih.hash = ?
  AND ih.item_id = i.id
ORDER BY...LIMIT...
```

For this query you will get a list of all matched hashes.

## Options

You can also limit the number of hashes of a word (e.g. only the first 4 combinations) or just hash the full word
without letter combinations.
This works for both, the raw and the normal functions.

### Full word hash

````rust
use sentc::keys::StdGroup;

fn example(group: &StdGroup, data: &str)
{
	let hashes = group.create_search_raw(data, true, None).unwrap();
}
````

Now the length of the hashes is only one.

### Hash a limit letter combination

````rust
use sentc::keys::StdGroup;

fn example(group: &StdGroup, data: &str)
{
	let hashes = group.create_search_raw(data, false, Some(4)).unwrap();
}
````

Now the length of the hashes is maximal 4.

## Going further

You can also set a boolean flag in your hashes table for the last hash of a word.
The last item in the hashes list is also the hash of the exact word.

This helps to do queries where you need the equal value and not all values like this.

| item_id                   | hash                       | last  |
|---------------------------|----------------------------|-------|
| `your id to an item`      | `hash of the item`         | false |
| `your id to an item`      | `another hash of the item` | true  |
| `your id to another item` | `hash of the other item`   | false |

If you want to only got the exact values test if the last is true.

With search and sortable encryption you got now everything you need to query your data without decrypting it first.