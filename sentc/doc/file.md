# File handling

File handling will be available after the beta.

Handling large encrypted files can be difficult, especially in the browser.

Large files are generally too big to encrypt all at once and can potentially overload system memory.
To solve this issue, one solution is to use a stream to encrypt and decrypt files one piece at a time.
However, browsers cannot send file streams through requests.

Another solution is to chunk the file into smaller pieces and encrypt each piece before sending it to storage.
This allows encrypted files to be sent from the browser, but requires managing multiple files instead of just one.
In addition to handling uploads, file deletion must also be managed, including deleting the individual pieces.

::: tip Sentc solution

Sentc offers a solution for handling large encrypted files.
In the client, Sentc chunks the file and encrypts each piece.
These encrypted pieces are then sent to our API storage or your storage.

We save all the part IDs associated with your file, allowing you to fetch the complete file from our backend as if it
were a single file.
Additionally, you can delete the file as if it were a single file, and Sentc will manage the deletion of the individual
encrypted pieces.

## Encrypt and upload a file

With Sentc, files can be encrypted for a group or for a single user.
We recommend encrypting files for a group, as this allows all group members to download and decrypt the file.

For each file, Sentc creates a new key that is used for encryption. To encrypt and upload a file for a group, follow
these steps:

It is important to store the `file id` to fetch the file later.

````rust
use sentc::keys::StdGroup;

async fn example(group: &StdGroup, jwt: &str, file: File)
{
	let output = group.create_file_with_file(jwt, file, None, None, None).await.unwrap();
}
````

For another user:

````rust
use sentc::keys::StdUser;

async fn example(user: &StdUser, file: File)
{
	let output = user.create_file_with_file(file, None, None, false).await.unwrap();
}
````

Create a file with a path:

````rust
use sentc::keys::StdGroup;

async fn example(group: &StdGroup, jwt: &str, path: &str)
{
	let output = group.create_file_with_path(jwt, path, None, None).await.unwrap();
}
````

For another user:

````rust
use sentc::keys::StdUser;

async fn example(user: &StdUser, path: &str)
{
	let output = user.create_file_with_path(path, None, None).await.unwrap();
}
````

To also sign a file, set the 'sign' parameter to 'true' in the function. This will use the user's sign key.
Note that this is not necessary when handling files only within your application and not from any other apps.

When downloading and verifying the file, you will also need to store the user ID to fetch the right verify key.

````rust
use sentc::keys::StdGroup;

async fn example(group: &StdGroup, jwt: &str, file: File)
{
	let output = group.create_file_with_file(jwt, file, None, None, Some(sign_key)).await.unwrap();
}
````

For another user:

````rust
use sentc::keys::StdUser;

async fn example(user: &StdUser, file: File)
{
	let output = user.create_file_with_file(file, None, None, true).await.unwrap();
}
````

To see the actual upload progress pass in the create file function a closure:

````rust
use sentc::keys::StdGroup;

async fn example(group: &StdGroup, jwt: &str, file: File)
{
	let output = group.create_file_with_file_and_upload_progress(jwt, file, None, None, None, |progress| {
		//do something with the progress
	}).await.unwrap();
}
````

## Download and decrypt a file

To download a file, simply use its file ID.
The file key may be encrypted using either another created key or a group key.
The file creator will always provide you with the master key ID.

````rust
use sentc::keys::StdGroup;

async fn example(group: &StdGroup, jwt: &str, file: File)
{
	let output = group.download_file(jwt, file, "file_id", None, None).await.unwrap();
}
````

Download file for another user:

````rust
use sentc::keys::StdUser;

async fn example(user: &StdUser, file: File)
{
	let output = user.download_file(file, "file_id", None, None).await.unwrap();
}
````

To also verify the file by put in the right verify key. Make sure you save the user id from the creator of the file when
uploading a file.

````rust
use sentc::keys::StdGroup;

async fn example(group: &StdGroup, jwt: &str, file: File)
{
	let output = group.download_file(jwt, file, "file_id", Some(verify_key), None).await.unwrap();
}
````

To see the actual download progress pass in the download file function a closure:

````rust
use sentc::keys::StdGroup;

async fn example(group: &StdGroup, jwt: &str, file: File)
{
	let output = group.download_file_with_progress(jwt, file, "file_id", |progress| {
		//do something with the progress
	}, None, None).await.unwrap();
}
````

## Delete a file

Just pass in the file id of the file to delete.

````rust
use sentc::keys::StdGroup;

async fn example(group: &StdGroup, jwt: &str)
{
	let output = group.delete_file(jwt, "file_id").await.unwrap();
}
````

## Setting up your storage

In the App options, you can choose to use your own storage for file upload and download.
By default, the SDK uses sentc storage, and you are charged per GB per month for its usage.

If you have your own storage solution, such as AWS S3, you can simply update the `delete`, `download` and `upload` URLs
to point to your own storage.
This will allow all file parts to be uploaded and downloaded directly from your storage.

If a file is deleted, we will call your backend storage to delete the corresponding file.
The delete process can be stacked to delete multiple files at once.

In summery:

1. Set up your own upload and download endpoints in the app options within the SDK.
2. Configure your upload endpoint to receive multiple parameters through the URL.
3. Call the sentc API to register the file part, and you will receive an ID that can be used to delete the file part.
4. Set up the delete endpoint and an optional token in your app's file options within the dashboard.

In rust, you need to pass in the url with the parameter:

````rust
use sentc::keys::StdGroup;

async fn example(group: &StdGroup, jwt: &str, file: File)
{
	let output = group.download_file(jwt, file, "file_id", None, Some("file_url")).await.unwrap();
}
````

We use the same URL for both upload and download, but with different HTTP methods:

- Upload: Method post
- Download: Method get

To update your URL, simply set the file part URL in the options.
The uploader will automatically upload the parts to the new URL,
and the downloader will attempt to download the parts from the new URL.

Please ensure that you transfer your data to the new URL.

### When uploading file parts to your url, register the file part at sentc api

Call this endpoint when the upload is done:

- `https://api.sentc.com/api/v1/file/part/<session_id>/<file_part_sequence>/<end>/<user_id>`

This endpoint needs your secret token and should only be called from your backend.
See [own backend](/guide/advanced/backend-only) for sending the token as header.

```
Header name: x-sentc-app-token
Header value: <your_app_token>
```

- session_id is the id of the file upload session, this is a string.
- file_part_sequence is the sequence of the file part when downloading and decrypting the file. if this is wrong then
  the file can't be decrypted anymore.
- end is a boolean. Pass in false if the file upload has not finished yet or true if it is.
- user_id is the user that uploaded the file.

The sdk will call your endpoint with these values in the url as parameter and the user id from the user jwt or
elsewhere.
A request might look like:

- `https://your_url.com/<session_id>/<file_part_sequence>/<end>`
- or `https://your_url.com/abc_123/0/false`
- or `https://your_url.com/abc_123/1/true`

Just extract the values and call the sentc api to register the file part, so sentc can download the file.
In the example above:

- `https://api.sentc.com/api/v1/file/part/abc_123/0/false/<user_id>`
- and `https://api.sentc.com/api/v1/file/part/abc_123/1/true/<user_id>`

### After calling the sentc api you will get back the file part id

This id is used to fetch and delete a part.
Please store the id or rename your file part to this id.

Return the success result as json to the sdk: `{"status":true,"result":"Success"}`.

### Alternative workflow

You can also call the sentc api first to register a part and then read the request body.
Then you will get the right id, and you can name your file correctly.

### Set to delete endpoint for file parts

This endpoint will be called with a `post` request and the deleted file part names in the body as json array:

````json
[
	"name_0",
	"name_1",
	"name_2"
]
````

You can also set a token for us, so you know that the request comes really from our api to delete the files.

### When downloading a part the part id is in the url

The sdk will call your endpoint with a get request and the part id in the url.
And except the encrypted file part as bytes.

`https://your_url.com/<part_id>`