# Application

## Create an account

1. Got to [https://api.sentc.com/dashboard/register](https://api.sentc.com/dashboard/register) and fill in the account information:
- Email
- First name
- Last name
- Company (optional)

2. Choose a password
3. Confirm the password
4. Fill out the captcha to prove that you are not a bot
5. Click register

After registration, you will receive an email. Please click on the link in the email to verify your email address.

Then you are ready to create applications.

## Create an app

1. When you are on the main dashboard page, click on the "New App" button in the right corner.
2. Choose an app name (the name will be displayed on the dashboard to make it easier to find your app).
3. Optionally, you can change the app options or file options. To change the app options, click on the app options name and then the options panel will open. The same goes for file options. By default, files are disabled and only user register and user delete are accessible with your secret token. See "App options" for more information.
4. After creating the app, you will receive your app tokens (public and secret) and jwt keys (sign and verify). You can download every important key and token as a .env file.

## App tokens and keys

After registration, you will get your app tokens and the jwt keys.

### Jwt keys

With the jwt keys you can create a jwt which is valid for your app at the sentc api (with the sign key) or verify a jwt (with the verify key).
The jwt is structured the following:

````json lines
{
    aud: string,
    sub: string,
    exp: number,
    iat: number,
	group_id: string,
	fresh: boolean
}
````

- aud is the user id
- sub is the device id
- group_id is the user device group (this value can be ignored)
- fresh, after login the user will get a fresh token. When the tokens refresh, 
the jwt is not fresh anymore. A fresh jwt is needed to delete a user, but the sdk will log in the user again before delete to get a fresh jwt

### App tokens

The public app token is used to access the API via the frontend, while the secret token is used for backend access. 
After creation, app tokens are hashed and cannot be recovered. 
To renew your app tokens, please remember to update the public app token for your SDK as well.


## App options

With app options, you can control which token can access which endpoint. 
By default, the public token can access every endpoint except for register and delete user. 
As Sentc only stores the required data, which includes only the username and encrypted keys, 
you may require additional information from your users, such as an email address or their full name.

To change the options, simply click on the row of the endpoint and choose public, secret, or block (which means no token can access this endpoint).

Additionally, you can choose other quick options by clicking on the "LAX" button to allow the public token access to all endpoints.

## App file options

By default, file handling is disabled.

However, if you choose to use the Sentc API storage option, no additional configuration is required on your end.

### Own backend

Using your own backend enables you to store files on your own storage system, 
so you don't need to pay for our storage services. 
To use this option, please set the files delete endpoint on your backend. 
We will call this endpoint with a delete request, 
passing the names of the deleted file parts in a JSON array in the request body.


````json
["name_0", "name_1", "name_2"]
````

Each file is divided into multiple parts, each with its own unique ID. These IDs are passed in an array.

As we use a worker to delete files, multiple file parts can be deleted at once.

You can also set a token to ensure that the delete request comes from the Sentc API for your files.

For more information about file handling in Sentc, please refer to the [Files](/guide/file/) section.

## Groups (Beta)

To work with others on an app, there are groups where all group member got access to the app secrets, but only high rak member can edit or delete apps.

An app can be created in a group just like in your account.

1. Login to your dashboard
2. In the upper left corner click on the `GROUPS` tab
3. Click on `NEW GROUP` to create a new group
4. Optional give the group a name and a description
5. Now the group shows up in your dashboard

To create an app in this group use the `NEW APP IN GROUP` button

### Manage member

- To go to the member click on the member icon in the top right corner next to the group name.
  1. In the member list click `INVITE MEMBER`
  2. Pass in the user id and optional a rank of the user. The rank can be changed later on. The user id is in the user's menu (the cog symbol in the right corner)
  3. Click on invite. Now the member is successfully added to your member list.
- To kick a member
  1. click on the pencil icon of the corresponding member
  2. click on kick member
  3. In this window you can also change the rank. This is only possible when you are the admin of this group.

To change the group name or description, go to the pencil icon next to the member icon. In this window you can also delete the group.