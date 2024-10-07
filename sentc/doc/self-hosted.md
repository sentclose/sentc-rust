# Self-hosting

The sdk connects to an api.
The api will store the encrypted user and group keys and will also manage the key rotation and group member.

## Docker

You can choose docker to run the api. To get started, download the [sentc/hosting](https://github.com/sentclose/hosting)
repo.
It contains basic docker-compose to get the server running.

```bash
git clone https://github.com/sentclose/hosting
cd hosting
```

Next copy and rename `.env.sample` to `.env` and `sentc.env.sample` to `sentc.env`

The `.env` file contains config about the used container. You can change the version of each container.

Optional but recommended: Change the mysql env too.

Next you have to create a root key with the `sentc key gen tool` and paste it into `ROOT_KEY` in the `sentc.env` file.

#### Root key generation

You can use the docker image to generate a key:

```bash
docker-compose -f key_gen/docker-compose.yml up
```

Without the -d flag to get the key output. Copy your key, and then you can down the container:

```bash
docker-compose -f key_gen/docker-compose.yml down -v
```

And delete the image

```bash
docker image rm sentc/key_gen
```

### Start

The default is mariadb with redis server.

```bash
docker-compose -f mysql/docker-compose.yml up -d
```

Now everything is running and you can start.

### Non default

If you are using an external Database, or a Database which is running native, then use
the `mysql/docker-compose.stand_alone.yml` file.

Before starting set also the both Env: `MYSQL_HOST` (your host where the db is running), `MYSQL_DB` (the database name).

```bash
docker-compose -f mysql/docker-compose.external_db.yml up -d
```

Keep in mind that this will use the array cache as default not redis. If you have redis also running, set the
Env `CACHE` to 2
and the Env `REDIS_URL` to your running redis url instance.

To use the sqlite container use this compose file:

```bash
docker-compose -f sqlite/docker-compose.yml up -d
```

This will start the sqlite version of the api. Make sure to place in the sqlite database in the folder: `db/sqlite`.
You can get it from the [api repo](https://github.com/sentclose/sentc-api/blob/master/db/sqlite/db.sqlite3).

### Server

This hosting approach not be directly access from the outside. Use a reverse proxy like nginx to handle tls.
Sentc itself will use http.

```text
server {
    client_max_body_size 6m;    # to make sure the file upload works
    
    server_name <your_server_name>
    
    location / {
        proxy_pass http://localhost:3002; # redirect to your running docker container. Sentc uses port 3002 as default.
        proxy_http_version 1.1;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For  $proxy_add_x_forwarded_for;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
    }
}
```

## SDK change

Set the base_url option in your SDK init to your hosted version to make sure that the sentc backend is not used.

For rust sdk set it everywhere in the code where it is asked for the base_url like StdUser::register("base_url",...).

## Register a self-hosted app

You can access your dashboard by going to your address where your instance running.
Then simply follow the register an app.

Use your public and secret token from this app.

### Disable app creation

Now the registration is still open for everyone. Set the Env `CUSTOMER_REGISTER` to `0` in your `sentc.env` file and
restart your docker container.
Now none can create a new account and register apps except your account.

```bash
docker-compose -f mysql/docker-compose.yml stop
```

And then start again.