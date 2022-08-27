# auth

A little auth package.

### Running Example Server
- `brew install golang-migrate`
- create a .env file, then set `MIGRATE_DB_DSN` variable and other variables defined in the config.go file.
- `make migrations/up`
- `make examples/server/run`

Here is a sample .env file:

```
EXAMPLE_PORT=9000
EXAMPLE_API_URL=http://localhost:9000
EXAMPLE_WEB_URL=http://localhost:9000
EXAMPLE_LOG_DIR=./logs
EXAMPLE_LOG_FILE_NAME=app.log
EXAMPLE_LOG_FILE_MAX_SIZE=100
EXAMPLE_LOG_LEVEL=debug
EXAMPLE_DB_DSN=root:1@tcp(localhost:3306)/example?parseTime=true

EXAMPLE_OAUTH_SECURE_COOKIE=false
EXAMPLE_OAUTH_GOOGLE_CLIENT_ID=<client_id>
EXAMPLE_OAUTH_GOOGLE_CLIENT_SECRET=<client_secret>
EXAMPLE_OAUTH_TWITTER_CLIENT_ID=<client_id>
EXAMPLE_OAUTH_TWITTER_CLIENT_SECRET=<client_secret>

EXAMPLE_SMTP_HOST=smtp.mailtrap.io
EXAMPLE_SMTP_PORT=2525
EXAMPLE_SMTP_USERNAME=<username>
EXAMPLE_SMTP_PASSWORD=<password>
EXAMPLE_SMTP_SENDER=Example <no-reply@example.com>

MIGRATE_DB_DSN=mysql://root:1@tcp(localhost:3306)/example
```

### References
- https://www.gobeyond.dev/wtf-dial/
- https://lets-go-further.alexedwards.net/