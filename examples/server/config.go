package main

import (
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"strconv"
	"time"

	"github.com/gorilla/sessions"
	"github.com/jmoiron/sqlx"
	"github.com/markbates/goth"
	"github.com/markbates/goth/gothic"
	"github.com/markbates/goth/providers/google"
	"github.com/markbates/goth/providers/twitter"
	"github.com/rs/zerolog"
	"gopkg.in/mail.v2"
	"gopkg.in/natefinch/lumberjack.v2"
)

type appconfig struct {
	port           int
	apiURL         string
	webURL         string
	logDir         string
	logFileName    string
	logFileMaxSize int
	logLevel       zerolog.Level
	dbdsn          string
}

type oathsecret struct {
	clientID     string
	clientSecret string
}
type oathconfig struct {
	callbackURL  string
	secureCookie bool
	google       oathsecret
	twitter      oathsecret
}

type smtpconfig struct {
	host   string
	port   int
	user   string
	pass   string
	sender string
}

type config struct {
	app  appconfig
	auth oathconfig
	smtp smtpconfig
}

func mustConfig() config {
	return config{
		app: appconfig{
			port:           envIntMust("EXAMPLE_PORT"),
			apiURL:         envStrMust("EXAMPLE_API_URL"),
			webURL:         envStrMust("EXAMPLE_WEB_URL"),
			logDir:         envStrMust("EXAMPLE_LOG_DIR"),
			logFileName:    envStrMust("EXAMPLE_LOG_FILE_NAME"),
			logFileMaxSize: envIntMust("EXAMPLE_LOG_FILE_MAX_SIZE"),
			logLevel:       envLogDefault("EXAMPLE_LOG_LEVEL", "info"),
			dbdsn:          envStrMust("EXAMPLE_DB_DSN"),
		},
		auth: oathconfig{
			callbackURL:  envStrMust("EXAMPLE_API_URL"),
			secureCookie: envBlnMust("EXAMPLE_OAUTH_SECURE_COOKIE"),
			google: oathsecret{
				clientID:     envStrMust("EXAMPLE_OAUTH_GOOGLE_CLIENT_ID"),
				clientSecret: envStrMust("EXAMPLE_OAUTH_GOOGLE_CLIENT_SECRET"),
			},
			twitter: oathsecret{
				clientID:     envStrMust("EXAMPLE_OAUTH_TWITTER_CLIENT_ID"),
				clientSecret: envStrMust("EXAMPLE_OAUTH_TWITTER_CLIENT_SECRET"),
			},
		},
		smtp: smtpconfig{
			host:   envStrMust("EXAMPLE_SMTP_HOST"),
			port:   envIntMust("EXAMPLE_SMTP_PORT"),
			user:   envStrMust("EXAMPLE_SMTP_USERNAME"),
			pass:   envStrMust("EXAMPLE_SMTP_PASSWORD"),
			sender: envStrMust("EXAMPLE_SMTP_SENDER"),
		},
	}
}

type logwrap struct {
	logger zerolog.Logger
	roller *lumberjack.Logger
}

func (l logwrap) Close() error {
	if l.roller != nil {
		return l.roller.Close()
	}
	return nil
}

func newLogger(c appconfig) (*logwrap, error) {
	var (
		writer  io.Writer
		logwrap logwrap
	)

	if c.logLevel == zerolog.DebugLevel {
		writer = zerolog.ConsoleWriter{Out: os.Stdout}
	} else {
		if err := os.MkdirAll(c.logDir, 0744); err != nil {
			return nil, err
		}
		roller := lumberjack.Logger{
			Filename:   fmt.Sprintf("%s/%s", c.logDir, c.logFileName),
			MaxBackups: 4,
			MaxSize:    c.logFileMaxSize,
			MaxAge:     30,
		}
		writer = &roller
		logwrap.roller = &roller
	}

	logwrap.logger = zerolog.New(writer).With().Timestamp().Logger().Level(c.logLevel)
	return &logwrap, nil
}

func newDB(c appconfig) (*sqlx.DB, error) {
	db, err := sqlx.Connect("pgx", c.dbdsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(25)
	db.SetConnMaxIdleTime(time.Minute * 15)
	return db, nil
}

func newSMTPDialer(c smtpconfig) *mail.Dialer {
	dialer := mail.NewDialer(c.host, c.port, c.user, c.pass)
	dialer.Timeout = 20 * time.Second
	return dialer
}

func setupOAuth(c oathconfig) error {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	if err != nil {
		return fmt.Errorf("cant generate auth key: %s", err)
	}

	store := sessions.NewCookieStore(key)
	store.MaxAge(300)
	store.Options.Path = "/"
	store.Options.HttpOnly = true
	store.Options.Secure = c.secureCookie
	gothic.Store = store

	goth.UseProviders(
		google.New(
			c.google.clientID,
			c.google.clientSecret,
			fmt.Sprintf("%s/api/v1/auth/google/callback", c.callbackURL),
		),
		twitter.New(
			c.twitter.clientID,
			c.twitter.clientSecret,
			fmt.Sprintf("%s/api/v1/auth/twitter/callback", c.callbackURL),
		),
	)
	return nil
}

//
//
//

func envStrMust(key string) string {
	val := os.Getenv(key)
	if val == "" {
		panic("env variable " + key + " must be provided")
	}
	return val
}
func envIntMust(key string) int {
	str := envStrMust(key)
	val, err := strconv.ParseInt(str, 10, 0)
	if err != nil {
		panic("env variable " + key + " must be integer")
	}
	return int(val)
}
func envBlnMust(key string) bool {
	str := envStrMust(key)
	val, err := strconv.ParseBool(str)
	if err != nil {
		panic("env variable " + key + " must be true or false")
	}
	return val
}

func envStrDefault(key string, def string) string {
	val := os.Getenv(key)
	if val == "" {
		return def
	}
	return envStrMust(key)
}
func envLogDefault(key string, def string) zerolog.Level {
	str := envStrDefault(key, def)
	lvl, err := zerolog.ParseLevel(str)
	if err != nil {
		panic("env variable " + key + " must be valid log level")
	}
	return lvl
}
