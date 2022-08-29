package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/aemdemir/auth/handler"
	"github.com/aemdemir/auth/mailer"
	"github.com/aemdemir/auth/service"
	"github.com/gorilla/mux"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/hlog"

	// postgresql driver
	_ "github.com/jackc/pgx/v4/stdlib"
)

func main() {
	cfg := mustConfig()

	lw, err := newLogger(cfg.app)
	if err != nil {
		panic(err)
	}
	defer lw.Close()

	lw.logger.
		Info().Msg("config loaded")

	db, err := newDB(cfg.app)
	if err != nil {
		panic(err)
	}
	defer db.Close()

	if err := setupOAuth(cfg.auth); err != nil {
		panic(err)
	}

	sv := service.NewService(
		&service.DB{DB: db},
		lw.logger,
		mailer.NewMailer(newSMTPDialer(cfg.smtp), cfg.smtp.sender))

	handler.SetLogger(lw.logger)
	h := handler.New(
		sv,
		lw.logger,
		handler.Config{
			SocialSigninRedirectURL:    fmt.Sprintf("%s/auth/signin_complete", cfg.app.webURL),
			LinkUserAccountRedirectURL: fmt.Sprintf("%s/auth/link_complete", cfg.app.webURL),
		})

	r := routes(h, lw.logger)
	listen(cfg.app.port, r, lw.logger)
}

// routes builds server routes.
func routes(h *handler.Handler, logger zerolog.Logger) http.Handler {
	router := mux.NewRouter()
	h.SetRoutes(router)

	// middleware
	router.Use(hlog.NewHandler(logger))
	router.Use(hlog.AccessHandler(func(r *http.Request, status, size int, duration time.Duration) {
		hlog.FromRequest(r).Info().
			Str("method", r.Method).
			Stringer("url", r.URL).
			Int("status", status).
			Int("size", size).
			Dur("duration", duration).
			Msg("")
	}))
	router.Use(hlog.RemoteAddrHandler("ip"))
	router.Use(hlog.UserAgentHandler("user_agent"))
	router.Use(hlog.RefererHandler("referer"))

	return h.Recoverer(h.CORS(router))
}

// listen starts listening on the given port.
func listen(port int, h http.Handler, logger zerolog.Logger) {
	srv := &http.Server{
		Addr:         fmt.Sprintf(":%d", port),
		Handler:      h,
		IdleTimeout:  time.Minute,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	shutdown := make(chan error)
	go func() {
		ch := make(chan os.Signal, 1)
		signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
		sg := <-ch

		logger.
			Info().Stringer("signal", sg).Msg("received shutdown signal")

		ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
		defer cancel()

		shutdown <- srv.Shutdown(ctx)
	}()

	logger.
		Info().Str("addr", srv.Addr).Msg("starting server")

	err := srv.ListenAndServe()
	if err != http.ErrServerClosed {
		logger.
			Fatal().Err(err).Msg("server closed unexpectedly")
	}

	err = <-shutdown
	if err != nil {
		logger.
			Fatal().Err(err).Msg("server cant be gracefully shutdown")
	}
	logger.
		Info().Msg("server gracefully shutdown")
}
