package main

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	  "github.com/joho/godotenv"
	_ "github.com/go-sql-driver/mysql"

	"amanah-auth/internal/config"
	"amanah-auth/internal/handler"
	"amanah-auth/internal/repository"
	"amanah-auth/internal/service"
)

func main() {

	_ = godotenv.Load()
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	cfg, err := config.Load()
	if err != nil {
		log.Error("config", "err", err)
		os.Exit(1)
	}

	db, err := sql.Open("mysql", cfg.DatabaseURL)
	if err != nil {
		log.Error("db open", "err", err)
		os.Exit(1)
	}
	defer db.Close()
	db.SetMaxOpenConns(20)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(30 * time.Minute)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	if err := db.PingContext(ctx); err != nil {
		cancel()
		log.Error("db ping", "err", err)
		os.Exit(1)
	}
	cancel()

	svc := service.NewAuth(repository.NewPostgres(db),
		service.NewLogNotifier(log, cfg.DebugOTP),
		service.Config{
			JWTSecret: cfg.JWTSecret, OTPSecret: cfg.OTPSecret,
			AccessTTL: cfg.AccessTTL, RefreshTTL: cfg.RefreshTTL, RefreshTTLRemember: cfg.RefreshTTLRemember,
			ResetTokenTTL: cfg.ResetTokenTTL, OTPTTL: cfg.OTPTTL, OTPResendCooldown: cfg.OTPResendCooldown,
			LockDuration: cfg.LockDuration, OTPMaxAttempts: cfg.OTPMaxAttempts, OTPMaxPerHour: cfg.OTPMaxPerHour,
			MaxLoginAttempts: cfg.MaxLoginAttempts, BcryptCost: cfg.BcryptCost, DebugOTP: cfg.DebugOTP,
		})

	srv := &http.Server{
		Addr:              ":" + cfg.Port,
		Handler:           handler.New(svc, log).Routes(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	go func() {
		log.Info("server listening", "addr", srv.Addr, "env", cfg.Env)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("server", "err", err)
			os.Exit(1)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	log.Info("shutting down")
	shutCtx, shutCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutCancel()
	_ = srv.Shutdown(shutCtx)
}
