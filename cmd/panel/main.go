package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/kaganyegin/server-side-control/internal/auth"
	"github.com/kaganyegin/server-side-control/internal/config"
	"github.com/kaganyegin/server-side-control/internal/store"
	"github.com/kaganyegin/server-side-control/internal/system"
	"github.com/kaganyegin/server-side-control/internal/web"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		slog.Error("load config", "error", err)
		os.Exit(1)
	}
	if cfg.BootstrapPassword == "" {
		slog.Error("load config", "error", "PANEL_BOOTSTRAP_PASSWORD must be set")
		os.Exit(1)
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	var dataStore *store.Store
	if cfg.DatabaseDSN != "" {
		dataStore, err = store.Open(cfg.DatabaseDSN)
		if err != nil {
			logger.Error("open database", "error", err)
			os.Exit(1)
		}
		defer dataStore.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		if err := dataStore.Migrate(ctx); err != nil {
			logger.Error("run migrations", "error", err)
			os.Exit(1)
		}
	}

	authenticator := auth.NewChainAuthenticator(
		auth.NewPAMAuthenticator(cfg.PAMService),
		auth.NewBootstrapAuthenticator(cfg.BootstrapUser, cfg.BootstrapPassword),
	)
	sessions := auth.NewSessionManager(12 * time.Hour)

	app, err := web.New(cfg, logger, dataStore, system.NewMetricsCollector(), authenticator, sessions)
	if err != nil {
		logger.Error("build web app", "error", err)
		os.Exit(1)
	}

	httpServer := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           app.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	go func() {
		logger.Info("panel started", "addr", cfg.ListenAddr, "app", cfg.AppName)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("listen and serve", "error", err)
			os.Exit(1)
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := httpServer.Shutdown(ctx); err != nil {
		logger.Error("shutdown server", "error", err)
		os.Exit(1)
	}
}
