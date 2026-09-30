// Command gateway runs the Secure Agent Tool Gateway.
package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"pnc3-gateway/internal/audit"
	"pnc3-gateway/internal/auth"
	"pnc3-gateway/internal/config"
	"pnc3-gateway/internal/gateway"
	"pnc3-gateway/internal/manifest"
	"pnc3-gateway/internal/policy"
	"pnc3-gateway/internal/session"
	"pnc3-gateway/internal/upstream"
	"pnc3-gateway/web"
)

func main() {
	cfgPath := flag.String("config", envOr("GATEWAY_CONFIG", "config/gateway.yaml"), "path to gateway.yaml")
	flag.Parse()
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	if err := run(*cfgPath, log); err != nil {
		log.Error("gateway stopped", "err", err)
		os.Exit(1)
	}
}

func run(cfgPath string, log *slog.Logger) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(cfg.StateDir, 0o700); err != nil {
		return err
	}

	signer, err := audit.LoadSigner(cfg.StateDir)
	if err != nil {
		return err
	}
	var store audit.Store
	if cfg.DatabaseURL != "" {
		// The database may still be starting (or briefly unreachable): retry for
		// up to a minute instead of crash-looping.
		deadline := time.Now().Add(60 * time.Second)
		for attempt := 1; ; attempt++ {
			store, err = audit.NewPGStore(ctx, cfg.DatabaseURL, signer)
			if err == nil || time.Now().After(deadline) || ctx.Err() != nil {
				break
			}
			log.Warn("audit database not reachable yet; retrying", "attempt", attempt, "err", err)
			time.Sleep(3 * time.Second)
		}
	} else {
		store, err = audit.NewFileStore(cfg.StateDir, signer)
	}
	if err != nil {
		return err
	}

	var sessions session.Store = session.NewMemory()
	if cfg.RedisURL != "" {
		if sessions, err = session.NewRedis(cfg.RedisURL); err != nil {
			return err
		}
	}

	engine, err := policy.NewEngine(cfg.PolicyDir)
	if err != nil {
		return err // fail closed: never start without a valid policy set
	}
	verifier, err := auth.New(ctx, cfg)
	if err != nil {
		return err
	}
	admin, err := auth.NewAdmin(cfg.AdminUsername, cfg.AdminPassword, cfg.AdminPassHash, cfg.SessionSecret)
	if err != nil {
		return err
	}
	if cfg.Env == "production" && cfg.DatabaseURL == "" {
		log.Warn("production without DATABASE_URL: the audit log is a local file, not the managed database")
	}
	registry, err := manifest.NewRegistry(cfg)
	if err != nil {
		return err
	}

	g := gateway.New(gateway.Deps{
		Config: cfg, Logger: log, Auth: verifier, Policy: engine, Registry: registry,
		Upstreams: upstream.NewPool(cfg, gateway.Version), Sessions: sessions, Audit: store, Signer: signer, Admin: admin,
	})
	if err := engine.Watch(func(err error) {
		if err != nil {
			log.Error("policy reload rejected; previous policies stay active", "err", err)
		} else {
			log.Info("policies reloaded")
		}
		g.PolicyReloaded(err)
	}); err != nil {
		log.Warn("policy hot reload disabled", "err", err)
	}
	g.Start(ctx)

	ui := web.Dist()
	srv := &http.Server{Addr: cfg.Listen, Handler: g.Handler(ui), ReadHeaderTimeout: 10 * time.Second}
	log.Info("secure agent tool gateway listening",
		"addr", cfg.Listen, "env", cfg.Env, "profile", cfg.Profile, "audit", store.Backend(), "sessions", sessions.Backend(),
		"policies", len(engine.Status().Policies), "dashboard", ui != nil)

	errCh := make(chan error, 1)
	go func() { errCh <- srv.ListenAndServe() }()
	select {
	case err := <-errCh:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdown)
	}
	return nil
}

func envOr(k, v string) string {
	if s := os.Getenv(k); s != "" {
		return s
	}
	return v
}
