// Command credwatch runs the temporary-credential misuse detector.
//
// Subcommands:
//
//	serve      run the HTTP service (default)
//	simulate   run built-in scenarios through the full pipeline and print
//	           what the detector decided for each; exits non-zero if any
//	           expectation is violated.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"credwatch/internal/attest"
	"credwatch/internal/attrib"
	"credwatch/internal/audit"
	"credwatch/internal/config"
	"credwatch/internal/credstore"
	"credwatch/internal/engine"
	"credwatch/internal/inventory"
	"credwatch/internal/model"
	"credwatch/internal/pipeline"
	"credwatch/internal/response"
	"credwatch/internal/scenario"
	"credwatch/internal/server"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	cmd := "serve"
	if len(os.Args) > 1 && !strings.HasPrefix(os.Args[1], "-") {
		cmd = os.Args[1]
		os.Args = append(os.Args[:1], os.Args[2:]...)
	}

	var err error
	switch cmd {
	case "serve":
		err = runServe()
	case "simulate":
		err = runSimulate()
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand %q (want serve or simulate)\n", cmd)
		os.Exit(2)
	}
	if err != nil {
		slog.Error("fatal", "err", err)
		os.Exit(1)
	}
}

type app struct {
	cfg      config.File
	creds    *credstore.Store
	inv      *inventory.Store
	attester *attest.Store
	policy   engine.Policy
	attCfg   attrib.Config
	proc     *pipeline.Processor
	actor    *response.Actor
	revoker  response.Revoker
}

func build(cfg config.File) (*app, error) {
	attCfg, err := cfg.AttribConfig()
	if err != nil {
		return nil, err
	}
	a := &app{
		cfg:      cfg,
		creds:    credstore.New(),
		inv:      inventory.NewStore(config.InventoryStoreConfig(cfg)),
		attester: attest.NewStore(nil, 2*time.Minute, time.Hour),
		policy:   cfg.Policy,
		attCfg:   attCfg,
	}
	det := engine.New(a.creds, attrib.New(a.inv, a.attCfg), a.policy)
	det.SetAttester(a.attester)
	a.revoker = &response.MemoryRevoker{}
	a.actor = response.NewActor(cfg.ResponseConfig(), a.revoker, a.creds, nil)

	sink := pipeline.Sink(pipeline.SinkFunc(func(ctx context.Context, inc *model.Incident) error {
		return deliverAlert(ctx, cfg, inc)
	}))
	dec, _ := audit.DecoderFor(model.ProviderAWS) // replaced per-message; see below
	_ = dec
	// The pipeline decoder is only used for the file/stream Run path. HTTP
	// ingest decodes per provider in the server. Use AWS as the stream default.
	streamDec, err := audit.DecoderFor(defaultProvider(cfg))
	if err != nil {
		return nil, err
	}
	a.proc = pipeline.New(cfg.Pipeline, streamDec, det, a.actor, sink)
	return a, nil
}

func defaultProvider(cfg config.File) model.Provider {
	for _, p := range cfg.Providers {
		return model.Provider(p)
	}
	return model.ProviderAWS
}

func runServe() error {
	var cfgPath, invPath string
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	fs.StringVar(&cfgPath, "config", "", "path to JSON config file")
	fs.StringVar(&invPath, "inventory", "", "path to initial inventory snapshot JSON")
	_ = fs.Parse(os.Args[1:])

	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}
	a, err := build(cfg)
	if err != nil {
		return err
	}
	if invPath == "" {
		invPath = cfg.Inventory.File
	}
	if invPath != "" {
		if err := loadInventoryFile(a, invPath); err != nil {
			return err
		}
	} else {
		slog.Warn("no inventory file configured; attribution will be unavailable and verdicts are capped at alert")
	}

	srv, err := server.New(server.Options{
		Processor:    a.proc,
		Creds:        a.creds,
		Inventory:    a.inv,
		Attester:     a.attester,
		Providers:    cfg.Providers,
		AuditPath:    cfg.Sources.HTTPPath,
		AttribConfig: a.attCfg,
		Policy:       a.policy,
		Now:          time.Now,
	})
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Replay any configured file sources through the streaming processor.
	for _, src := range cfg.Sources.Files {
		go func(provider, path string) {
			if err := replayFile(ctx, a, model.Provider(provider), path); err != nil && ctx.Err() == nil {
				slog.Error("replay failed", "path", path, "err", err)
			}
		}(src.Provider, src.Path)
	}

	httpSrv := &http.Server{Addr: cfg.ListenAddr, Handler: srv.Handler(), ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(shutCtx)
	}()

	go janitor(ctx, a)

	slog.Info("credwatch listening", "addr", cfg.ListenAddr, "providers", cfg.Providers, "dry_run", cfg.Response.DryRun)
	if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

func janitor(ctx context.Context, a *app) {
	t := time.NewTicker(5 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			now := time.Now()
			a.creds.Sweep(now)
			a.attester.Sweep()
		}
	}
}

func loadInventoryFile(a *app, path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("inventory: read %s: %w", path, err)
	}
	var payload server.SnapshotPayload
	if err := json.Unmarshal(b, &payload); err != nil {
		return fmt.Errorf("inventory: parse %s: %w", path, err)
	}
	snap, err := payload.Build(time.Now())
	if err != nil {
		return err
	}
	a.inv.Set(snap)
	slog.Info("inventory loaded", "path", path, "records", snap.Len())
	return nil
}

func replayFile(ctx context.Context, a *app, provider model.Provider, path string) error {
	dec, err := audit.DecoderFor(provider)
	if err != nil {
		return err
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	// NDJSON stream: one audit record per line, plus optional credential
	// records marked with "kind":"credential".
	dec2 := json.NewDecoder(f)
	for dec2.More() {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		var raw json.RawMessage
		if err := dec2.Decode(&raw); err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
		var probe struct {
			Kind string `json:"kind"`
		}
		_ = json.Unmarshal(raw, &probe)
		if probe.Kind == "credential" {
			var c model.Credential
			if err := json.Unmarshal(raw, &c); err != nil {
				return err
			}
			a.creds.Put(&c)
			continue
		}
		if _, err := dec.Decode(raw); err != nil {
			return fmt.Errorf("audit record: %w", err)
		}
		if _, err := a.proc.Ingest(ctx, raw); err != nil && err != pipeline.ErrDuplicate {
			slog.Warn("ingest failed", "err", err)
		}
	}
	return nil
}

func deliverAlert(ctx context.Context, cfg config.File, inc *model.Incident) error {
	// Always emit a structured log line: this is the minimum viable alert and
	// it is what a log-based pager consumes.
	line, _ := json.Marshal(inc)
	slog.Warn("credential misuse",
		"severity", inc.Severity,
		"verdict", inc.Verdict,
		"credential", inc.CredentialID,
		"binding", inc.Binding.Class,
		"origin", inc.Origin.Kind,
		"source", inc.Event.SourceIP,
		"lag_seconds", inc.LagSeconds,
		"incident", string(line),
	)
	if cfg.Alerts.WebhookURL == "" {
		return nil
	}
	timeout := cfg.Alerts.Timeout.Duration()
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, http.MethodPost, cfg.Alerts.WebhookURL, bytes.NewReader(line))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("webhook returned %s", resp.Status)
	}
	return nil
}

// runSimulate exercises the built-in scenarios through the real pipeline and
// checks the expected verdicts, so the binary itself is a regression test.
func runSimulate() error {
	fs := flag.NewFlagSet("simulate", flag.ExitOnError)
	var verbose bool
	fs.BoolVar(&verbose, "v", false, "print every decision")
	_ = fs.Parse(os.Args[1:])

	scen := scenario.All()
	failures := 0
	for _, s := range scen {
		ok, err := scenario.RunAndCheck(s, verbose)
		if err != nil {
			fmt.Printf("FAIL %-34s error: %v\n", s.Name, err)
			failures++
			continue
		}
		if ok {
			fmt.Printf("ok   %-34s %s\n", s.Name, s.Description)
		} else {
			fmt.Printf("FAIL %-34s expected verdict not produced\n", s.Name)
			failures++
		}
	}
	if failures > 0 {
		return fmt.Errorf("%d of %d scenarios failed", failures, len(scen))
	}
	fmt.Printf("\nall %d scenarios passed\n", len(scen))
	return nil
}
