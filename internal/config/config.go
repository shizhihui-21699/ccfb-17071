// Package config loads the service configuration.
//
// Configuration is intentionally explicit about the trade-offs the operator is
// making: whether provider egress is tolerated, whether shared NAT is accepted,
// whether attestation is required, and whether containment mutates anything.
// Hiding these defaults would let a team believe they have exact attribution
// when they have none.
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"credwatch/internal/attrib"
	"credwatch/internal/engine"
	"credwatch/internal/model"
	"credwatch/internal/pipeline"
	"credwatch/internal/response"
	"credwatch/internal/unit"
)

type File struct {
	ListenAddr string `json:"listen_addr"`

	Providers []string `json:"providers"`

	Policy engine.Policy `json:"policy"`

	Inventory struct {
		File                       string        `json:"file"`
		MaxAge                     unit.Duration `json:"max_age"`
		ProviderRanges             []string      `json:"provider_ranges"`
		Blocklist                  []string      `json:"blocklist"`
		AllowProviderEgressDefault bool          `json:"allow_provider_egress_default"`
	} `json:"inventory"`

	Response struct {
		Enabled             bool   `json:"enabled"`
		DryRun              bool   `json:"dry_run"`
		MinSeverity         string `json:"min_severity"`
		PrincipalMechanism  string `json:"principal_mechanism"`
		CooldownSeconds     int    `json:"cooldown_seconds"`
		MaxActionsPerMinute int    `json:"max_actions_per_minute"`
	} `json:"response"`

	Pipeline pipeline.Config `json:"pipeline"`

	// Ingest sources.
	Sources struct {
		// File paths replayed at startup (tail -f style), one JSON record per
		// line. For local evaluation and tests.
		Files []struct {
			Provider string `json:"provider"`
			Path     string `json:"path"`
		} `json:"files"`
		// HTTP ingest endpoint path for pull-mode collectors.
		HTTPPath string `json:"http_path"`
	} `json:"sources"`

	Alerts struct {
		// Webhook receives incident JSON. Empty disables delivery (incidents
		// are still archived).
		WebhookURL string        `json:"webhook_url"`
		Timeout    unit.Duration `json:"timeout"`
	} `json:"alerts"`
}

func Default() File {
	f := File{
		ListenAddr: ":8080",
		Providers:  []string{"aws"},
		Policy:     engine.DefaultPolicy(),
	}
	f.Inventory.MaxAge = unit.Duration(10 * time.Minute)
	f.Response.Enabled = true
	f.Response.DryRun = true
	f.Response.MinSeverity = string(model.SevHigh)
	f.Response.PrincipalMechanism = string(response.MechPrincipalDeny)
	f.Response.CooldownSeconds = 600
	f.Response.MaxActionsPerMinute = 30
	f.Pipeline = pipeline.DefaultConfig()
	f.Sources.HTTPPath = "/v1/audit"
	f.Alerts.Timeout = unit.Duration(5 * time.Second)
	return f
}

func Load(path string) (File, error) {
	f := Default()
	if path == "" {
		return f, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return f, fmt.Errorf("config: read %s: %w", path, err)
	}
	if err := json.Unmarshal(b, &f); err != nil {
		return f, fmt.Errorf("config: parse %s: %w", path, err)
	}
	if err := f.Validate(); err != nil {
		return f, err
	}
	return f, nil
}

func (f File) Validate() error {
	if f.Response.CooldownSeconds < 0 {
		return fmt.Errorf("config: response.cooldown_seconds must be >= 0")
	}
	mech := response.Mechanism(f.Response.PrincipalMechanism)
	switch mech {
	case response.MechSessionRevoke, response.MechPrincipalDeny, response.MechPrincipalQuarantine, response.MechNone:
	default:
		return fmt.Errorf("config: unknown response.principal_mechanism %q", mech)
	}
	sev := model.Severity(f.Response.MinSeverity)
	switch sev {
	case model.SevInfo, model.SevLow, model.SevMedium, model.SevHigh, model.SevCritical:
	default:
		return fmt.Errorf("config: unknown response.min_severity %q", sev)
	}
	if f.Policy.AlertMinScore < f.Policy.WatchMinScore {
		return fmt.Errorf("config: policy.alert_min_score must be >= watch_min_score")
	}
	if f.Policy.AutoRevokeMinScore < f.Policy.AlertMinScore {
		return fmt.Errorf("config: policy.auto_revoke_min_score must be >= alert_min_score")
	}
	return nil
}

// ResponseConfig converts to the response package's config.
func (f File) ResponseConfig() response.Config {
	return response.Config{
		Enabled:               f.Response.Enabled,
		DryRun:                f.Response.DryRun,
		MinSeverity:           model.Severity(f.Response.MinSeverity),
		PrincipalMechanism:    response.Mechanism(f.Response.PrincipalMechanism),
		PerCredentialCooldown: time.Duration(f.Response.CooldownSeconds) * time.Second,
		MaxActionsPerMinute:   f.Response.MaxActionsPerMinute,
	}
}

// AttribConfig converts to the attributor config, parsing CIDRs.
func (f File) AttribConfig() (attrib.Config, error) {
	cfg := attrib.Config{AllowProviderEgressDefault: f.Inventory.AllowProviderEgressDefault}
	for _, p := range f.Inventory.ProviderRanges {
		pref, err := parsePrefix(p)
		if err != nil {
			return cfg, err
		}
		cfg.ProviderRanges = append(cfg.ProviderRanges, pref)
	}
	for _, p := range f.Inventory.Blocklist {
		pref, err := parsePrefix(p)
		if err != nil {
			return cfg, err
		}
		cfg.Blocklist = append(cfg.Blocklist, pref)
	}
	return cfg, nil
}

func InventoryStoreConfig(f File) time.Duration {
	if f.Inventory.MaxAge <= 0 {
		return 10 * time.Minute
	}
	return f.Inventory.MaxAge.Duration()
}
