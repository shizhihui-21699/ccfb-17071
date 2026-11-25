// Package server exposes the service over HTTP.
//
// Endpoints:
//
//	POST /v1/audit        raw provider audit record(s)  (ingest)
//	POST /v1/credentials  issuance record(s)            (issuance feed or poller)
//	POST /v1/attest       agent claim                   (workload corroboration)
//	POST /v1/inventory    inventory snapshot            (refresh)
//	GET  /healthz         liveness + inventory staleness
//	GET  /metrics         counters
//	GET  /v1/incidents    recent incidents (newest first)
//	POST /v1/simulate     run an end-to-end scenario (evaluation helper)
//
// Ingest endpoints accept a single JSON object, a JSON array, or NDJSON lines.
package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"credwatch/internal/attest"
	"credwatch/internal/attrib"
	"credwatch/internal/audit"
	"credwatch/internal/credstore"
	"credwatch/internal/engine"
	"credwatch/internal/inventory"
	"credwatch/internal/model"
	"credwatch/internal/pipeline"
)

type Server struct {
	proc         *pipeline.Processor
	creds        *credstore.Store
	inv          *inventory.Store
	attester     *attest.Store
	decoders     map[model.Provider]audit.Decoder
	defProv      model.Provider
	alerts       Sink
	now          func() time.Time
	attribConfig attrib.Config
	policy       engine.Policy
	mux          *http.ServeMux
}

type Sink interface {
	Deliver(ctx context.Context, inc *model.Incident) error
}

type Options struct {
	Processor *pipeline.Processor
	Creds     *credstore.Store
	Inventory *inventory.Store
	Attester  *attest.Store
	Providers []string
	AuditPath string
	Alerts    Sink
	Now       func() time.Time

	// Evaluation controls: used by /v1/simulate so its fresh detector matches
	// the live one's attribution and policy.
	AttribConfig attrib.Config
	Policy       engine.Policy
}

func New(o Options) (*Server, error) {
	if o.Now == nil {
		o.Now = time.Now
	}
	s := &Server{
		proc:         o.Processor,
		creds:        o.Creds,
		inv:          o.Inventory,
		attester:     o.Attester,
		decoders:     map[model.Provider]audit.Decoder{},
		alerts:       o.Alerts,
		now:          o.Now,
		attribConfig: o.AttribConfig,
		policy:       o.Policy,
		mux:          http.NewServeMux(),
	}
	for _, p := range o.Providers {
		d, err := audit.DecoderFor(model.Provider(p))
		if err != nil {
			return nil, err
		}
		s.decoders[d.Provider()] = d
	}
	if len(s.decoders) == 0 {
		d, _ := audit.DecoderFor(model.ProviderAWS)
		s.decoders[d.Provider()] = d
	}
	// Deterministic default keeps replay/evaluation reproducible.
	s.defProv = model.ProviderAWS
	for p := range s.decoders {
		s.defProv = p
		break
	}

	auditPath := o.AuditPath
	if auditPath == "" {
		auditPath = "/v1/audit"
	}
	s.mux.HandleFunc(auditPath, s.handleAudit)
	s.mux.HandleFunc("/v1/credentials", s.handleCredentials)
	s.mux.HandleFunc("/v1/attest", s.handleAttest)
	s.mux.HandleFunc("/v1/inventory", s.handleInventory)
	s.mux.HandleFunc("/healthz", s.handleHealth)
	s.mux.HandleFunc("/metrics", s.handleMetrics)
	s.mux.HandleFunc("/v1/incidents", s.handleIncidents)
	s.mux.HandleFunc("/v1/simulate", s.handleSimulate)
	return s, nil
}

func (s *Server) Handler() http.Handler { return s.mux }

// ---------- ingest ----------

type ingestBody struct {
	Provider string            `json:"provider"`
	Records  []json.RawMessage `json:"records"`
}

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 32<<20))
	if err != nil {
		http.Error(w, "read body: "+err.Error(), http.StatusBadRequest)
		return
	}
	provider := model.Provider(strings.TrimSpace(r.URL.Query().Get("provider")))
	if provider == "" {
		provider = s.defProv
	}
	dec, ok := s.decoders[provider]
	if !ok {
		http.Error(w, "unsupported provider "+string(provider), http.StatusBadRequest)
		return
	}

	records, err := splitRecords(body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	var out struct {
		Accepted  int               `json:"accepted"`
		Failed    int               `json:"failed"`
		Decisions []engine.Decision `json:"decisions,omitempty"`
		Errors    []string          `json:"errors,omitempty"`
	}
	for _, raw := range records {
		// A CloudTrail file may itself contain many records; flatten it.
		if provider == model.ProviderAWS {
			var probe struct {
				Records []json.RawMessage `json:"Records"`
			}
			if json.Unmarshal(raw, &probe) == nil && len(probe.Records) > 1 {
				for _, sub := range probe.Records {
					s.ingestOne(dec, sub, &out)
				}
				continue
			}
		}
		s.ingestOne(dec, raw, &out)
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) ingestOne(dec audit.Decoder, raw []byte, out *struct {
	Accepted  int               `json:"accepted"`
	Failed    int               `json:"failed"`
	Decisions []engine.Decision `json:"decisions,omitempty"`
	Errors    []string          `json:"errors,omitempty"`
}) {
	dec_, err := s.proc.Ingest(context.Background(), raw)
	if err != nil && err != pipeline.ErrDuplicate {
		out.Failed++
		if len(out.Errors) < 20 {
			out.Errors = append(out.Errors, err.Error())
		}
		return
	}
	out.Accepted++
	if dec_.Verdict != "" {
		out.Decisions = append(out.Decisions, dec_)
	}
}

func (s *Server) handleCredentials(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var creds []model.Credential
	if err := decodeBody(r, &creds); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	for i := range creds {
		c := &creds[i]
		if c.KeyID == "" {
			http.Error(w, fmt.Sprintf("credential %d: key_id is required", i), http.StatusBadRequest)
			return
		}
		if c.KeyKind == "" {
			c.KeyKind = model.KeyExactSession
		}
		if c.IssuerKind == "" {
			c.IssuerKind = model.IssuerUnknown
		}
		if c.Scope.Kind == "" {
			c.Scope.Kind = model.ScopeRole
		}
		s.creds.Put(c)
	}
	writeJSON(w, http.StatusOK, map[string]any{"accepted": len(creds)})
}

func (s *Server) handleAttest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.attester == nil {
		http.Error(w, "attestation not enabled", http.StatusNotImplemented)
		return
	}
	var claims []attest.Claim
	if err := decodeBody(r, &claims); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	accepted := 0
	for _, c := range claims {
		if err := s.attester.Submit(c); err != nil {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
		accepted++
	}
	writeJSON(w, http.StatusOK, map[string]any{"accepted": accepted})
}

func (s *Server) handleInventory(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		_, st := s.inv.Snapshot()
		writeJSON(w, http.StatusOK, st)
	case http.MethodPost:
		var data SnapshotPayload
		if err := decodeBody(r, &data); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		snap, err := data.Build(s.now())
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		s.inv.Set(snap)
		writeJSON(w, http.StatusOK, map[string]any{"records": snap.Len(), "snapshot": snap.ID})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	_, st := s.inv.Snapshot()
	status := http.StatusOK
	healthy := st.HasSnapshot && !st.Stale
	if !healthy {
		status = http.StatusServiceUnavailable
	}
	writeJSON(w, status, map[string]any{
		"healthy":     healthy,
		"inventory":   st,
		"credentials": s.creds.Len(),
	})
}

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	var b strings.Builder
	for k, v := range s.proc.StatsSnapshot() {
		fmt.Fprintf(&b, "credwatch_%s %d\n", k, v)
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	_, _ = io.WriteString(w, b.String())
}

func (s *Server) handleIncidents(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"incidents": s.proc.Incidents(200)})
}

func splitRecords(body []byte) ([]json.RawMessage, error) {
	trimmed := strings.TrimSpace(string(body))
	if trimmed == "" {
		return nil, fmt.Errorf("empty body")
	}
	// Array of records.
	if strings.HasPrefix(trimmed, "[") {
		var arr []json.RawMessage
		if err := json.Unmarshal([]byte(trimmed), &arr); err != nil {
			return nil, fmt.Errorf("parse array: %w", err)
		}
		return arr, nil
	}
	// Envelope {"provider":..,"records":[..]} or a single object.
	var env ingestBody
	if err := json.Unmarshal([]byte(trimmed), &env); err == nil && len(env.Records) > 0 {
		return env.Records, nil
	}
	// NDJSON.
	if strings.Contains(trimmed, "\n") {
		var out []json.RawMessage
		for i, line := range strings.Split(trimmed, "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			if !json.Valid([]byte(line)) {
				return nil, fmt.Errorf("ndjson line %d is not valid JSON", i+1)
			}
			out = append(out, json.RawMessage(line))
		}
		return out, nil
	}
	return []json.RawMessage{json.RawMessage(trimmed)}, nil
}

func decodeBody(r *http.Request, dst any) error {
	body, err := io.ReadAll(io.LimitReader(r.Body, 32<<20))
	if err != nil {
		return err
	}
	trimmed := strings.TrimSpace(string(body))
	// Accept either a JSON array or a single object.
	if strings.HasPrefix(trimmed, "[") {
		return json.Unmarshal([]byte(trimmed), dst)
	}
	// Wrap single object into a one-element array via reflection-free path:
	// unmarshal into []json.RawMessage then into target slice/struct.
	var one json.RawMessage
	if err := json.Unmarshal([]byte(trimmed), &one); err != nil {
		return err
	}
	wrapped := append(append([]byte("["), one...), ']')
	if err := json.Unmarshal(wrapped, dst); err == nil {
		return nil
	}
	return json.Unmarshal([]byte(trimmed), dst)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}
