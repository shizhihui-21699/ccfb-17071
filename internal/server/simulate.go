package server

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"credwatch/internal/attrib"
	"credwatch/internal/engine"
	"credwatch/internal/model"
)

// simulateRequest runs a set of raw audit records through a fresh detector
// that shares inventory, credentials and attestation with the live service but
// keeps no behavioural state. This is the evaluation hook: it answers "what
// would the detector decide for this stream?" without polluting production
// windows or firing alerts.
type simulateRequest struct {
	Provider string            `json:"provider"`
	Records  []json.RawMessage `json:"records"`
	// Now overrides the evaluation clock (RFC3339). Useful for replaying a
	// historical attack and measuring detection lag exactly.
	Now string `json:"now"`
}

type simulateResponse struct {
	Provider  string           `json:"provider"`
	Evaluated int              `json:"evaluated"`
	Results   []simulateResult `json:"results"`
}

type simulateResult struct {
	EventTime  time.Time `json:"event_time"`
	LagSeconds float64   `json:"lag_seconds"`
	Verdict    string    `json:"verdict"`
	Severity   string    `json:"severity"`
	Score      int       `json:"score"`
	Binding    string    `json:"binding"`
	Reason     string    `json:"reason"`
	Origin     string    `json:"origin"`
	Instance   string    `json:"instance,omitempty"`
	Function   string    `json:"function,omitempty"`
	Evidence   []string  `json:"evidence,omitempty"`
}

func (s *Server) handleSimulate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 32<<20))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(string(body)) == "" {
		http.Error(w, "empty body", http.StatusBadRequest)
		return
	}
	var req simulateRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	provider := model.Provider(req.Provider)
	if provider == "" {
		provider = s.defProv
	}
	dec, ok := s.decoders[provider]
	if !ok {
		http.Error(w, "unsupported provider", http.StatusBadRequest)
		return
	}
	now := s.now()
	if req.Now != "" {
		t, err := time.Parse(time.RFC3339, req.Now)
		if err != nil {
			http.Error(w, "bad now: "+err.Error(), http.StatusBadRequest)
			return
		}
		now = t.UTC()
	}
	det := engine.New(s.creds, attrib.New(s.inv, s.attribConfig), s.policy)
	if s.attester != nil {
		det.SetAttester(s.attester)
	}
	det.SetClock(func() time.Time { return now })

	resp := simulateResponse{Provider: string(provider)}
	for _, raw := range req.Records {
		ev, err := dec.Decode(raw)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		d := det.Process(ev)
		resp.Evaluated++
		rr := simulateResult{
			EventTime:  d.Event.EventTime,
			LagSeconds: d.Lag.Seconds(),
			Verdict:    string(d.Verdict),
			Severity:   string(d.Severity),
			Score:      d.Score,
			Binding:    string(d.Binding.Class),
			Reason:     d.Binding.Reason,
			Origin:     string(d.Origin.Kind),
			Instance:   d.Origin.InstanceID,
			Function:   d.Origin.FunctionID,
		}
		for _, e := range d.Evidence {
			rr.Evidence = append(rr.Evidence, e.Rule+": "+e.Detail)
		}
		resp.Results = append(resp.Results, rr)
	}
	writeJSON(w, http.StatusOK, resp)
}
