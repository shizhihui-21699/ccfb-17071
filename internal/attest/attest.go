// Package attest implements a workload-side corroboration channel.
//
// Network attribution has a hard limit: when many workloads egress through one
// NAT gateway, or a serverless function leaves from provider-owned addresses,
// the audit address cannot identify the caller. The fix is not a better IP
// heuristic, it is a second, independent source of truth: a small agent on the
// instance/pod/function runtime reports which credential it actually used.
//
// Claims are authenticated with a per-agent HMAC key and bounded in time, so a
// compromised workload cannot forge another workload's claim, and a replay
// outside the window is rejected.
//
// Claims only ever *corroborate*. A missing claim never proves theft (agents
// deploy late, crash, or are blocked); a present claim from a different
// workload than the credential's scope is strong evidence of misuse.
package attest

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"credwatch/internal/model"
)

type Claim struct {
	KeyID        string `json:"key_id"`
	WorkloadID   string `json:"workload_id"`
	WorkloadKind string `json:"workload_kind"`
	// Addr is the workload's own address as the agent sees it. Used only as a
	// hint; the trusted path is the WorkloadID/Scope comparison.
	Addr string `json:"addr,omitempty"`

	IssuedAt  time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expires_at"`
	AgentID   string    `json:"agent_id"`
	Signature string    `json:"signature"`
}

func (c *Claim) canonical() string {
	return strings.Join([]string{
		"v1", c.KeyID, c.WorkloadID, c.WorkloadKind, c.Addr,
		c.IssuedAt.UTC().Format(time.RFC3339Nano),
		c.ExpiresAt.UTC().Format(time.RFC3339Nano),
		c.AgentID,
	}, "\n")
}

func sign(secret []byte, c *Claim) string {
	m := hmac.New(sha256.New, secret)
	m.Write([]byte(c.canonical()))
	return base64.RawStdEncoding.EncodeToString(m.Sum(nil))
}

var (
	ErrUnknownAgent = errors.New("attestation: unknown agent")
	ErrBadSignature = errors.New("attestation: bad signature")
	ErrBadClaim     = errors.New("attestation: invalid claim window")
	ErrReplay       = errors.New("attestation: claim timestamp outside accepted window")
)

type Store struct {
	mu      sync.RWMutex
	keyring map[string][]byte // agent id -> secret
	byKey   map[string][]Claim
	maxSkew time.Duration
	retain  time.Duration
	now     func() time.Time
}

func NewStore(now func() time.Time, maxSkew, retain time.Duration) *Store {
	if now == nil {
		now = time.Now
	}
	if maxSkew <= 0 {
		maxSkew = 2 * time.Minute
	}
	if retain <= 0 {
		retain = time.Hour
	}
	return &Store{keyring: map[string][]byte{}, byKey: map[string][]Claim{}, maxSkew: maxSkew, retain: retain, now: now}
}

// SetAgentKey registers or rotates an agent secret.
func (s *Store) SetAgentKey(agentID string, secret []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.keyring[agentID] = append([]byte(nil), secret...)
}

// Sign is the agent-side helper (also used in tests and the simulator).
func (s *Store) Sign(c *Claim) error {
	s.mu.RLock()
	secret, ok := s.keyring[c.AgentID]
	s.mu.RUnlock()
	if !ok {
		return ErrUnknownAgent
	}
	c.Signature = sign(secret, c)
	return nil
}

func (s *Store) Submit(c Claim) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	secret, ok := s.keyring[c.AgentID]
	if !ok {
		return ErrUnknownAgent
	}
	if !hmac.Equal([]byte(sign(secret, &c)), []byte(c.Signature)) {
		return ErrBadSignature
	}
	now := s.now()
	if c.ExpiresAt.Before(c.IssuedAt) || c.ExpiresAt.Sub(c.IssuedAt) > 24*time.Hour {
		return ErrBadClaim
	}
	if c.IssuedAt.After(now.Add(s.maxSkew)) {
		return ErrReplay
	}
	// An already-expired claim is useless but not an error; drop it so the
	// store does not grow without bound from clock-skewed agents.
	if c.ExpiresAt.Before(now.Add(-s.maxSkew)) {
		return nil
	}
	c.Signature = ""
	list := s.byKey[c.KeyID]
	for _, existing := range list {
		if existing.AgentID == c.AgentID && existing.IssuedAt.Equal(c.IssuedAt) {
			return nil // idempotent re-submit
		}
	}
	s.byKey[c.KeyID] = append(list, c)
	return nil
}

// ClaimFor returns the claim covering the given instant, preferring the most
// recent. ok=false means "no agent reported use", never "no use happened".
func (s *Store) ClaimFor(key string, at time.Time) (Claim, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	list := s.byKey[key]
	var best Claim
	found := false
	for _, c := range list {
		if at.Before(c.IssuedAt.Add(-s.maxSkew)) || at.After(c.ExpiresAt.Add(s.maxSkew)) {
			continue
		}
		if !found || c.IssuedAt.After(best.IssuedAt) {
			best, found = c, true
		}
	}
	return best, found
}

// ClaimsFor exposes all live claims for a key (incident enrichment).
func (s *Store) ClaimsFor(key string) []Claim {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]Claim(nil), s.byKey[key]...)
}

// Sweep drops claims whose validity ended before the retention horizon.
func (s *Store) Sweep() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	n := 0
	for k, list := range s.byKey {
		live := list[:0]
		for _, c := range list {
			if now.Sub(c.ExpiresAt) > s.retain {
				n++
				continue
			}
			live = append(live, c)
		}
		if len(live) == 0 {
			delete(s.byKey, k)
		} else {
			s.byKey[k] = live
		}
	}
	return n
}

// MatchScope reports whether a claim agrees with a credential's scope.
//
// Returns (true, true) when the claim names exactly the scoped workload,
// (true, false) when the claim names a different workload we can identify,
// and (false, false) when there is no claim at all.
func MatchScope(c Claim, sc model.Scope) (claimed bool, matches bool) {
	if c.WorkloadID == "" {
		return true, false
	}
	switch sc.Kind {
	case model.ScopeInstance, model.ScopeFleet, model.ScopeFunction:
		return true, c.WorkloadID == sc.ID
	case model.ScopeRole, model.ScopeUser:
		// The workldoad is not the principal; accept any claim for role/user
		// scopes and let it corroborate that *some* agent used the key.
		return true, true
	}
	return true, false
}

// AgentIDs returns registered agent ids, sorted (admin endpoint / tests).
func (s *Store) AgentIDs() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]string, 0, len(s.keyring))
	for id := range s.keyring {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

func (s *Store) String() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return fmt.Sprintf("attest{agents:%d keys:%d}", len(s.keyring), len(s.byKey))
}
