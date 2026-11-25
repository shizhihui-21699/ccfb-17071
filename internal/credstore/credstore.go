// Package credstore holds issuance records for temporary credentials,
// keyed by the correlation key the audit log exposes.
//
// It also remembers credentials that were already actioned, because audit
// logs are late and out of order: the same stolen key keeps producing events
// for minutes after revocation, and every one of them must not page anyone.
package credstore

import (
	"errors"
	"sort"
	"strings"
	"sync"
	"time"

	"credwatch/internal/model"
)

var ErrNotFound = errors.New("credential not found")

type actioned struct {
	At     time.Time
	Reason string
}

type Store struct {
	mu       sync.RWMutex
	creds    map[string]*model.Credential // key -> credential
	actioned map[string]actioned
	// sessionIndex maps a session name / principal to keys, for providers
	// whose logs sometimes omit the access key.
	bySession map[string][]string

	// trackIssuanceBuildsBaseline keeps the store bounded but remembers
	// enough history to detect "same session name, new key" patterns that
	// often accompany re-issuance after theft.
	maxAge time.Duration
}

func New() *Store {
	return &Store{
		creds:     make(map[string]*model.Credential),
		actioned:  make(map[string]actioned),
		bySession: make(map[string][]string),
		maxAge:    24 * time.Hour,
	}
}

func sessionKey(c *model.Credential) string {
	if c.SessionName == "" && c.PrincipalID == "" {
		return ""
	}
	return c.RoleARN + "|" + c.PrincipalID + "|" + c.SessionName
}

// Put inserts or updates an issuance record. Later updates to the same key
// (e.g. refreshed scope data) are allowed; the key itself is immutable.
func (s *Store) Put(c *model.Credential) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *c
	s.creds[c.KeyID] = &cp
	if k := sessionKey(c); k != "" {
		keys := s.bySession[k]
		found := false
		for _, existing := range keys {
			if existing == c.KeyID {
				found = true
				break
			}
		}
		if !found {
			s.bySession[k] = append(keys, c.KeyID)
		}
	}
}

func (s *Store) Get(key string) (*model.Credential, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	c, ok := s.creds[key]
	if !ok {
		return nil, ErrNotFound
	}
	cp := *c
	return &cp, nil
}

// Resolve finds the issuance record for an event. Exact key match wins,
// regardless of whether the credential is still live: an *expired* key that
// is still being used is not "unknown", it is one of the strongest signals
// there is (the legitimate holder stopped, someone else did not). The engine
// decides what expiry means; the store must not hide the record.
//
// When the provider's log only carries a session name/principal, fall back to
// the most recently issued matching credential, marking the result as
// principal-scoped so the engine does not over-claim precision.
func (s *Store) Resolve(ev *model.Event, now time.Time) (*model.Credential, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if ev.AccessKeyID != "" {
		if c, ok := s.creds[ev.AccessKeyID]; ok {
			cp := *c
			return &cp, true
		}
		// Case-insensitive fallback: some providers normalize key casing
		// differently across log streams.
		lk := strings.ToLower(ev.AccessKeyID)
		for k, c := range s.creds {
			if strings.ToLower(k) == lk {
				cp := *c
				return &cp, true
			}
		}
	}
	var candidates []*model.Credential
	for _, c := range s.creds {
		if c.SessionName != "" && c.SessionName == ev.SessionName &&
			(ev.PrincipalID == "" || c.PrincipalID == ev.PrincipalID) {
			candidates = append(candidates, c)
		}
	}
	if len(candidates) == 0 {
		return nil, false
	}
	// Prefer a live credential at this instant, then the most recently issued.
	sort.Slice(candidates, func(i, j int) bool {
		li := !candidates[i].Expired(now, 10*time.Minute)
		lj := !candidates[j].Expired(now, 10*time.Minute)
		if li != lj {
			return li
		}
		return candidates[i].IssuedAt.After(candidates[j].IssuedAt)
	})
	cp := *candidates[0]
	cp.KeyKind = model.KeyPrincipal // imprecise correlation
	return &cp, true
}

// MarkActioned records that a credential has been revoked or escalated, so
// later events for the same key are attached to the existing incident rather
// than firing new pages.
func (s *Store) MarkActioned(key, reason string, at time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.actioned[key] = actioned{At: at, Reason: reason}
}

func (s *Store) Actioned(key string) (time.Time, string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	a, ok := s.actioned[key]
	return a.At, a.Reason, ok
}

// Sweep drops expired credentials older than the retention window and stale
// actioned records, bounding memory in long-running deployments.
func (s *Store) Sweep(now time.Time) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	removed := 0
	for k, c := range s.creds {
		if c.Expired(now, 0) && now.Sub(c.ExpiresAt) > s.maxAge {
			delete(s.creds, k)
			removed++
		}
	}
	for k, a := range s.actioned {
		if now.Sub(a.At) > s.maxAge {
			delete(s.actioned, k)
			removed++
		}
	}
	if removed > 0 {
		for k, keys := range s.bySession {
			live := keys[:0]
			for _, kk := range keys {
				if _, ok := s.creds[kk]; ok {
					live = append(live, kk)
				}
			}
			if len(live) == 0 {
				delete(s.bySession, k)
			} else {
				s.bySession[k] = live
			}
		}
	}
	return removed
}

// Len is used by metrics/tests.
func (s *Store) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.creds)
}

// NormalizeKeyID lowercases and trims a key so that providers with
// case-variant log formats match the same record.
func NormalizeKeyID(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}
