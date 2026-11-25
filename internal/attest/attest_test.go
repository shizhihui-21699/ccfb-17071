package attest_test

import (
	"testing"
	"time"

	"credwatch/internal/attest"
	"credwatch/internal/model"
)

func TestSignatureRequired(t *testing.T) {
	now := time.Now()
	s := attest.NewStore(func() time.Time { return now }, time.Minute, time.Hour)
	s.SetAgentKey("agent-1", []byte("k1"))
	claim := attest.Claim{KeyID: "ASIA1", WorkloadID: "i-a", IssuedAt: now, ExpiresAt: now.Add(time.Minute), AgentID: "agent-1"}
	if err := s.Submit(claim); err != attest.ErrBadSignature {
		t.Fatalf("unsigned claim must be rejected, got %v", err)
	}
}

func TestForgedClaimFromOtherAgent(t *testing.T) {
	now := time.Now()
	s := attest.NewStore(func() time.Time { return now }, time.Minute, time.Hour)
	s.SetAgentKey("agent-1", []byte("k1"))
	s.SetAgentKey("agent-2", []byte("k2"))
	// agent-2 signs a claim that names i-a; the key must be agent-2's.
	c := attest.Claim{KeyID: "ASIA1", WorkloadID: "i-a", IssuedAt: now, ExpiresAt: now.Add(time.Minute), AgentID: "agent-2"}
	if err := s.Sign(&c); err != nil {
		t.Fatal(err)
	}
	if err := s.Submit(c); err != nil {
		t.Fatalf("self-signed claim should verify: %v", err)
	}
	// Now swap the agent id without re-signing: must fail.
	c.AgentID = "agent-1"
	if err := s.Submit(c); err != attest.ErrBadSignature {
		t.Fatalf("tampered agent id must fail verification, got %v", err)
	}
}

func TestClaimForWindow(t *testing.T) {
	now := time.Now()
	s := attest.NewStore(func() time.Time { return now }, 30*time.Second, time.Hour)
	s.SetAgentKey("a", []byte("k"))
	c := attest.Claim{KeyID: "ASIA1", WorkloadID: "i-a", IssuedAt: now, ExpiresAt: now.Add(time.Minute), AgentID: "a"}
	_ = s.Sign(&c)
	_ = s.Submit(c)

	if _, ok := s.ClaimFor("ASIA1", now.Add(30*time.Second)); !ok {
		t.Fatal("claim should cover its own window")
	}
	if _, ok := s.ClaimFor("ASIA1", now.Add(10*time.Minute)); ok {
		t.Fatal("claim must not cover a time past expiry + skew")
	}
	if _, ok := s.ClaimFor("OTHER", now); ok {
		t.Fatal("no claim for a different key")
	}
}

func TestUnknownAgentRejected(t *testing.T) {
	now := time.Now()
	s := attest.NewStore(func() time.Time { return now }, time.Minute, time.Hour)
	c := attest.Claim{KeyID: "ASIA1", WorkloadID: "i-a", IssuedAt: now, ExpiresAt: now.Add(time.Minute), AgentID: "ghost"}
	if err := s.Submit(c); err != attest.ErrUnknownAgent {
		t.Fatalf("want ErrUnknownAgent, got %v", err)
	}
}

func TestMatchScope(t *testing.T) {
	cases := []struct {
		claim string
		scope model.Scope
		want  bool
	}{
		{"i-a", model.Scope{Kind: model.ScopeInstance, ID: "i-a"}, true},
		{"i-b", model.Scope{Kind: model.ScopeInstance, ID: "i-a"}, false},
		{"eks-prod", model.Scope{Kind: model.ScopeFleet, ID: "eks-prod"}, true},
		{"fn-x", model.Scope{Kind: model.ScopeFunction, ID: "fn-y"}, false},
		{"anything", model.Scope{Kind: model.ScopeRole, ID: "r"}, true},
	}
	for _, tc := range cases {
		_, got := attest.MatchScope(attest.Claim{WorkloadID: tc.claim}, tc.scope)
		if got != tc.want {
			t.Errorf("claim %q vs scope %s/%s: want %v got %v", tc.claim, tc.scope.Kind, tc.scope.ID, tc.want, got)
		}
	}
}
