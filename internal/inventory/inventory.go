// Package inventory answers "who owns this network address right now?".
//
// Attribution is impossible without it: an audit source address is only a
// *representation*, so the service must know which addresses belong to which
// instance, which are shared NAT/proxy egress, and which are provider-owned.
//
// The interface is deliberately snapshot-based. Real deployments back it with
// periodic provider Describe* calls (EC2/ENI, EKS, Lambda, NAT gateways) and a
// short cache TTL; attribution must be a local, sub-millisecond operation on
// the hot path, never an API call per event.
package inventory

import (
	"net/netip"
	"sort"
	"sync"
	"time"

	"credwatch/internal/model"
)

// Record is one addressable network endpoint owned by the account.
type Record struct {
	Addr netip.Prefix // usually a single-host prefix (/32, /128)

	Kind model.OriginKind
	// Specificity of the mapping: how strongly a hit identifies one workload.
	Specificity model.Specificity

	InstanceID string
	FleetID    string
	FunctionID string
	ProxyID    string
	SubnetID   string
	NATGateway string
	AccountID  string
	Zone       string

	// SharedEgress marks ranges that many workloads egress through (NAT
	// gateway, egress proxy pool, corporate NAT EIPs).
	SharedEgress bool
	// Blocklisted marks addresses that must never carry this account's
	// credentials (known attacker infrastructure, Tor exits, ...).
	Blocklisted bool

	// ValidFrom/ValidUntil let an inventory lane expire stale records when
	// the upstream source cannot delete them (e.g. DNS-derived entries).
	ValidFrom  time.Time
	ValidUntil time.Time

	Source string
}

func (r Record) Live(now time.Time) bool {
	if !r.ValidFrom.IsZero() && now.Before(r.ValidFrom) {
		return false
	}
	if !r.ValidUntil.IsZero() && now.After(r.ValidUntil) {
		return false
	}
	return true
}

// Snapshot is an immutable, sorted view used for fast lookups.
type Snapshot struct {
	ID      string
	BuiltAt time.Time
	records []Record
	exact   map[netip.Addr]int // index into records for /32 and /128
	byInst  map[string]string  // instance id -> primary address
	// freeform metadata for scope resolution
	instances map[string]InstanceInfo
	fleets    map[string]FleetInfo
	funcs     map[string]FunctionInfo
	proxies   map[string]ProxyInfo
}

type InstanceInfo struct {
	ID            string   `json:"id"`
	PrivateAddrs  []string `json:"private_addrs"`
	PublicAddr    string   `json:"public_addr,omitempty"`
	NATGatewayIDs []string `json:"nat_gateway_ids,omitempty"`
	SubnetID      string   `json:"subnet_id,omitempty"`
	VPCID         string   `json:"vpc_id,omitempty"`
	AccountID     string   `json:"account_id,omitempty"`
	IAMRole       string   `json:"iam_role,omitempty"`
}

type FleetInfo struct {
	ID            string   `json:"id"`
	Kind          string   `json:"kind"` // "eks", "ecs", "k8s"
	Nodes         []string `json:"nodes,omitempty"`
	PodCIDRs      []string `json:"pod_cidrs,omitempty"`
	NATGatewayIDs []string `json:"nat_gateway_ids,omitempty"`
	AccountID     string   `json:"account_id,omitempty"`
}

type FunctionInfo struct {
	ID            string   `json:"id"`
	ARN           string   `json:"arn,omitempty"`
	ENIs          []string `json:"enis,omitempty"`
	VPCID         string   `json:"vpc_id,omitempty"`
	NATGatewayIDs []string `json:"nat_gateway_ids,omitempty"`
	AccountID     string   `json:"account_id,omitempty"`
}

type ProxyInfo struct {
	ID         string   `json:"id"`
	CIDRs      []string `json:"cidrs"`
	AccountID  string   `json:"account_id,omitempty"`
	Forwarding bool     `json:"forwarding"`
}

// Resilience: lookups never fail; they degrade to a less specific answer and
// say why, so the engine can weigh confidence.

type SnapshotData struct {
	Records   []Record
	Instances []InstanceInfo
	Fleets    []FleetInfo
	Functions []FunctionInfo
	Proxies   []ProxyInfo
}

func BuildSnapshot(id string, now time.Time, data SnapshotData) *Snapshot {
	s := &Snapshot{
		ID:        id,
		BuiltAt:   now,
		exact:     make(map[netip.Addr]int, len(data.Records)),
		byInst:    make(map[string]string),
		instances: make(map[string]InstanceInfo, len(data.Instances)),
		fleets:    make(map[string]FleetInfo, len(data.Fleets)),
		funcs:     make(map[string]FunctionInfo, len(data.Functions)),
		proxies:   make(map[string]ProxyInfo, len(data.Proxies)),
	}
	for _, r := range data.Records {
		if !r.Live(now) {
			continue
		}
		s.records = append(s.records, r)
	}
	sort.Slice(s.records, func(i, j int) bool {
		// Longest prefix first so the most specific record wins.
		if s.records[i].Addr.Bits() != s.records[j].Addr.Bits() {
			return s.records[i].Addr.Bits() > s.records[j].Addr.Bits()
		}
		return s.records[i].Addr.Addr().Less(s.records[j].Addr.Addr())
	})
	for i, r := range s.records {
		if r.Addr.Bits() == r.Addr.Addr().BitLen() {
			s.exact[r.Addr.Addr()] = i
		}
		if r.InstanceID != "" {
			if _, ok := s.byInst[r.InstanceID]; !ok {
				s.byInst[r.InstanceID] = r.Addr.Addr().String()
			}
		}
	}
	for _, i := range data.Instances {
		s.instances[i.ID] = i
	}
	for _, f := range data.Fleets {
		s.fleets[f.ID] = f
	}
	for _, f := range data.Functions {
		s.funcs[f.ID] = f
	}
	for _, p := range data.Proxies {
		s.proxies[p.ID] = p
	}
	return s
}

func (s *Snapshot) Instance(id string) (InstanceInfo, bool) { i, ok := s.instances[id]; return i, ok }
func (s *Snapshot) Fleet(id string) (FleetInfo, bool)       { i, ok := s.fleets[id]; return i, ok }
func (s *Snapshot) Function(id string) (FunctionInfo, bool) { i, ok := s.funcs[id]; return i, ok }
func (s *Snapshot) Proxy(id string) (ProxyInfo, bool)       { i, ok := s.proxies[id]; return i, ok }
func (s *Snapshot) Len() int                                { return len(s.records) }

// Lookup resolves an address to the most specific record that contains it.
// The bool is false only when nothing contains the address.
func (s *Snapshot) Lookup(a netip.Addr) (Record, bool) {
	if a.IsValid() {
		if idx, ok := s.exact[a]; ok {
			return s.records[idx], true
		}
		for _, r := range s.records {
			if r.Addr.Contains(a) {
				return r, true
			}
		}
	}
	return Record{}, false
}

// InstanceAddr returns the recorded private address of an instance, used to
// tie a shared-egress call back to a scope when attestation corroborates it.
func (s *Snapshot) InstanceAddr(id string) (netip.Addr, bool) {
	str, ok := s.byInst[id]
	if !ok {
		return netip.Addr{}, false
	}
	a, err := netip.ParseAddr(str)
	return a, err == nil
}

// Store holds the current snapshot behind an atomic pointer so the hot path
// never blocks on a refresh. A failed refresh keeps the previous snapshot and
// reports staleness instead of returning errors — degraded attribution is
// better than a detector that stops seeing traffic during an API outage.
type Store struct {
	mu        sync.RWMutex
	cur       *Snapshot
	prev      *Snapshot
	maxAge    time.Duration
	lastErr   error
	lastErrAt time.Time
	refreshOK time.Time
}

func NewStore(maxAge time.Duration) *Store {
	if maxAge <= 0 {
		maxAge = 10 * time.Minute
	}
	return &Store{maxAge: maxAge}
}

func (s *Store) Set(snap *Snapshot) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cur != nil {
		s.prev = s.cur
	}
	s.cur = snap
	s.refreshOK = time.Now()
	s.lastErr = nil
}

func (s *Store) RecordError(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastErr = err
	s.lastErrAt = time.Now()
}

// Snapshot returns the current view plus a staleness assessment. Callers pass
// the result into the engine so incidents can carry attribution confidence
// (a stale inventory turns "external" into "unverifiable", not "safe").
func (s *Store) Snapshot() (*Snapshot, Staleness) {
	return s.SnapshotAt(time.Now())
}

// SnapshotAt evaluates staleness against an explicit clock. Replay and
// evaluation must use event time, not wall time, or a backtest over a
// historical attack sees every inventory as years stale.
func (s *Store) SnapshotAt(now time.Time) (*Snapshot, Staleness) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	st := Staleness{HasSnapshot: s.cur != nil}
	if s.cur != nil {
		st.Age = now.Sub(s.cur.BuiltAt)
		st.ID = s.cur.ID
		st.Stale = st.Age > s.maxAge
	}
	if s.lastErr != nil {
		st.LastError = s.lastErr.Error()
		st.LastErrorAt = s.lastErrAt
	}
	if !s.refreshOK.IsZero() {
		st.LastSuccess = s.refreshOK
	}
	return s.cur, st
}

type Staleness struct {
	HasSnapshot bool          `json:"has_snapshot"`
	ID          string        `json:"id,omitempty"`
	Age         time.Duration `json:"age_ns"`
	Stale       bool          `json:"stale"`
	LastSuccess time.Time     `json:"last_success"`
	LastError   string        `json:"last_error,omitempty"`
	LastErrorAt time.Time     `json:"last_error_at,omitempty"`
}
