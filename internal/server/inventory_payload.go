package server

import (
	"fmt"
	"net/netip"
	"time"

	"credwatch/internal/attrib"
	"credwatch/internal/inventory"
	"credwatch/internal/model"
)

// SnapshotPayload is the JSON inventory format accepted on /v1/inventory and
// produced by a provider collector. It is deliberately a flat superset of the
// inventory package's types so operators can hand-write it.
type SnapshotPayload struct {
	Snapshot string `json:"snapshot"`

	Instances []inventory.InstanceInfo `json:"instances"`
	Fleets    []inventory.FleetInfo    `json:"fleets"`
	Functions []inventory.FunctionInfo `json:"functions"`
	Proxies   []inventory.ProxyInfo    `json:"proxies"`

	Records []RecordPayload `json:"records"`
}

type RecordPayload struct {
	CIDR         string `json:"cidr"`
	Kind         string `json:"kind"`
	Specificity  string `json:"specificity"`
	InstanceID   string `json:"instance_id"`
	FleetID      string `json:"fleet_id"`
	FunctionID   string `json:"function_id"`
	ProxyID      string `json:"proxy_id"`
	SubnetID     string `json:"subnet_id"`
	NATGateway   string `json:"nat_gateway"`
	AccountID    string `json:"account_id"`
	Zone         string `json:"zone"`
	SharedEgress bool   `json:"shared_egress"`
	Blocklisted  bool   `json:"blocklisted"`
	Source       string `json:"source"`
	ValidUntil   string `json:"valid_until,omitempty"`
}

func (p SnapshotPayload) Build(now time.Time) (*inventory.Snapshot, error) {
	id := p.Snapshot
	if id == "" {
		id = fmt.Sprintf("snap-%d", now.Unix())
	}
	data := inventory.SnapshotData{
		Instances: p.Instances,
		Fleets:    p.Fleets,
		Functions: p.Functions,
		Proxies:   p.Proxies,
	}
	for i, r := range p.Records {
		pref, err := netip.ParsePrefix(r.CIDR)
		if err != nil {
			if a, e2 := netip.ParseAddr(r.CIDR); e2 == nil {
				a = a.Unmap()
				pref = netip.PrefixFrom(a, a.BitLen())
			} else {
				return nil, fmt.Errorf("record %d: bad cidr %q: %w", i, r.CIDR, err)
			}
		}
		kind := model.OriginKind(r.Kind)
		if kind == "" {
			kind = inferKind(r)
		}
		rec := inventory.Record{
			Addr:         pref,
			Kind:         kind,
			Specificity:  model.Specificity(r.Specificity),
			InstanceID:   r.InstanceID,
			FleetID:      r.FleetID,
			FunctionID:   r.FunctionID,
			ProxyID:      r.ProxyID,
			SubnetID:     r.SubnetID,
			NATGateway:   r.NATGateway,
			AccountID:    r.AccountID,
			Zone:         r.Zone,
			SharedEgress: r.SharedEgress,
			Blocklisted:  r.Blocklisted,
			Source:       firstNonEmptyStr(r.Source, "inventory"),
		}
		if rec.Specificity == "" {
			rec.Specificity = inferSpecificity(rec)
		}
		if rec.Zone == "" {
			rec.Zone = "account"
		}
		if r.ValidUntil != "" {
			if t, err := time.Parse(time.RFC3339, r.ValidUntil); err == nil {
				rec.ValidUntil = t
			}
		}
		data.Records = append(data.Records, rec)
	}
	return inventory.BuildSnapshot(id, now, data), nil
}

func inferKind(r RecordPayload) model.OriginKind {
	switch {
	case r.InstanceID != "":
		return model.OriginInstance
	case r.FleetID != "":
		return model.OriginFleetPod
	case r.FunctionID != "":
		return model.OriginFunctionENI
	case r.ProxyID != "":
		return model.OriginProxy
	case r.NATGateway != "":
		return model.OriginNAT
	}
	return model.OriginInstance
}

func inferSpecificity(r inventory.Record) model.Specificity {
	switch r.Kind {
	case model.OriginInstance, model.OriginFunctionENI:
		return model.SpecExact
	case model.OriginFleetPod:
		return model.SpecScoped
	case model.OriginNAT, model.OriginProxy, model.OriginVPCEndpoint:
		return model.SpecAmbiguous
	}
	return model.SpecNone
}

func firstNonEmptyStr(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// compile-time assertion that attrib config remains compatible with the
// server's needs; kept here so refactors break in one place.
var _ = attrib.Config{}
