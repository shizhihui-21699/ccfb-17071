package config

import (
	"fmt"
	"net/netip"
)

func parsePrefix(s string) (netip.Prefix, error) {
	if p, err := netip.ParsePrefix(s); err == nil {
		return p, nil
	}
	if a, err := netip.ParseAddr(s); err == nil {
		return netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen()), nil
	}
	return netip.Prefix{}, fmt.Errorf("config: %q is not an address or CIDR", s)
}
