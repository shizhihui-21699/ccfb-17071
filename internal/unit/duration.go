package unit

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Duration accepts either a Go duration string ("15m", "600s") or a bare
// number of nanoseconds, because a hand-written config should read like prose
// while a machine-generated one may emit integers. Both are common, and a
// failure here is a startup error the operator cannot work around.
type Duration time.Duration

func (d Duration) Duration() time.Duration { return time.Duration(d) }

func (d *Duration) UnmarshalJSON(b []byte) error {
	s := strings.TrimSpace(string(b))
	if s == "null" || s == `""` {
		*d = 0
		return nil
	}
	if strings.HasPrefix(s, `"`) {
		var str string
		if err := json.Unmarshal(b, &str); err != nil {
			return err
		}
		if str == "" {
			*d = 0
			return nil
		}
		// Bare numbers in a string ("600" meaning seconds) are a common
		// authoring mistake; treat a unitless value as seconds.
		if onlyDigits(str) {
			secs, err := time.ParseDuration(str + "s")
			if err != nil {
				return fmt.Errorf("duration %q: %w", str, err)
			}
			*d = Duration(secs)
			return nil
		}
		dur, err := time.ParseDuration(str)
		if err != nil {
			return fmt.Errorf("duration %q: %w", str, err)
		}
		*d = Duration(dur)
		return nil
	}
	var ns int64
	if err := json.Unmarshal(b, &ns); err != nil {
		return fmt.Errorf("duration must be a string like \"15m\" or an integer of nanoseconds: %w", err)
	}
	*d = Duration(ns)
	return nil
}

func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Duration(d).String())
}

func onlyDigits(s string) bool {
	if s == "" {
		return false
	}
	if s[0] == '-' {
		s = s[1:]
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
