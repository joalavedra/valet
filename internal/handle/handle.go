// Package handle defines the opaque credential handle URI scheme.
package handle

import (
	"fmt"
	"regexp"
	"strings"
)

// Handle is an opaque URI referencing a stored credential: cred://<site>/<label>
// for logins and API keys, card://<label> for payment cards.
type Handle string

var segment = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

// New builds a handle of the given kind ("cred" or "card").
func New(kind, site, label string) (Handle, error) {
	label = strings.ToLower(strings.TrimSpace(label))
	site = strings.ToLower(strings.TrimSpace(site))
	switch kind {
	case "cred":
		if !segment.MatchString(site) || !segment.MatchString(label) {
			return "", fmt.Errorf("invalid cred handle %q/%q", site, label)
		}
		return Handle("cred://" + site + "/" + label), nil
	case "card":
		if !segment.MatchString(label) {
			return "", fmt.Errorf("invalid card handle %q", label)
		}
		return Handle("card://" + label), nil
	default:
		return "", fmt.Errorf("unknown handle kind %q", kind)
	}
}

// Parse splits a handle into kind, site ("" for cards) and label.
func Parse(h string) (kind, site, label string, err error) {
	if rest, ok := strings.CutPrefix(h, "cred://"); ok {
		parts := strings.SplitN(rest, "/", 2)
		if len(parts) != 2 {
			return "", "", "", fmt.Errorf("malformed cred handle %q", h)
		}
		return "cred", parts[0], parts[1], nil
	}
	if rest, ok := strings.CutPrefix(h, "api://"); ok {
		if rest == "" {
			return "", "", "", fmt.Errorf("malformed api handle %q", h)
		}
		return "api", "", rest, nil
	}
	if rest, ok := strings.CutPrefix(h, "card://"); ok {
		if rest == "" {
			return "", "", "", fmt.Errorf("malformed card handle %q", h)
		}
		return "card", "", rest, nil
	}
	return "", "", "", fmt.Errorf("unrecognized handle %q", h)
}

// Validate reports whether h is a well-formed handle.
func Validate(h string) error { _, _, _, err := Parse(h); return err }

func (h Handle) String() string { return string(h) }
