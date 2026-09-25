// Package policy defines grant policies and the evaluator that decides
// whether a concrete edge request is allowed under a grant's policy.
package policy

import (
	"path"
	"strings"
	"time"
)

// SpendPolicy caps card spend in minor currency units.
type SpendPolicy struct {
	PerTx     int64    `json:"per_tx,omitempty"`
	Daily     int64    `json:"daily,omitempty"`
	Currency  string   `json:"currency,omitempty"`
	Merchants []string `json:"merchants,omitempty"`
}

// Policy is attached to a grant and evaluated per request.
type Policy struct {
	Hosts        []string     `json:"hosts,omitempty"`   // host globs, e.g. "*.github.com"
	Methods      []string     `json:"methods,omitempty"` // e.g. ["GET","POST"]; empty = any
	Paths        []string     `json:"paths,omitempty"`   // path globs; empty = any
	TTL          Duration     `json:"ttl,omitempty"`
	MaxUses      int          `json:"max_uses,omitempty"` // 0 = unlimited
	RequireHuman bool         `json:"require_human,omitempty"`
	Spend        *SpendPolicy `json:"spend,omitempty"`
}

// Duration is a JSON-friendly time.Duration (seconds).
type Duration int64

// D converts to time.Duration in seconds.
func (d Duration) D() time.Duration { return time.Duration(d) * time.Second }

// Request is the concrete request being authorized.
type Request struct {
	Host     string
	Method   string
	Path     string
	Merchant string
	Amount   int64
	Currency string
	Now      time.Time
}

// GrantView is the subset of a stored grant the evaluator needs.
type GrantView struct {
	ExpiresAt time.Time
	Uses      int
	MaxUses   int
}

// Decision is the evaluation result.
type Decision struct {
	Allow  bool   `json:"allow"`
	Reason string `json:"reason"`
}

func deny(reason string) Decision { return Decision{Allow: false, Reason: reason} }

var allow = Decision{Allow: true, Reason: "ok"}

// GlobMatch reports whether value matches a host/path glob pattern.
func GlobMatch(pattern, value string) bool { return globMatch(pattern, value) }

func globMatch(pattern, value string) bool {
	if pattern == "*" {
		return true
	}
	if ok, _ := path.Match(pattern, value); ok {
		return true
	}
	// path.Match's * doesn't cross "/"; treat a trailing /* as a subtree.
	if strings.HasSuffix(pattern, "/*") && strings.HasPrefix(value, pattern[:len(pattern)-1]) {
		return true
	}
	if strings.HasPrefix(pattern, "*.") && (value == pattern[2:] || strings.HasSuffix(value, pattern[1:])) {
		return true
	}
	return pattern == value
}

// Evaluate checks req against policy p and grant g.
func Evaluate(p *Policy, g *GrantView, req Request) Decision {
	if req.Now.After(g.ExpiresAt) {
		return deny("grant expired")
	}
	effectiveMax := g.MaxUses
	if p.MaxUses > 0 && (effectiveMax == 0 || p.MaxUses < effectiveMax) {
		effectiveMax = p.MaxUses
	}
	if effectiveMax > 0 && g.Uses >= effectiveMax {
		return deny("grant use limit reached")
	}
	if len(p.Hosts) > 0 && req.Host != "" {
		ok := false
		for _, h := range p.Hosts {
			if globMatch(h, req.Host) {
				ok = true
				break
			}
		}
		if !ok {
			return deny("host not allowed: " + req.Host)
		}
	}
	if len(p.Methods) > 0 && req.Method != "" {
		ok := false
		for _, m := range p.Methods {
			if strings.EqualFold(m, req.Method) {
				ok = true
				break
			}
		}
		if !ok {
			return deny("method not allowed: " + req.Method)
		}
	}
	if len(p.Paths) > 0 && req.Path != "" {
		ok := false
		for _, pat := range p.Paths {
			if globMatch(pat, req.Path) {
				ok = true
				break
			}
		}
		if !ok {
			return deny("path not allowed: " + req.Path)
		}
	}
	if p.Spend != nil && req.Amount > 0 {
		sp := p.Spend
		if sp.PerTx > 0 && req.Amount > sp.PerTx {
			return deny("amount exceeds per-transaction limit")
		}
		if len(sp.Merchants) > 0 {
			ok := false
			for _, m := range sp.Merchants {
				if globMatch(m, req.Merchant) {
					ok = true
					break
				}
			}
			if !ok {
				return deny("merchant not allowed: " + req.Merchant)
			}
		}
		if sp.Currency != "" && req.Currency != "" && !strings.EqualFold(sp.Currency, req.Currency) {
			return deny("currency mismatch")
		}
	}
	return allow
}
