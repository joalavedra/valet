// Package netguard is the SSRF hard fence for edges that dial
// agent-chosen hosts: it refuses non-publicly-routable destinations
// (loopback, private, link-local, CGNAT, metadata, reserved) before a
// connection is opened, and dials the resolved IP directly so DNS
// answers can't flip between check and connect.
package netguard

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"
)

// ErrBlocked marks a destination that failed the routability check.
var ErrBlocked = errors.New("upstream address is not publicly routable")

var blockedPrefixes = []netip.Prefix{
	// IPv4
	netip.MustParsePrefix("0.0.0.0/8"),      // this network
	netip.MustParsePrefix("10.0.0.0/8"),     // private
	netip.MustParsePrefix("100.64.0.0/10"),  // CGNAT
	netip.MustParsePrefix("127.0.0.0/8"),    // loopback
	netip.MustParsePrefix("169.254.0.0/16"), // link-local (cloud metadata)
	netip.MustParsePrefix("172.16.0.0/12"),  // private
	netip.MustParsePrefix("192.0.0.0/24"),   // IETF protocol assignments
	netip.MustParsePrefix("192.168.0.0/16"), // private
	netip.MustParsePrefix("198.18.0.0/15"),  // benchmark
	netip.MustParsePrefix("224.0.0.0/4"),    // multicast
	netip.MustParsePrefix("240.0.0.0/4"),    // reserved
	// IPv6
	netip.MustParsePrefix("::/128"),        // unspecified
	netip.MustParsePrefix("::1/128"),       // loopback
	netip.MustParsePrefix("64:ff9b::/96"),  // NAT64 (checked via embedded v4 too)
	netip.MustParsePrefix("2001:db8::/32"), // documentation
	netip.MustParsePrefix("fc00::/7"),      // ULA
	netip.MustParsePrefix("fe80::/10"),     // link-local
	netip.MustParsePrefix("ff00::/8"),      // multicast
}

// Blocked reports whether ip is not publicly routable. IPv4-mapped and
// NAT64 addresses are judged by their embedded IPv4 address.
func Blocked(ip netip.Addr) bool {
	if !ip.IsValid() {
		return true
	}
	if ip.Is4In6() {
		ip = ip.Unmap()
	}
	if ip.IsUnspecified() || ip.IsLoopback() || ip.IsPrivate() ||
		ip.IsLinkLocalUnicast() || ip.IsMulticast() {
		return true
	}
	if nat64 := netip.MustParsePrefix("64:ff9b::/96"); nat64.Contains(ip) {
		b := ip.As16()
		v4 := netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]})
		return Blocked(v4)
	}
	for _, p := range blockedPrefixes {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// DialContext returns a dialer that resolves the host once, vetoes any
// non-public address (unless allowPrivate), and dials the vetted IPs
// directly — the remote end sees the literal IP, so a second resolution
// can't produce a different (blocked) answer.
func DialContext(allowPrivate bool) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		var ips []netip.Addr
		if ip, err := netip.ParseAddr(host); err == nil {
			ips = []netip.Addr{ip}
		} else {
			ips, err = net.DefaultResolver.LookupNetIP(ctx, "ip", host)
			if err != nil {
				return nil, err
			}
		}
		if !allowPrivate {
			for _, ip := range ips {
				if Blocked(ip) {
					return nil, fmt.Errorf("%w: %s", ErrBlocked, host)
				}
			}
		}
		d := &net.Dialer{Timeout: 10 * time.Second}
		var lastErr error
		for _, ip := range ips {
			conn, err := d.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
			if err == nil {
				return conn, nil
			}
			lastErr = err
		}
		if lastErr == nil {
			lastErr = fmt.Errorf("no addresses for %s", host)
		}
		return nil, lastErr
	}
}

// Transport returns an http.Transport whose dial is gated by the
// routability check. Transports are cached per flag so callers share
// connection pools. Proxy is nil — proxies would bypass the dial-time
// check.
func Transport(allowPrivate bool) *http.Transport {
	if allowPrivate {
		return transportFor(true)
	}
	return transportFor(false)
}

var (
	transportMu sync.Mutex
	transports  = map[bool]*http.Transport{}
)

func transportFor(allowPrivate bool) *http.Transport {
	transportMu.Lock()
	defer transportMu.Unlock()
	if t := transports[allowPrivate]; t != nil {
		return t
	}
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.DialContext = DialContext(allowPrivate)
	t.Proxy = nil
	transports[allowPrivate] = t
	return t
}
