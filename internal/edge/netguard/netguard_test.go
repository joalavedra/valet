package netguard

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestBlocked(t *testing.T) {
	cases := []struct {
		ip      string
		blocked bool
	}{
		{"127.0.0.1", true},
		{"10.1.2.3", true},
		{"172.16.0.1", true},
		{"172.32.0.1", false},
		{"192.168.1.1", true},
		{"169.254.169.254", true},
		{"100.64.0.1", true},
		{"0.0.0.0", true},
		{"198.18.0.1", true},
		{"224.0.0.1", true},
		{"8.8.8.8", false},
		{"1.1.1.1", false},
		{"::1", true},
		{"::", true},
		{"fe80::1", true},
		{"fd00::1", true},
		{"ff02::1", true},
		{"2001:db8::1", true},
		{"2606:4700::1111", false},
		{"::ffff:127.0.0.1", true},
		{"::ffff:8.8.8.8", false},
		{"64:ff9b::7f00:1", true},   // NAT64 of 127.0.0.1
		{"64:ff9b::808:808", false}, // NAT64 of 8.8.8.8
	}
	for _, c := range cases {
		ip, err := netip.ParseAddr(c.ip)
		if err != nil {
			t.Fatalf("parse %s: %v", c.ip, err)
		}
		if got := Blocked(ip); got != c.blocked {
			t.Errorf("Blocked(%s) = %v, want %v", c.ip, got, c.blocked)
		}
	}
}

// countingListener accepts on a wrapped listener so tests can tell
// whether a dial ever reached the upstream.
type countingListener struct {
	net.Listener
	count *int32
}

func (l *countingListener) Accept() (net.Conn, error) {
	atomic.AddInt32(l.count, 1)
	return l.Listener.Accept()
}

func TestDialContextBlocksPrivate(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	count := new(int32)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	srv.Listener.Close()
	srv.Listener = &countingListener{ln, count}
	srv.Start()
	defer srv.Close()

	addr := srv.Listener.Addr().String()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if _, err := DialContext(false)(ctx, "tcp", addr); !errors.Is(err, ErrBlocked) {
		t.Fatalf("want ErrBlocked for %s, got %v", addr, err)
	}
	if *count != 0 {
		t.Fatal("connection reached the listener")
	}
	// "localhost" resolves to 127.0.0.1 — blocked by name as well.
	if _, err := DialContext(false)(ctx, "tcp", "localhost:"+addr[strings.LastIndex(addr, ":")+1:]); !errors.Is(err, ErrBlocked) {
		t.Fatalf("want ErrBlocked for localhost, got %v", err)
	}
	// allowPrivate dials through.
	conn, err := DialContext(true)(ctx, "tcp", addr)
	if err != nil {
		t.Fatalf("allowPrivate dial: %v", err)
	}
	conn.Close()
	if *count == 0 {
		t.Fatal("allowPrivate dial never reached the listener")
	}
}
