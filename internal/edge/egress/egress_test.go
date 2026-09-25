package egress

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// fakeProxy accepts absolute-form requests, asserts proxy auth, injects a
// credential header, and forwards to the upstream.
func fakeProxy(t *testing.T, upstream string, wantAuth string, saw *map[string]string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.IsAbs() {
			if got := r.Header.Get("Proxy-Authorization"); got != wantAuth {
				t.Errorf("proxy auth: got %q want %q", got, wantAuth)
			}
		}
		req, err := http.NewRequest(r.Method, upstream+r.URL.RequestURI(), r.Body)
		if err != nil {
			t.Error(err)
			return
		}
		req.Header = r.Header.Clone()
		req.Header.Set("X-Injected", "1")
		resp, err := http.DefaultTransport.RoundTrip(req)
		if err != nil {
			t.Error(err)
			return
		}
		defer resp.Body.Close()
		for k, vv := range resp.Header {
			for _, v := range vv {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(resp.StatusCode)
		b := make([]byte, 0)
		buf := make([]byte, 32<<10)
		for {
			n, err := resp.Body.Read(buf)
			b = append(b, buf[:n]...)
			if err != nil {
				break
			}
		}
		w.Write(b)
	}))
}

func testClient(t *testing.T, proxy *httptest.Server, addr string) *Client {
	t.Helper()
	c, err := New(&Config{ProxyURL: "http://userinfo@127.0.0.1" + fmt.Sprintf(":%s", portOf(t, proxy)), Addr: addr, Token: "tok", Vault: "v"})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func portOf(t *testing.T, s *httptest.Server) string {
	t.Helper()
	parts := strings.Split(s.URL, ":")
	return parts[len(parts)-1]
}

func TestDoThroughProxy(t *testing.T) {
	var saw map[string]string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		saw = map[string]string{}
		for k := range r.Header {
			saw[k] = r.Header.Get(k)
		}
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Set-Cookie", "sid=secret")
		w.Header().Set("X-Ratelimit-Remaining", "9")
		fmt.Fprint(w, "upstream-body")
	}))
	defer upstream.Close()
	sawProxy := map[string]string{}
	proxy := fakeProxy(t, upstream.URL, "Basic dXNlcmluZm86", &sawProxy)
	defer proxy.Close()

	c := testClient(t, proxy, "")
	res, err := c.Do(context.Background(), Request{
		Method:  "GET",
		URL:     upstream.URL + "/x",
		Headers: map[string]string{"Proxy-Authorization": "Basic evil", "Host": "evil.com", "X-Custom": "1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Body != "upstream-body" {
		t.Fatalf("body %q", res.Body)
	}
	if _, ok := res.Headers["Set-Cookie"]; ok {
		t.Fatal("set-cookie leaked")
	}
	if res.Headers["X-Ratelimit-Remaining"] != "9" {
		t.Fatalf("ratelimit header missing: %v", res.Headers)
	}
	if saw["X-Injected"] != "1" {
		t.Fatal("proxy did not inject header")
	}
	if saw["X-Custom"] != "1" {
		t.Fatal("custom header not forwarded")
	}
	if pa := saw["Proxy-Authorization"]; pa != "Basic dXNlcmluZm86" {
		t.Fatalf("agent-supplied proxy auth not replaced: %q", pa)
	}
}

func TestDoTruncates(t *testing.T) {
	big := strings.Repeat("a", (1<<20)+10)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, big)
	}))
	defer upstream.Close()
	saw := map[string]string{}
	proxy := fakeProxy(t, upstream.URL, "Basic dXNlcmluZm86", &saw)
	defer proxy.Close()
	c := testClient(t, proxy, "")
	res, err := c.Do(context.Background(), Request{Method: "GET", URL: upstream.URL})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Truncated || len(res.Body) != 1<<20 {
		t.Fatalf("want truncated 1MiB, got %d truncated=%v", len(res.Body), res.Truncated)
	}
}

func TestDiscover(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/discover" {
			t.Errorf("path %q", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer tok" {
			t.Error("missing bearer")
		}
		if r.Header.Get("X-Vault") != "v" {
			t.Error("missing X-Vault")
		}
		fmt.Fprint(w, `{"vault":"v","services":[{"name":"echo","host":"example.com/api/*"}],"available_credentials":["KEY"]}`)
	}))
	defer api.Close()
	c, err := New(&Config{ProxyURL: "http://u@127.0.0.1:1", Addr: api.URL, Token: "tok", Vault: "v"})
	if err != nil {
		t.Fatal(err)
	}
	svcs, err := c.Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(svcs) != 1 || svcs[0].Name != "echo" || svcs[0].Host != "example.com/api/*" {
		t.Fatalf("services %+v", svcs)
	}
	svc, err := c.ServiceByName(context.Background(), "echo")
	if err != nil || svc == nil {
		t.Fatalf("ServiceByName: %v %v", svc, err)
	}
}

func TestDoDoesNotFollowRedirects(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/secret", http.StatusFound)
	}))
	defer upstream.Close()
	saw := map[string]string{}
	proxy := fakeProxy(t, upstream.URL, "Basic dXNlcmluZm86", &saw)
	defer proxy.Close()
	c := testClient(t, proxy, "")
	res, err := c.Do(context.Background(), Request{Method: "GET", URL: upstream.URL + "/"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != http.StatusFound {
		t.Fatalf("expected 302 passthrough, got %d", res.Status)
	}
	if res.Headers["Location"] != "/secret" {
		t.Fatalf("no Location header exposed: %v", res.Headers)
	}
}

func TestDoDropsConnectionNamedHeaders(t *testing.T) {
	saw := map[string]string{}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for k := range r.Header {
			saw[strings.ToLower(k)] = k
		}
	}))
	defer upstream.Close()
	proxy := fakeProxy(t, upstream.URL, "Basic dXNlcmluZm86", nil)
	defer proxy.Close()
	c := testClient(t, proxy, "")
	_, err := c.Do(context.Background(), Request{Method: "GET", URL: upstream.URL + "/", Headers: map[string]string{
		"Connection": "X-Smuggle, keep-alive", "X-Smuggle": "1", "X-Keep": "1",
	}})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := saw["x-smuggle"]; ok {
		t.Fatal("Connection-named header was forwarded")
	}
	if _, ok := saw["x-keep"]; !ok {
		t.Fatal("ordinary header missing")
	}
}

func TestDoTruncatedOmitsContentLength(t *testing.T) {
	big := strings.Repeat("a", maxBody+10)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		io.WriteString(w, big)
	}))
	defer upstream.Close()
	proxy := fakeProxy(t, upstream.URL, "Basic dXNlcmluZm86", nil)
	defer proxy.Close()
	c := testClient(t, proxy, "")
	res, err := c.Do(context.Background(), Request{Method: "GET", URL: upstream.URL + "/"})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Truncated {
		t.Fatal("expected truncated response")
	}
	for k := range res.Headers {
		if strings.EqualFold(k, "Content-Length") {
			t.Fatal("Content-Length emitted on truncated response")
		}
	}
}
