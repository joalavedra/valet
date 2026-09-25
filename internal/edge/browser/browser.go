// Package browser implements the browser edge: Valet connects to an
// agent-controlled Chrome session over CDP and types real secret values
// into form fields itself, so they never enter the agent's context.
package browser

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/chromedp/cdproto/target"
	"github.com/chromedp/chromedp"
	"github.com/pquerna/otp/totp"
)

// Result is the outcome reported back to the agent, never values.
type Result struct {
	Status string   `json:"status"`
	Detail string   `json:"detail,omitempty"`
	Filled []string `json:"filled,omitempty"`
}

const (
	StatusOK            = "ok"
	StatusNeedOTP       = "need_otp"
	StatusWrongPassword = "wrong_password"
	StatusCaptcha       = "captcha"
	StatusHostMismatch  = "host_mismatch"
	StatusUnknown       = "unknown"
)

// Filler types values into selectors in an existing browser session.
type Filler interface {
	PageURL(ctx context.Context, cdpWSURL string) (string, error)
	// ResolvePage returns a page-level devtools ws URL for the target whose
	// URL matches pageURL, or an error when no unique target matches.
	ResolvePage(ctx context.Context, cdpURL, pageURL string) (string, error)
	Fill(ctx context.Context, cdpWSURL, expectedHost string, mapping map[string]string, submit string, values map[string]string) (Result, error)
}

type sessionEntry struct {
	ctx      context.Context
	lastUsed time.Time
}

// CDPFiller attaches to existing page targets. Sessions are intentionally
// rooted in Background: request cancellation must not close an agent tab.
type CDPFiller struct {
	Timeout time.Duration
	mu      sync.Mutex
	sess    map[string]*sessionEntry
	stop    chan struct{}
	once    sync.Once
}

func (f *CDPFiller) startSweeper() {
	f.once.Do(func() {
		f.stop = make(chan struct{})
		go func() {
			t := time.NewTicker(time.Minute)
			defer t.Stop()
			for {
				select {
				case <-t.C:
					f.evictIdle()
				case <-f.stop:
					return
				}
			}
		}()
	})
}

func (f *CDPFiller) evictIdle() {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.sess == nil {
		return
	}
	cutoff := time.Now().Add(-5 * time.Minute)
	for k, s := range f.sess {
		if s.lastUsed.Before(cutoff) {
			// Do not call chromedp.Cancel here: the chromedp source closes
			// attached targets on cancellation. Keeping the session alive is
			// safer than closing the agent's tab.
			delete(f.sess, k)
		}
	}
	for len(f.sess) > 16 {
		var oldest string
		var at time.Time
		for k, s := range f.sess {
			if oldest == "" || s.lastUsed.Before(at) {
				oldest, at = k, s.lastUsed
			}
		}
		delete(f.sess, oldest)
	}
}

// cdpHTTPBase maps a cdp base URL (ws, wss, http, https) to the http(s) URL
// used for /json queries, plus the ws scheme for building page-level URLs.
func cdpHTTPBase(raw string) (base, wsScheme string, err error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "", "", fmt.Errorf("invalid cdp url")
	}
	switch u.Scheme {
	case "ws", "http":
		return "http://" + u.Host, "ws", nil
	case "wss", "https":
		return "https://" + u.Host, "wss", nil
	default:
		return "", "", fmt.Errorf("unsupported cdp url scheme %q", u.Scheme)
	}
}

// listPages returns page targets advertised by the browser's /json endpoint.
func (f *CDPFiller) listPages(ctx context.Context, cdpURL string) (wsScheme, hostport string, pages []struct {
	ID  string
	URL string
}, err error) {
	base, scheme, err := cdpHTTPBase(cdpURL)
	if err != nil {
		return "", "", nil, err
	}
	u, err := url.Parse(cdpURL)
	if err != nil {
		return "", "", nil, err
	}
	var targets []struct {
		ID   string `json:"id"`
		Type string `json:"type"`
		URL  string `json:"url"`
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/json", nil)
	if err != nil {
		return "", "", nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", "", nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return "", "", nil, fmt.Errorf("cdp status %d", resp.StatusCode)
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&targets); err != nil {
		return "", "", nil, err
	}
	pages = make([]struct{ ID, URL string }, 0)
	for _, t := range targets {
		if t.Type == "page" {
			pages = append(pages, struct{ ID, URL string }{t.ID, t.URL})
		}
	}
	return scheme, u.Host, pages, nil
}

func debugTargets(ctx context.Context, wsURL string) (browserWS, pageID, pageURL string, err error) {
	u, err := url.Parse(wsURL)
	if err != nil || u.Host == "" {
		return "", "", "", fmt.Errorf("invalid cdp websocket url")
	}
	base, _, err := cdpHTTPBase(wsURL)
	if err != nil {
		return "", "", "", err
	}
	get := func(path string, v any) error {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+path, nil)
		if err != nil {
			return err
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode >= 400 {
			return fmt.Errorf("cdp status %d", resp.StatusCode)
		}
		return json.NewDecoder(resp.Body).Decode(v)
	}
	var ver struct {
		WebSocket string `json:"webSocketDebuggerUrl"`
	}
	if err := get("/json/version", &ver); err != nil {
		return "", "", "", err
	}
	requested := ""
	if strings.HasPrefix(u.Path, "/devtools/page/") {
		requested = strings.TrimPrefix(u.Path, "/devtools/page/")
	} else if strings.HasPrefix(u.Path, "/devtools/browser/") {
		// Browser-level URLs are accepted only when there is exactly one page.
	} else if u.Path != "" && u.Path != "/" {
		return "", "", "", fmt.Errorf("page-level cdp_ws_url required")
	}
	var targets []struct {
		ID   string `json:"id"`
		Type string `json:"type"`
		URL  string `json:"url"`
	}
	if err := get("/json", &targets); err != nil {
		return "", "", "", err
	}
	pages := make([]struct{ ID, URL string }, 0)
	for _, t := range targets {
		if t.Type == "page" {
			pages = append(pages, struct{ ID, URL string }{t.ID, t.URL})
		}
	}
	if requested != "" {
		for _, p := range pages {
			if p.ID == requested {
				return ver.WebSocket, p.ID, p.URL, nil
			}
		}
		return "", "", "", fmt.Errorf("page target not found")
	}
	if len(pages) != 1 {
		return "", "", "", fmt.Errorf("page-level cdp_ws_url required")
	}
	return ver.WebSocket, pages[0].ID, pages[0].URL, nil
}

func (f *CDPFiller) session(ctx context.Context, ws string) (context.Context, error) {
	f.startSweeper()
	f.mu.Lock()
	if s, ok := f.sess[ws]; ok {
		// Hit the cache before rediscovering targets: attached pages are
		// hidden from /json in headless Chrome.
		s.lastUsed = time.Now()
		f.mu.Unlock()
		return s.ctx, nil
	}
	f.mu.Unlock()
	browserWS, pageID, _, err := debugTargets(ctx, ws)
	if err != nil {
		return nil, err
	}
	f.mu.Lock()
	if f.sess == nil {
		f.sess = map[string]*sessionEntry{}
	}
	if s, ok := f.sess[ws]; ok {
		s.lastUsed = time.Now()
		f.mu.Unlock()
		return s.ctx, nil
	}
	f.mu.Unlock()
	// Allocate outside the lock: this dials the browser websocket and may
	// block, while evictIdle also needs f.mu.
	allocCtx, _ := chromedp.NewRemoteAllocator(context.Background(), browserWS, chromedp.NoModifyURL)
	s, _ := chromedp.NewContext(allocCtx, chromedp.WithTargetID(target.ID(pageID)))
	// Attach eagerly under the session ctx. The first Run binds the target
	// executor and its listeners to the ctx it is given (chromedp.go
	// attachTarget/newTarget), so a per-fill WithTimeout child used here
	// would kill the session when it expires or is canceled.
	done := make(chan error, 1)
	go func() {
		done <- chromedp.Run(s, chromedp.ActionFunc(func(context.Context) error { return nil }))
	}()
	select {
	case err := <-done:
		if err != nil {
			return nil, err
		}
	case <-time.After(f.timeout()):
		return nil, fmt.Errorf("cdp attach timed out")
	}
	f.mu.Lock()
	f.sess[ws] = &sessionEntry{ctx: s, lastUsed: time.Now()}
	f.mu.Unlock()
	f.evictIdle()
	return s, nil
}

// PageURL returns the current page URL.
func (f *CDPFiller) PageURL(ctx context.Context, ws string) (string, error) {
	_, _, pageURL, err := debugTargets(ctx, ws)
	if err == nil {
		return pageURL, nil
	}
	// Attached pages vanish from /json in headless Chrome; ask the cached
	// session for its location instead of failing.
	f.mu.Lock()
	se := f.sess[ws]
	f.mu.Unlock()
	if se == nil || se.ctx == nil {
		return "", err
	}
	var loc string
	lctx, cancel := context.WithTimeout(se.ctx, 3*time.Second)
	defer cancel()
	if lerr := chromedp.Run(lctx, chromedp.Location(&loc)); lerr != nil {
		return "", err
	}
	return loc, nil
}

// pageTargetID extracts the trailing segment of a devtools/page/ ws URL.
func pageTargetID(ws string) string {
	if i := strings.LastIndex(ws, "/"); i >= 0 {
		return ws[i+1:]
	}
	return ws
}

// normalizePageURL drops the fragment and trailing slash for comparison.
func normalizePageURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	u.Fragment = ""
	u.RawFragment = ""
	s := u.String()
	return strings.TrimRight(s, "/")
}

// samePageNoQuery compares scheme, host and path, ignoring query and fragment.
func samePageNoQuery(a, b string) bool {
	ua, err1 := url.Parse(a)
	ub, err2 := url.Parse(b)
	if err1 != nil || err2 != nil {
		return false
	}
	return ua.Scheme == ub.Scheme && ua.Host == ub.Host && ua.Path == ub.Path
}

// ResolvePage picks the page target whose URL matches pageURL and returns its
// page-level ws URL. Cached sessions count as candidates too, since attached
// pages can disappear from /json in headless Chrome.
func (f *CDPFiller) ResolvePage(ctx context.Context, cdpURL, pageURL string) (string, error) {
	scheme, hostport, pages, err := f.listPages(ctx, cdpURL)
	if err != nil {
		return "", err
	}
	type cand struct{ ws, url string }
	cands := make([]cand, 0, len(pages))
	for _, p := range pages {
		cands = append(cands, cand{ws: scheme + "://" + hostport + "/devtools/page/" + p.ID, url: p.URL})
	}
	f.mu.Lock()
	cached := make([]cand, 0, len(f.sess))
	for ws := range f.sess {
		cached = append(cached, cand{ws: ws})
	}
	f.mu.Unlock()
	for _, c := range cached {
		// Only sessions against this CDP endpoint count as candidates.
		if u, err := url.Parse(c.ws); err != nil || u.Host != hostport {
			continue
		}
		// Attached pages may be hidden from /json; ask the page itself.
		var loc string
		f.mu.Lock()
		se := f.sess[c.ws]
		f.mu.Unlock()
		if se == nil || se.ctx == nil {
			continue
		}
		lctx, cancel := context.WithTimeout(se.ctx, 3*time.Second)
		if err := chromedp.Run(lctx, chromedp.Location(&loc)); err == nil {
			c.url = loc
		}
		cancel()
		seen := false
		for _, e := range cands {
			if pageTargetID(e.ws) == pageTargetID(c.ws) {
				seen = true
			}
		}
		if !seen {
			cands = append(cands, c)
		}
	}
	want := normalizePageURL(pageURL)
	var matches []cand
	for _, c := range cands {
		if normalizePageURL(c.url) == want {
			matches = append(matches, c)
		}
	}
	if len(matches) == 0 {
		for _, c := range cands {
			if samePageNoQuery(c.url, pageURL) {
				matches = append(matches, c)
			}
		}
	}
	if len(matches) == 0 {
		wantHost := ""
		if u, err := url.Parse(pageURL); err == nil {
			wantHost = u.Hostname()
		}
		for _, c := range cands {
			if u, err := url.Parse(c.url); err == nil && u.Hostname() == wantHost {
				matches = append(matches, c)
			}
		}
	}
	if len(matches) == 0 {
		return "", fmt.Errorf("page not found")
	}
	if len(matches) > 1 {
		return "", fmt.Errorf("ambiguous page")
	}
	return matches[0].ws, nil
}

// classifyOutcome is pure so login outcome behavior can be table-tested.
func classifyOutcome(urlBefore, urlAfter string, hasPassword, hasOTP, hasCaptcha bool, text string, filledOTP bool) string {
	// When we just typed the OTP ourselves, an OTP field on the unchanged
	// page is the form we filled, not a challenge — keep polling and let
	// the wrong_password/unknown checks settle it at the deadline.
	if hasOTP && !(filledOTP && urlAfter == urlBefore) {
		return StatusNeedOTP
	}
	if hasCaptcha {
		return StatusCaptcha
	}
	if urlAfter != urlBefore || !hasPassword {
		return StatusOK
	}
	lower := strings.ToLower(text)
	for _, word := range []string{"invalid", "incorrect", "wrong", "not recognized", "try again"} {
		if strings.Contains(lower, word) {
			return StatusWrongPassword
		}
	}
	return StatusUnknown
}

func (f *CDPFiller) timeout() time.Duration {
	if f.Timeout > 0 {
		return f.Timeout
	}
	return 30 * time.Second
}

// Fill checks the live page host immediately before typing and reports the
// login outcome after submit without exposing CDP errors or values.
func (f *CDPFiller) Fill(ctx context.Context, ws, expectedHost string, mapping map[string]string, submit string, values map[string]string) (Result, error) {
	s, err := f.session(ctx, ws)
	if err != nil {
		return Result{Status: StatusUnknown}, err
	}
	deadline, cancel := context.WithTimeout(s, f.timeout())
	defer cancel()
	var before string
	res := Result{Status: StatusOK}
	actions := []chromedp.Action{chromedp.Location(&before), chromedp.ActionFunc(func(context.Context) error {
		u, err := url.Parse(before)
		if err != nil || u.Hostname() == "" || !strings.EqualFold(u.Hostname(), expectedHost) {
			res.Status = StatusHostMismatch
			return fmt.Errorf("host mismatch")
		}
		return nil
	})}
	fields := make([]string, 0, len(mapping))
	for field := range mapping {
		fields = append(fields, field)
	}
	sort.Strings(fields)
	for _, field := range fields {
		val, ok := values[field]
		if !ok {
			return Result{Status: StatusUnknown}, fmt.Errorf("missing value for field %q", field)
		}
		sel := mapping[field]
		// chromedp.SetValue passes the value as a typed runtime.CallFunctionOn
		// argument (no string interpolation into script source) and its
		// embedded setAttribute.js dispatches input+change events.
		actions = append(actions,
			chromedp.WaitVisible(sel, chromedp.ByQuery),
			chromedp.SetValue(sel, val, chromedp.ByQuery))
	}
	if submit != "" {
		// A DOM click() is used rather than Input.dispatchMouseEvent: in
		// headless Chrome the synthesized click does not reliably reach
		// submit buttons.
		selJSON, _ := json.Marshal(submit)
		actions = append(actions, chromedp.Evaluate(fmt.Sprintf(`var e = document.querySelector(%s); if (e) e.click()`, selJSON), nil))
	}
	if err := chromedp.Run(deadline, actions...); err != nil {
		return res, err
	}
	res.Filled = fields
	if submit == "" {
		return res, nil
	}
	for end := time.Now().Add(8 * time.Second); time.Now().Before(end); time.Sleep(200 * time.Millisecond) {
		var after, text string
		var hasPassword, hasOTP, hasCaptcha bool
		if err := chromedp.Run(deadline, chromedp.Location(&after), chromedp.Evaluate(`document.body.innerText`, &text), chromedp.Evaluate(`!!document.querySelector('input[type="password"]')`, &hasPassword), chromedp.Evaluate(`!!document.querySelector('input[autocomplete="one-time-code"], input[name*="otp" i], input[name*="code" i]')`, &hasOTP), chromedp.Evaluate(`!!document.querySelector('iframe[src*="captcha" i], .g-recaptcha, .h-captcha')`, &hasCaptcha)); err != nil {
			return res, err
		}
		_, filledOTP := mapping["otp"]
		status := classifyOutcome(before, after, hasPassword, hasOTP, hasCaptcha, text, filledOTP)
		// Keep polling on wrong_password/unknown: navigation can still be
		// in flight, and failure keywords may appear in unrelated page
		// text while the old DOM is still up.
		if status != StatusUnknown && status != StatusWrongPassword {
			res.Status = status
			return res, nil
		}
		res.Status = status
	}
	return res, nil
}

// TOTPCode generates a TOTP code from a base32 seed.
func TOTPCode(seed string) (string, error) {
	return totp.GenerateCode(strings.ToUpper(strings.TrimSpace(seed)), time.Now())
}

// Mask replaces secret values with handle placeholders.
func Mask(text string, values map[string]string) string {
	for h, v := range values {
		if v != "" {
			text = strings.ReplaceAll(text, v, "{{"+h+"}}")
		}
	}
	return text
}
