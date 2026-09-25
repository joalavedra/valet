// Package browser implements the browser edge: Valet connects to an
// agent-controlled Chrome session over CDP and types real secret values
// into form fields itself, so they never enter the agent's context.
package browser

import (
	"context"
	"encoding/json"
	"fmt"
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

func debugTargets(ctx context.Context, wsURL string) (browserWS, pageID, pageURL string, err error) {
	u, err := url.Parse(wsURL)
	if err != nil || u.Host == "" {
		return "", "", "", fmt.Errorf("invalid cdp websocket url")
	}
	base := "http://" + u.Host
	if u.Scheme == "wss" {
		base = "https://" + u.Host
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
	if err != nil {
		return "", err
	}
	return pageURL, nil
}

// classifyOutcome is pure so login outcome behavior can be table-tested.
func classifyOutcome(urlBefore, urlAfter string, hasPassword, hasOTP, hasCaptcha bool, text string) string {
	if hasOTP {
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
		// Set the field value in-page: Input.insertText depends on focus
		// and synthesized events, which are unreliable in headless Chrome.
		// Value assignment plus input/change events works for plain and
		// framework-managed fields alike.
		js := fmt.Sprintf(`(function(){var e=document.querySelector(%q); if(!e) return 'no field'; e.value=%q; e.dispatchEvent(new Event('input',{bubbles:true})); e.dispatchEvent(new Event('change',{bubbles:true})); return 'ok'})()`, sel, val)
		actions = append(actions,
			chromedp.WaitVisible(sel, chromedp.ByQuery),
			chromedp.Evaluate(js, nil))
	}
	if submit != "" {
		// A DOM click() is used rather than Input.dispatchMouseEvent: in
		// headless Chrome the synthesized click does not reliably reach
		// submit buttons.
		actions = append(actions, chromedp.Evaluate(fmt.Sprintf(`document.querySelector(%q) && document.querySelector(%q).click()`, submit, submit), nil))
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
		status := classifyOutcome(before, after, hasPassword, hasOTP, hasCaptcha, text)
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
