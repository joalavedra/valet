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
	"strings"
	"sync"
	"time"

	"github.com/chromedp/cdproto/target"

	cdpinput "github.com/chromedp/cdproto/input"
	"github.com/chromedp/chromedp"
	"github.com/pquerna/otp/totp"
)

// FieldRef names the credential field mapped to a DOM selector.
type FieldRef struct {
	Field string `json:"field"` // e.g. "username", "password", "totp"
	Role  string `json:"role,omitempty"`
}

// Result is the outcome reported back to the agent: a status, never values.
type Result struct {
	Status string   `json:"status"` // ok | need_otp | wrong_password | captcha | unknown
	Detail string   `json:"detail,omitempty"`
	Filled []string `json:"filled,omitempty"`
}

// Status values.
const (
	StatusOK            = "ok"
	StatusNeedOTP       = "need_otp"
	StatusWrongPassword = "wrong_password"
	StatusCaptcha       = "captcha"
	StatusUnknown       = "unknown"
)

// Filler types secret values into a remote browser over CDP.
type Filler interface {
	// PageURL returns the browser's current page URL.
	PageURL(ctx context.Context, cdpWSURL string) (string, error)
	// Fill types values into the selectors named by mapping (field -> CSS
	// selector), optionally clicking submit afterwards.
	Fill(ctx context.Context, cdpWSURL string, mapping map[string]string, submit string, values map[string]string) (Result, error)
}

// CDPFiller uses chromedp with a remote allocator to attach to an existing
// browser via its CDP websocket URL.
type CDPFiller struct {
	Timeout time.Duration

	mu       sync.Mutex
	sessions map[string]context.Context
}

// debugTargets lists the page targets of the debuggable browser at hostPort
// (derived from a CDP websocket URL).
func debugTargets(ctx context.Context, wsURL string) (browserWS string, pageID string, pageURL string, err error) {
	u, err := url.Parse(wsURL)
	if err != nil {
		return "", "", "", err
	}
	scheme := "http"
	if u.Scheme == "wss" {
		scheme = "https"
	}
	base := scheme + "://" + u.Host
	req, err := http.NewRequestWithContext(ctx, "GET", base+"/json/version", nil)
	if err != nil {
		return "", "", "", err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", "", "", err
	}
	defer resp.Body.Close()
	var ver struct {
		WebSocket string `json:"webSocketDebuggerUrl"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&ver); err != nil {
		return "", "", "", err
	}
	if strings.HasPrefix(u.Path, "/devtools/page/") {
		pageID = strings.TrimPrefix(u.Path, "/devtools/page/")
	}
	req2, err := http.NewRequestWithContext(ctx, "GET", base+"/json", nil)
	if err != nil {
		return "", "", "", err
	}
	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		return "", "", "", err
	}
	defer resp2.Body.Close()
	var targets []struct {
		ID   string `json:"id"`
		Type string `json:"type"`
		URL  string `json:"url"`
	}
	if err := json.NewDecoder(resp2.Body).Decode(&targets); err != nil {
		return "", "", "", err
	}
	for _, t := range targets {
		if t.Type == "page" && (pageID == "" || t.ID == pageID) {
			return ver.WebSocket, t.ID, t.URL, nil
		}
	}
	if pageID != "" {
		// Attached targets can vanish from /json in new headless mode;
		// the page ws URL already names the target.
		return ver.WebSocket, pageID, "", nil
	}
	return "", "", "", fmt.Errorf("no page target found")
}

// session returns a chromedp context attached to the page target, cached by
// (browser ws, page id). We never cancel the context: chromedp's cleanup
// closes the browser tab, which belongs to the agent.
func (f *CDPFiller) session(ctx context.Context, cdpWSURL string) (context.Context, error) {
	browserWS, pageID, _, err := debugTargets(ctx, cdpWSURL)
	if err != nil {
		return nil, err
	}
	key := browserWS + "#" + pageID
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.sessions == nil {
		f.sessions = map[string]context.Context{}
	}
	if s, ok := f.sessions[key]; ok {
		return s, nil
	}
	allocCtx, _ := chromedp.NewRemoteAllocator(ctx, browserWS)
	bctx, _ := chromedp.NewContext(allocCtx, chromedp.WithTargetID(target.ID(pageID)))
	f.sessions[key] = bctx
	return bctx, nil
}

// PageURL returns the URL of the browser's current page.
func (f *CDPFiller) PageURL(ctx context.Context, cdpWSURL string) (string, error) {
	_, _, pageURL, err := debugTargets(ctx, cdpWSURL)
	if err != nil {
		return "", err
	}
	if pageURL != "" {
		return pageURL, nil
	}
	s, err := f.session(ctx, cdpWSURL)
	if err != nil {
		return "", err
	}
	var loc string
	if err := chromedp.Run(s, chromedp.Location(&loc)); err != nil {
		return "", err
	}
	return loc, nil
}

// Fill types each field's secret into its selector, then clicks submit.
func (f *CDPFiller) Fill(ctx context.Context, cdpWSURL string, mapping map[string]string, submit string, values map[string]string) (Result, error) {
	bctx, err := f.session(ctx, cdpWSURL)
	if err != nil {
		return Result{Status: StatusUnknown, Detail: err.Error()}, err
	}

	res := Result{Status: StatusOK}
	for field, sel := range mapping {
		val, ok := values[field]
		if !ok {
			return Result{Status: StatusUnknown, Detail: "missing value for field " + field}, fmt.Errorf("missing value for field %q", field)
		}
		sel, val := sel, val
		if err := chromedp.Run(bctx,
			chromedp.WaitVisible(sel, chromedp.ByQuery),
			chromedp.Click(sel, chromedp.ByQuery),
			chromedp.ActionFunc(func(c context.Context) error {
				return cdpinput.InsertText(val).Do(c)
			}),
		); err != nil {
			res.Status = classify(err)
			res.Detail = err.Error()
			return res, fmt.Errorf("fill %s: %w", field, err)
		}
		res.Filled = append(res.Filled, field)
	}
	if submit != "" {
		if err := chromedp.Run(bctx, chromedp.Click(submit, chromedp.ByQuery)); err != nil {
			res.Status = classify(err)
			res.Detail = err.Error()
			return res, fmt.Errorf("submit: %w", err)
		}
		chromedp.Run(bctx, chromedp.Sleep(2*time.Second))
	}
	return res, nil
}

func classify(err error) string {
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "captcha"):
		return StatusCaptcha
	case strings.Contains(msg, "otp") || strings.Contains(msg, "totp") || strings.Contains(msg, "2fa"):
		return StatusNeedOTP
	case strings.Contains(msg, "password"):
		return StatusWrongPassword
	default:
		return StatusUnknown
	}
}

// TOTPCode generates a TOTP code from a base32 seed.
func TOTPCode(seed string) (string, error) {
	return totp.GenerateCode(strings.ToUpper(strings.TrimSpace(seed)), time.Now())
}

// Mask replaces every occurrence of a secret value in text with its
// {{handle}} placeholder so agent-visible output never contains secrets.
func Mask(text string, values map[string]string) string {
	for h, v := range values {
		if v == "" {
			continue
		}
		text = strings.ReplaceAll(text, v, "{{"+h+"}}")
	}
	return text
}
