// Package browser implements the browser edge: Valet connects to an
// agent-controlled Chrome session over CDP and types real secret values
// into form fields itself, so they never enter the agent's context.
package browser

import (
	"context"
	"fmt"
	"strings"
	"time"

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
	Fill(ctx context.Context, cdpWSURL string, mapping map[string]FieldRef, values map[string]string) (Result, error)
}

// CDPFiller uses chromedp with a remote allocator to attach to an existing
// browser via its CDP websocket URL.
type CDPFiller struct {
	// TOTPValues maps a field name (e.g. "totp") to a TOTP seed; when a
	// mapping requests a totp field and values has no plain code, the seed
	// is used to generate one in-process.
	Timeout time.Duration
}

// Fill types each mapped field's secret into its selector.
func (f *CDPFiller) Fill(ctx context.Context, cdpWSURL string, mapping map[string]FieldRef, values map[string]string) (Result, error) {
	timeout := f.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	allocCtx, cancel := chromedp.NewRemoteAllocator(ctx, cdpWSURL)
	defer cancel()
	bctx, cancel2 := chromedp.NewContext(allocCtx)
	defer cancel2()
	bctx, cancel3 := context.WithTimeout(bctx, timeout)
	defer cancel3()

	res := Result{Status: StatusOK}
	for sel, ref := range mapping {
		val, ok := values[ref.Field]
		if !ok {
			return Result{Status: StatusUnknown, Detail: "missing value for field " + ref.Field}, fmt.Errorf("missing value for field %q", ref.Field)
		}
		sel, val := sel, val
		if err := chromedp.Run(bctx,
			chromedp.WaitVisible(sel, chromedp.ByQuery),
			chromedp.ActionFunc(func(c context.Context) error {
				return cdpinput.InsertText(val).Do(c)
			}),
		); err != nil {
			res.Status = classify(err)
			res.Detail = err.Error()
			return res, fmt.Errorf("fill %s: %w", ref.Field, err)
		}
		res.Filled = append(res.Filled, ref.Field)
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
