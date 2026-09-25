package card

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// PayRequest is the agent-supplied payment API call. Body and header values
// may contain {{card.<field>}} placeholders filled from the stored aliases.
type PayRequest struct {
	Method  string            `json:"method"`
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers,omitempty"`
	Body    string            `json:"body"`
}

// Response mirrors the upstream reply; body is capped at 256 KiB.
type Response struct {
	Status    int               `json:"status"`
	Headers   map[string]string `json:"headers"`
	Body      string            `json:"body"`
	Truncated bool              `json:"truncated,omitempty"`
}

const maxPayBody = 256 << 10

var placeholderRE = regexp.MustCompile(`\{\{\s*card\.([a-z_]+)\s*\}\}`)

// ErrCVCRequired is returned by Fill when a request references {{card.cvc}}
// but no CVC alias is stored — the merchant needs a human step-up.
var ErrCVCRequired = fmt.Errorf("cvc required (step-up)")

var cardFields = map[string]bool{
	"number": true, "exp_month": true, "exp_year": true, "holder": true, "cvc": true,
}

// Fill substitutes {{card.*}} placeholders in req.Body and req.Headers with
// the stored card fields. Unknown placeholders error; {{card.cvc}} requires
// a stored cvc field (otherwise the merchant needs a step-up).
func Fill(req PayRequest, fields map[string]string) (PayRequest, error) {
	sub := func(s string) (string, error) {
		var e error
		out := placeholderRE.ReplaceAllStringFunc(s, func(m string) string {
			name := placeholderRE.FindStringSubmatch(m)[1]
			if !cardFields[name] {
				e = fmt.Errorf("unknown card placeholder {{card.%s}}", name)
				return m
			}
			v := fields[name]
			if v == "" && name == "number" {
				v = fields["alias"] // legacy entries stored the PAN under "alias"
			}
			if v == "" {
				if name == "cvc" {
					e = ErrCVCRequired
				} else {
					e = fmt.Errorf("card field %q missing", name)
				}
				return m
			}
			return v
		})
		return out, e
	}
	var err error
	if req.Body, err = sub(req.Body); err != nil {
		return req, err
	}
	for k, v := range req.Headers {
		nv, err := sub(v)
		if err != nil {
			return req, err
		}
		req.Headers[k] = nv
	}
	return req, nil
}

var payRespHeaders = map[string]bool{
	"content-type": true, "content-length": true, "location": true,
	"x-request-id": true, "retry-after": true,
}

var payHopHeaders = map[string]bool{
	"connection": true, "keep-alive": true, "proxy-authenticate": true,
	"proxy-authorization": true, "proxy-connection": true, "te": true,
	"trailer": true, "transfer-encoding": true, "upgrade": true, "host": true,
}

var panRE = regexp.MustCompile(`\d[\d -]{11,30}\d`)
var cvcKeyRE = regexp.MustCompile(`"(?i:cv[cv]|security_code|csc)"\s*:\s*"?(\d{3,4})"?`)

func luhnOK(digits string) bool {
	sum := 0
	alt := false
	for i := len(digits) - 1; i >= 0; i-- {
		d := int(digits[i] - '0')
		if alt {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		alt = !alt
	}
	return sum%10 == 0
}

// redact scrubs leaked card material out of a response body: stored field
// values, Luhn-valid PANs (with optional separators), and values under
// cvc-like JSON keys.
func redact(body string, fields map[string]string) string {
	for _, v := range fields {
		if len(v) >= 4 {
			body = strings.ReplaceAll(body, v, "[redacted]")
		}
	}
	body = panRE.ReplaceAllStringFunc(body, func(m string) string {
		digits := strings.Map(func(r rune) rune {
			if r >= '0' && r <= '9' {
				return r
			}
			return -1
		}, m)
		if len(digits) < 13 || len(digits) > 19 || !luhnOK(digits) {
			return m
		}
		return "****" + digits[len(digits)-4:]
	})
	body = cvcKeyRE.ReplaceAllString(body, `"***"`)
	return body
}

// Do sends req via p.Transport(). Redirects are never followed (they could
// leave the evaluated merchant host); the response body is capped at 256KiB
// and redacted of any card material that leaks back.
// Errors never include the request or response body.
func Do(ctx context.Context, p Provider, req PayRequest, fields map[string]string) (*Response, error) {
	// Only secrets get verbatim redaction; non-secret fields like expiry or
	// holder would over-redact ordinary response text (e.g. "2030").
	secrets := map[string]string{}
	for _, k := range []string{"number", "cvc", "alias"} {
		if v := fields[k]; v != "" {
			secrets[k] = v
		}
	}
	tr, err := p.Transport()
	if err != nil {
		return nil, err
	}
	method := strings.ToUpper(req.Method)
	if method == "" {
		method = http.MethodPost
	}
	var body io.Reader
	if req.Body != "" {
		body = strings.NewReader(req.Body)
	}
	hreq, err := http.NewRequestWithContext(ctx, method, req.URL, body)
	if err != nil {
		return nil, err
	}
	// Hop-by-hop and proxy-scoped headers (including any named by the
	// agent's Connection header) never reach the proxy.
	connNames := map[string]bool{}
	for _, tok := range strings.Split(req.Headers["Connection"]+","+req.Headers["connection"], ",") {
		if t := strings.ToLower(strings.TrimSpace(tok)); t != "" {
			connNames[t] = true
		}
	}
	for k, v := range req.Headers {
		lk := strings.ToLower(k)
		if payHopHeaders[lk] || connNames[lk] || strings.HasPrefix(lk, "proxy-") {
			continue
		}
		hreq.Header.Set(k, v)
	}
	hc := &http.Client{
		Transport: tr,
		Timeout:   30 * time.Second,
		// Redirects go back to the caller; following them could leave the
		// merchant host the grant was evaluated for.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	resp, err := hc.Do(hreq)
	if err != nil {
		return nil, fmt.Errorf("pay request failed")
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxPayBody+1))
	if err != nil {
		return nil, fmt.Errorf("pay read failed")
	}
	out := &Response{Status: resp.StatusCode, Headers: map[string]string{}, Body: redact(string(raw), secrets)}
	if len(raw) > maxPayBody {
		out.Body = redact(string(raw[:maxPayBody]), secrets)
		out.Truncated = true
	}
	for k, vv := range resp.Header {
		lk := strings.ToLower(k)
		if payRespHeaders[lk] || strings.HasPrefix(lk, "x-ratelimit-") {
			if out.Truncated && lk == "content-length" {
				continue
			}
			out.Headers[k] = strings.Join(vv, ", ")
		}
	}
	return out, nil
}
