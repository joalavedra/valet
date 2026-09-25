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
			if v == "" {
				if name == "cvc" {
					e = fmt.Errorf("cvc required (step-up)")
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

// Do sends req via p.Transport(). Redirects are never followed (they could
// leave the evaluated merchant host); the response body is capped at 256KiB.
// Errors never include the request or response body.
func Do(ctx context.Context, p Provider, req PayRequest) (*Response, error) {
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
	for k, v := range req.Headers {
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
	out := &Response{Status: resp.StatusCode, Headers: map[string]string{}, Body: string(raw)}
	if len(raw) > maxPayBody {
		out.Body = string(raw[:maxPayBody])
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
