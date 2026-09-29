package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// sseEmit writes one Server-Sent-Event.
type sseEmit func(event string, data any)

func emitJSON(w http.ResponseWriter, flusher http.Flusher, event string, data any) {
	b, _ := json.Marshal(data)
	fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event, b)
	flusher.Flush()
}

const systemPrompt = `You are a shopping assistant for the Valet demo store.
You never see card numbers: payment goes through Valet, which asks the
owner to approve purchases on their phone. Keep answers short. Before
calling checkout, confirm what you are about to buy — unless the user was
explicit (e.g. "buy the coffee beans"). Always call list_products before
checkout so prices and product ids are current.`

type chatAgent struct {
	app *app
}

func newChatAgent(a *app) *chatAgent { return &chatAgent{app: a} }

// chatHandler streams SSE: text/tool/approval_required/receipt/error/done.
func (a *app) chatHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ConversationID string `json:"conversation_id"`
		Message        string `json:"message"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&req); err != nil || req.Message == "" {
		writeJSON(w, 400, map[string]string{"error": "message required"})
		return
	}
	if req.ConversationID == "" {
		req.ConversationID = "default"
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeJSON(w, 500, map[string]string{"error": "no streaming"})
		return
	}
	emit := func(ev string, data any) { emitJSON(w, flusher, ev, data) }

	a.mu.Lock()
	history := append([]geminiContent{}, a.convs[req.ConversationID]...)
	a.mu.Unlock()
	history = append(history, geminiContent{Role: "user", Parts: []geminiPart{{Text: req.Message}}})

	ctx, cancel := context.WithTimeout(r.Context(), 6*time.Minute)
	defer cancel()

	for round := 0; round < 8; round++ {
		content, err := a.gemini.generate(ctx, &geminiRequest{
			SystemInstruction: &geminiContent{Role: "system", Parts: []geminiPart{{Text: systemPrompt}}},
			Contents:          history,
			Tools:             demoTools,
		})
		if err != nil {
			emit("error", map[string]string{"error": err.Error()})
			break
		}
		history = append(history, *content)
		var calls []geminiPart
		texts := []string{}
		for _, p := range content.Parts {
			if p.FunctionCall != nil {
				calls = append(calls, p)
			} else if p.Text != "" {
				texts = append(texts, p.Text)
			}
		}
		if len(texts) > 0 {
			emit("text", map[string]string{"content": strings.Join(texts, "\n")})
		}
		if len(calls) == 0 {
			break
		}
		var responses []geminiPart
		for _, p := range calls {
			fc := p.FunctionCall
			emit("tool", map[string]any{"name": fc.Name, "args": summarizeArgs(fc.Name, fc.Args)})
			res := a.agent.runTool(ctx, req.ConversationID, fc, emit)
			responses = append(responses, geminiPart{FunctionResponse: &geminiFunctionResponse{Name: fc.Name, Response: res}})
		}
		history = append(history, geminiContent{Role: "user", Parts: responses})
	}
	a.mu.Lock()
	a.convs[req.ConversationID] = history
	a.mu.Unlock()
	emit("done", map[string]any{"ok": true})
}

func summarizeArgs(name string, args map[string]any) string {
	switch name {
	case "checkout":
		qty := any(1)
		if args["qty"] != nil {
			qty = args["qty"]
		}
		return fmt.Sprintf("product=%v qty=%v", args["product_id"], qty)
	default:
		return ""
	}
}

func (a *chatAgent) runTool(ctx context.Context, convID string, fc *geminiFunctionCall, emit sseEmit) map[string]any {
	switch fc.Name {
	case "list_products":
		return map[string]any{"products": a.app.store.products}
	case "checkout":
		id, _ := fc.Args["product_id"].(string)
		qty := 1
		if q, ok := fc.Args["qty"].(float64); ok {
			if q > 10 {
				return map[string]any{"status": "error", "reason": "qty must be 1-10"}
			}
			if q > 0 {
				qty = int(q)
			}
		}
		return a.app.agentCheckout(ctx, convID, id, qty, emit)
	default:
		return map[string]any{"status": "error", "reason": "unknown tool"}
	}
}

// agentCheckout runs the Valet grant → approval → pay pipeline for one item.
func (a *app) agentCheckout(ctx context.Context, convID, productID string, qty int, emit sseEmit) map[string]any {
	p := a.store.byID(productID)
	if p == nil {
		return map[string]any{"status": "error", "reason": "unknown product"}
	}
	total := p.PriceCents * int64(qty)
	merchant := ""
	if u, err := url.Parse(a.cfg.PublicURL); err == nil {
		merchant = u.Hostname()
	}
	purpose := fmt.Sprintf("Buy %dx %s at Valet Demo Store", qty, p.Name)
	pol := map[string]any{
		"spend": map[string]any{
			"per_tx": total, "currency": "USD",
			"merchants": []string{merchant},
		},
	}
	// Per-conversation dedupe: at most one pending grant request. A reserved
	// entry means requestGrant is in flight; an id entry is a live approval.
	a.mu.Lock()
	pa := a.pending[convID]
	if pa == nil {
		a.pending[convID] = &pendingApproval{reserved: true}
	}
	a.mu.Unlock()
	pendingReason := map[string]any{"status": "pending_approval", "reason": "a purchase is already awaiting the owner's approval"}
	if pa != nil {
		if pa.reserved {
			return pendingReason
		}
		st, err := a.valet.grantRequestStatus(ctx, pa.id, 0)
		if err == nil && st["status"] == "pending" {
			emit("approval_required", map[string]any{
				"request_id": pa.id, "purpose": pa.purpose, "amount_cents": pa.total,
				"merchant": pa.merchant, "expires_at": pa.expiresAt, "agent": "Valet Shopping Agent",
			})
			return pendingReason
		}
		a.mu.Lock()
		if a.pending[convID] != pa {
			a.mu.Unlock()
			return pendingReason
		}
		a.pending[convID] = &pendingApproval{reserved: true}
		a.mu.Unlock()
	}
	clearPending := func() {
		a.mu.Lock()
		delete(a.pending, convID)
		a.mu.Unlock()
	}
	out, err := a.valet.requestGrant(ctx, "card://"+a.cfg.CardLabel, purpose, 600, 1, pol)
	if err != nil {
		clearPending()
		return map[string]any{"status": "error", "reason": "grant request failed"}
	}
	var grantToken string
	if out["status"] == "pending_approval" {
		rid, _ := out["request_id"].(string)
		exp, _ := out["expires_at"].(string)
		a.mu.Lock()
		a.pending[convID] = &pendingApproval{
			id: rid, purpose: purpose, total: int(total), merchant: merchant, expiresAt: exp,
		}
		a.mu.Unlock()
		emit("approval_required", map[string]any{
			"request_id": rid, "purpose": purpose, "amount_cents": total,
			"merchant": merchant, "expires_at": exp, "agent": "Valet Shopping Agent",
		})
		deadline := time.Now().Add(5 * time.Minute)
		for {
			if time.Now().After(deadline) {
				clearPending()
				return map[string]any{"status": "expired", "reason": "approval timed out"}
			}
			st, err := a.valet.grantRequestStatus(ctx, rid, 60)
			if err != nil {
				if ctx.Err() == nil {
					// Genuine poll failure — clear. On client disconnect the
					// approval is still live; the next buy should reuse it.
					clearPending()
				}
				return map[string]any{"status": "error", "reason": "approval poll failed"}
			}
			switch st["status"] {
			case "approved":
				grantToken, _ = st["token"].(string)
			case "pending":
				continue
			default:
				clearPending()
				s, _ := st["status"].(string)
				return map[string]any{"status": s}
			}
			break
		}
		clearPending()
	} else {
		clearPending()
		grantToken, _ = out["token"].(string)
	}
	if grantToken == "" {
		return map[string]any{"status": "error", "reason": "no grant token"}
	}
	orderJSON, _ := json.Marshal(map[string]any{"items": []orderItem{{ID: productID, Qty: qty}}})
	body := fmt.Sprintf(`{"order":%s,"card":{"number":"{{card.number}}","exp_month":"{{card.exp_month}}","exp_year":"{{card.exp_year}}","cvc":"{{card.cvc}}"}}`, orderJSON)
	res, err := a.valet.pay(ctx, grantToken, a.cfg.PublicURL+"/store/checkout", string(body), total, "USD")
	if err != nil && strings.Contains(err.Error(), "need_cvc") {
		// Stored card has no CVC on file — retry without the field.
		body = fmt.Sprintf(`{"order":%s,"card":{"number":"{{card.number}}","exp_month":"{{card.exp_month}}","exp_year":"{{card.exp_year}}"}}`, orderJSON)
		res, err = a.valet.pay(ctx, grantToken, a.cfg.PublicURL+"/store/checkout", string(body), total, "USD")
	}
	if err != nil {
		return map[string]any{"status": "error", "reason": "pay failed"}
	}
	status, _ := res["status"].(string)
	if status != "ok" {
		return map[string]any{"status": "declined", "reason": status}
	}
	var upstream struct {
		OrderID    string `json:"order_id"`
		Status     string `json:"status"`
		TotalCents int64  `json:"total_cents"`
		Last4      string `json:"last4"`
	}
	if body, ok := res["body"].(string); ok {
		json.Unmarshal([]byte(body), &upstream)
	}
	receipt := map[string]any{
		"order_id": upstream.OrderID, "total_cents": upstream.TotalCents,
		"last4": upstream.Last4, "status": "paid",
	}
	emit("receipt", receipt)
	return map[string]any{"status": "paid", "order_id": upstream.OrderID, "total_cents": upstream.TotalCents, "last4": upstream.Last4}
}
