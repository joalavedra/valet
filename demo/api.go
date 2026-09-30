package main

import (
	"encoding/json"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

func (a *app) stateHandler(w http.ResponseWriter, r *http.Request) {
	out := map[string]any{"card_saved": false, "cards": []any{}, "pending_approvals": []any{}, "grants": []any{}, "audit": []any{}, "orders": []any{}}
	if h, err := a.valet.ownerList(r.Context(), "/v1/owner/handles"); err == nil {
		if handles, ok := h["handles"].([]any); ok {
			cards := []any{}
			for _, x := range handles {
				m, _ := x.(map[string]any)
				hdl, _ := m["handle"].(string)
				label, ok := strings.CutPrefix(hdl, "card://")
				if !ok {
					continue
				}
				var meta struct {
					Last4       string `json:"last4"`
					Bin         string `json:"bin"`
					Last4Source string `json:"last4_source"`
				}
				if s, ok := m["metadata"].(string); ok {
					json.Unmarshal([]byte(s), &meta)
				}
				cards = append(cards, map[string]any{
					"handle": hdl, "label": label, "last4": meta.Last4,
					"bin": meta.Bin, "verified": meta.Last4Source == "vgs",
				})
			}
			out["cards"] = cards
			out["card_saved"] = len(cards) > 0
			// Default card: the configured/selected label while it exists,
			// else the first remaining card.
			def := a.cardLabel()
			found := false
			for _, c := range cards {
				if m, _ := c.(map[string]any); m["label"] == def {
					found = true
				}
			}
			if !found {
				def = ""
				if len(cards) > 0 {
					if m, _ := cards[0].(map[string]any); m != nil {
						def, _ = m["label"].(string)
					}
				}
			}
			out["default_card"] = def
		}
	}
	if ap, err := a.valet.ownerList(r.Context(), "/v1/owner/approvals?status=pending"); err == nil {
		out["pending_approvals"] = ap["approvals"]
	}
	if g, err := a.valet.ownerList(r.Context(), "/v1/owner/grants"); err == nil {
		out["grants"] = g["grants"]
	}
	if au, err := a.valet.ownerList(r.Context(), "/v1/owner/audit"); err == nil {
		if list, ok := au["audit"].([]any); ok && len(list) > 10 {
			out["audit"] = list[:10]
		} else {
			out["audit"] = au["audit"]
		}
	}
	a.mu.Lock()
	orders := make([]order, len(a.orders))
	copy(orders, a.orders)
	a.mu.Unlock()
	out["orders"] = orders
	writeJSON(w, 200, out)
}

// cardLabelRE mirrors handle.New's segment rules, narrowed to what the
// demo accepts as a card label.
var cardLabelRE = regexp.MustCompile(`^[a-z0-9-]{1,32}$`)

// cardLabel returns the label of the card checkout should use.
func (a *app) cardLabel() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.defaultCard
}

func (a *app) captureHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Label string `json:"label"`
	}
	// Body is optional; an empty body captures under the default label.
	_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&req)
	label := strings.ToLower(strings.TrimSpace(req.Label))
	if label == "" {
		if label = a.cardLabel(); label == "" {
			label = "personal"
		}
	}
	if !cardLabelRE.MatchString(label) {
		writeJSON(w, 400, map[string]string{"error": "bad label"})
		return
	}
	returnURL := a.cfg.PublicURL + "/?saved=1"
	out, err := a.valet.ownerCreateCapture(r.Context(), label, 900, returnURL)
	if err != nil {
		writeJSON(w, 502, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"url": out["url"], "expires_at": out["expires_at"]})
}

// defaultCardHandler marks an existing card:// label as the checkout card.
func (a *app) defaultCardHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Label string `json:"label"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&req); err != nil {
		writeJSON(w, 400, map[string]string{"error": "bad json"})
		return
	}
	label := strings.ToLower(strings.TrimSpace(req.Label))
	h, err := a.valet.ownerList(r.Context(), "/v1/owner/handles")
	if err != nil {
		writeJSON(w, 502, map[string]string{"error": err.Error()})
		return
	}
	exists := false
	if handles, ok := h["handles"].([]any); ok {
		for _, x := range handles {
			if m, _ := x.(map[string]any); m["handle"] == "card://"+label {
				exists = true
			}
		}
	}
	if !exists {
		writeJSON(w, 404, map[string]string{"error": "card not found"})
		return
	}
	a.mu.Lock()
	a.defaultCard = label
	a.mu.Unlock()
	writeJSON(w, 200, map[string]string{"default": label})
}

// deleteCardHandler removes card://<label> via the owner API and falls back
// to the first remaining card when the default is deleted.
func (a *app) deleteCardHandler(w http.ResponseWriter, r *http.Request) {
	label := r.PathValue("label")
	if _, err := a.valet.ownerDelete(r.Context(), "/v1/owner/handles/"+url.PathEscape("card://"+label)); err != nil {
		writeJSON(w, 502, map[string]string{"error": err.Error()})
		return
	}
	if a.cardLabel() == label {
		a.mu.Lock()
		a.defaultCard = ""
		a.mu.Unlock()
	}
	writeJSON(w, 200, map[string]string{"status": "deleted"})
}

func (a *app) decisionHandler(action string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		out, err := a.valet.ownerAction(r.Context(), "/v1/owner/approvals/"+id+"/"+action)
		if err != nil {
			writeJSON(w, 502, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, out)
	}
}

func (a *app) revokeHandler(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	out, err := a.valet.ownerAction(r.Context(), "/v1/owner/grants/"+id+"/revoke")
	if err != nil {
		writeJSON(w, 502, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, out)
}
