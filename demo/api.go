package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
)

// cardInfo is the wallet's view of one card:// handle.
type cardInfo struct {
	Handle   string `json:"handle"`
	Label    string `json:"label"`
	Last4    string `json:"last4"`
	Bin      string `json:"bin"`
	Verified bool   `json:"verified"`
}

// resolveCard lists card handles and resolves the effective checkout label:
// a.defaultCard while it exists, else the first remaining card, else "".
func (a *app) resolveCard(ctx context.Context) (string, []cardInfo, error) {
	h, err := a.valet.ownerList(ctx, "/v1/owner/handles")
	if err != nil {
		return "", nil, err
	}
	cards := []cardInfo{}
	if handles, ok := h["handles"].([]any); ok {
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
			cards = append(cards, cardInfo{
				Handle: hdl, Label: label, Last4: meta.Last4,
				Bin: meta.Bin, Verified: meta.Last4Source == "vgs",
			})
		}
	}
	def := a.cardLabel()
	found := false
	for _, c := range cards {
		if c.Label == def {
			found = true
		}
	}
	if !found {
		// The configured/persisted default is gone — fall back to the first
		// card and persist it so a re-added old label can't sneak back in.
		def = ""
		if len(cards) > 0 {
			def = cards[0].Label
		}
		a.mu.Lock()
		changed := a.defaultCard != def
		a.defaultCard = def
		a.mu.Unlock()
		if changed {
			a.saveState()
		}
	}
	return def, cards, nil
}

// demoState persists the selected default card across restarts.
type demoState struct {
	DefaultCard string `json:"default_card"`
}

func (a *app) stateFile() string {
	if f := os.Getenv("DEMO_STATE_FILE"); f != "" {
		return f
	}
	return "demo-state.json"
}

func (a *app) loadState() {
	var st demoState
	if b, err := os.ReadFile(a.stateFile()); err == nil && json.Unmarshal(b, &st) == nil && st.DefaultCard != "" {
		a.defaultCard = st.DefaultCard
	}
}

// saveState writes the current default card (0600); best effort.
func (a *app) saveState() {
	a.mu.Lock()
	b, _ := json.Marshal(demoState{DefaultCard: a.defaultCard})
	a.mu.Unlock()
	_ = os.WriteFile(a.stateFile(), b, 0o600)
}

func (a *app) stateHandler(w http.ResponseWriter, r *http.Request) {
	out := map[string]any{"card_saved": false, "cards": []any{}, "pending_approvals": []any{}, "grants": []any{}, "audit": []any{}, "orders": []any{}}
	if def, cards, err := a.resolveCard(r.Context()); err == nil {
		out["cards"] = cards
		out["card_saved"] = len(cards) > 0
		out["default_card"] = def
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
	// No implicit replace: a label already in the wallet must be removed first.
	_, cards, err := a.resolveCard(r.Context())
	if err != nil {
		writeJSON(w, 502, map[string]string{"error": err.Error()})
		return
	}
	for _, c := range cards {
		if c.Label == label {
			writeJSON(w, 409, map[string]string{"error": "label already in use — remove it first"})
			return
		}
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
	if !cardLabelRE.MatchString(label) {
		writeJSON(w, 400, map[string]string{"error": "bad label"})
		return
	}
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
	a.saveState()
	writeJSON(w, 200, map[string]string{"default": label})
}

// deleteCardHandler removes card://<label> via the owner API and falls back
// to the first remaining card when the default is deleted.
func (a *app) deleteCardHandler(w http.ResponseWriter, r *http.Request) {
	label := r.PathValue("label")
	if !cardLabelRE.MatchString(label) {
		writeJSON(w, 400, map[string]string{"error": "bad label"})
		return
	}
	if _, err := a.valet.ownerDelete(r.Context(), "/v1/owner/handles/"+url.PathEscape("card://"+label)); err != nil {
		writeJSON(w, 502, map[string]string{"error": err.Error()})
		return
	}
	if a.cardLabel() == label {
		a.mu.Lock()
		a.defaultCard = ""
		a.mu.Unlock()
		a.saveState()
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
