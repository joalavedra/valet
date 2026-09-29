package main

import (
	"encoding/json"
	"net/http"
)

func (a *app) stateHandler(w http.ResponseWriter, r *http.Request) {
	out := map[string]any{"card_saved": false, "pending_approvals": []any{}, "grants": []any{}, "audit": []any{}, "orders": []any{}}
	if h, err := a.valet.ownerList(r.Context(), "/v1/owner/handles"); err == nil {
		if handles, ok := h["handles"].([]any); ok {
			for _, x := range handles {
				m, _ := x.(map[string]any)
				if m["handle"] == "card://"+a.cfg.CardLabel {
					out["card_saved"] = true
					var meta struct {
						Last4    string `json:"last4"`
						ExpMonth string `json:"exp_month"`
						ExpYear  string `json:"exp_year"`
						Holder   string `json:"holder"`
						Provider string `json:"provider"`
					}
					if s, ok := m["metadata"].(string); ok {
						json.Unmarshal([]byte(s), &meta)
					}
					out["card_last4"] = meta.Last4
					out["card_exp"] = meta.ExpMonth + "/" + meta.ExpYear
					out["card_holder"] = meta.Holder
				}
			}
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

func (a *app) captureHandler(w http.ResponseWriter, r *http.Request) {
	returnURL := a.cfg.PublicURL + "/?saved=1"
	out, err := a.valet.ownerCreateCapture(r.Context(), a.cfg.CardLabel, 900, returnURL)
	if err != nil {
		writeJSON(w, 502, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"url": out["url"], "expires_at": out["expires_at"]})
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
