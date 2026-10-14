package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/joalavedra/valet/internal/edge/issuer"
	_ "github.com/joalavedra/valet/internal/edge/issuer/mock" // registers the mock driver
	"github.com/joalavedra/valet/internal/handle"
	"github.com/joalavedra/valet/internal/policy"
	"github.com/joalavedra/valet/internal/store"
)

// cardIssuer resolves the registered issuer driver by name.
func (s *Server) cardIssuer(name string) (issuer.Issuer, error) {
	return issuer.Get(name)
}

// issuerDriverOf returns the driver name from an issuer credential's metadata.
func issuerDriverOf(c *store.Credential) string {
	var m struct {
		Driver string `json:"driver"`
	}
	if json.Unmarshal([]byte(c.Metadata), &m) == nil && m.Driver != "" {
		return m.Driver
	}
	return "mock"
}

// mintIssuedCard issues one scoped card for a grant on an issuer:// handle
// and records its display metadata (never PAN/CVC).
func (s *Server) mintIssuedCard(g *store.Grant, cred *store.Credential, purpose string) error {
	kind, _, _, err := handle.Parse(g.Handle)
	if err != nil || kind != "issuer" {
		return nil
	}
	driver, err := s.cardIssuer(issuerDriverOf(cred))
	if err != nil {
		return err
	}
	var p policy.Policy
	_ = json.Unmarshal([]byte(g.Policy), &p)
	spec := issuer.CardSpec{
		GrantID:   g.ID,
		Merchants: p.Hosts,
		ExpiresAt: g.ExpiresAt,
		SingleUse: g.MaxUses == 1,
		Purpose:   purpose,
	}
	if p.Spend != nil {
		if len(p.Spend.Merchants) > 0 {
			spec.Merchants = p.Spend.Merchants
		}
		spec.PerTx = p.Spend.PerTx
		spec.Total = p.Spend.Total
		spec.Currency = p.Spend.Currency
	}
	c, err := driver.Issue(context.Background(), spec)
	if err != nil {
		return err
	}
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return err
	}
	row := &store.IssuedCard{
		ID: "ic_" + hex.EncodeToString(b), GrantID: g.ID, Handle: g.Handle,
		Driver: driver.Name(), CardID: c.ID, Brand: c.Brand, Last4: c.Last4,
		ExpMonth: c.ExpMonth, ExpYear: c.ExpYear, Status: c.Status,
	}
	if row.Status == "" {
		row.Status = "active"
	}
	if err := s.st.AddIssuedCard(row); err != nil {
		_ = driver.Close(context.Background(), c.ID)
		return err
	}
	detail, _ := json.Marshal(map[string]string{"grant_id": g.ID, "driver": driver.Name(), "last4": c.Last4})
	_ = s.chain.Append(&store.AuditEntry{AgentID: g.AgentID, Handle: g.Handle, Edge: "issuer", Target: "card", Decision: "card_issued", Detail: string(detail)})
	return nil
}

// closeIssuedCard closes the card bound to a grant — best-effort: a driver
// failure still marks the row closed.
func (s *Server) closeIssuedCard(grantID, reason string) {
	row, err := s.st.GetIssuedCardByGrant(grantID)
	if err != nil || row == nil || row.Status != "active" {
		return
	}
	if drv, err := s.cardIssuer(row.Driver); err == nil {
		if cerr := drv.Close(context.Background(), row.CardID); cerr != nil {
			slog.Debug("issuer close failed", "card_id", row.CardID, "error", cerr)
		}
	}
	if err := s.st.CloseIssuedCard(row.ID); err != nil {
		slog.Debug("issued card close failed", "id", row.ID, "error", err)
	}
	detail, _ := json.Marshal(map[string]string{"grant_id": grantID, "reason": reason})
	_ = s.chain.Append(&store.AuditEntry{Handle: row.Handle, Edge: "issuer", Target: "card", Decision: "card_closed", Detail: string(detail)})
}

// sweepIssuedCards closes active cards whose grant is revoked or expired.
// The background ticker calls it; tests can call it directly.
func (s *Server) sweepIssuedCards() {
	cards, err := s.st.ListIssuedCards(true)
	if err != nil {
		return
	}
	now := time.Now()
	for _, c := range cards {
		g, err := s.st.GetGrant(c.GrantID)
		if err != nil || g == nil {
			s.closeIssuedCard(c.GrantID, "revoked")
			continue
		}
		switch {
		case g.RevokedAt != nil:
			s.closeIssuedCard(c.GrantID, "revoked")
		case !now.Before(g.ExpiresAt):
			s.closeIssuedCard(c.GrantID, "expired")
		}
	}
}

type issuedCardView struct {
	ID        string     `json:"id"`
	GrantID   string     `json:"grant_id"`
	Handle    string     `json:"handle"`
	Driver    string     `json:"driver"`
	Brand     string     `json:"brand"`
	Last4     string     `json:"last4"`
	ExpMonth  string     `json:"exp_month"`
	ExpYear   string     `json:"exp_year"`
	Status    string     `json:"status"`
	CreatedAt time.Time  `json:"created_at"`
	ClosedAt  *time.Time `json:"closed_at"`
}

// ownerCards lists minted issuer cards (display metadata only).
func (s *Server) ownerCards(w http.ResponseWriter, r *http.Request) {
	cards, err := s.st.ListIssuedCards(false)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	out := []issuedCardView{}
	for _, c := range cards {
		out = append(out, issuedCardView{
			ID: c.ID, GrantID: c.GrantID, Handle: c.Handle, Driver: c.Driver,
			Brand: c.Brand, Last4: c.Last4, ExpMonth: c.ExpMonth, ExpYear: c.ExpYear,
			Status: c.Status, CreatedAt: c.CreatedAt, ClosedAt: c.ClosedAt,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"cards": out})
}

// ownerCardClose closes the card and revokes the grant it is bound to.
func (s *Server) ownerCardClose(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	row, err := s.st.GetIssuedCard(id)
	if err != nil || row == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "card not found"})
		return
	}
	s.closeIssuedCard(row.GrantID, "owner")
	_ = s.st.RevokeGrant(row.GrantID)
	writeJSON(w, http.StatusOK, map[string]string{"status": "closed"})
}
