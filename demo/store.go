package main

import (
	"encoding/json"
	"net/http"
	"sync/atomic"
	"time"
)

// product is a fixed catalog item — no DB, this is a demo store.
// Rails lists the crypto rails a crypto-priced product accepts
// ("x402", "mpp"); card products leave it empty.
type product struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	PriceCents int64    `json:"price_cents"`
	Currency   string   `json:"currency"`
	Emoji      string   `json:"emoji"`
	Rails      []string `json:"rails,omitempty"`
}

type order struct {
	ID          string      `json:"order_id"`
	TotalCents  int64       `json:"total_cents"`
	Last4       string      `json:"last4"`
	Items       []orderItem `json:"items"`
	CreatedAt   time.Time   `json:"created_at"`
	Rail        string      `json:"rail,omitempty"`
	Network     string      `json:"network,omitempty"`
	Tx          string      `json:"tx,omitempty"`
	ExplorerURL string      `json:"explorer_url,omitempty"`
}

type orderItem struct {
	ID  string `json:"id"`
	Qty int    `json:"qty"`
}

type demoStore struct {
	products []product
	nextID   atomic.Int64
}

// newDemoStore builds the catalog; the crypto-priced report exists only
// when a payout address is configured (DEMO_PAY_TO).
func newDemoStore(payTo string) *demoStore {
	products := []product{
		{ID: "coffee", Name: "Colombian coffee beans (250g)", PriceCents: 1800, Currency: "USD", Emoji: "☕"},
		{ID: "sneakers", Name: "Running sneakers", PriceCents: 8900, Currency: "USD", Emoji: "👟"},
		{ID: "headphones", Name: "Wireless headphones", PriceCents: 12900, Currency: "USD", Emoji: "🎧"},
		{ID: "book", Name: "\"Designing Agent Systems\" (paperback)", PriceCents: 3400, Currency: "USD", Emoji: "📖"},
		{ID: "flowers", Name: "Seasonal flower bouquet", PriceCents: 4200, Currency: "USD", Emoji: "💐"},
		{ID: "ticket", Name: "Concert ticket — balcony", PriceCents: 7500, Currency: "USD", Emoji: "🎟️"},
	}
	if payTo != "" {
		products = append(products, product{
			ID: "report", Name: "Agent Commerce Market Report (PDF)",
			PriceCents: 1, Currency: "USDC", Emoji: "📊",
			Rails: []string{"x402", "mpp"},
		})
	}
	return &demoStore{products: products}
}

func (s *demoStore) byID(id string) *product {
	for i := range s.products {
		if s.products[i].ID == id {
			return &s.products[i]
		}
	}
	return nil
}

// luhn reports whether digits passes the Luhn check — a VGS tok_ alias fails
// here, which is the proof the reveal never leaves the vault.
func luhn(number string) bool {
	sum, alt := 0, false
	for i := len(number) - 1; i >= 0; i-- {
		d := number[i]
		if d < '0' || d > '9' {
			return false
		}
		n := int(d - '0')
		if alt {
			n *= 2
			if n > 9 {
				n -= 9
			}
		}
		sum += n
		alt = !alt
	}
	return len(number) >= 13 && len(number) <= 19 && sum%10 == 0
}

func (a *app) productsHandler(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"products": a.store.products})
}

type checkoutRequest struct {
	Order struct {
		Items []orderItem `json:"items"`
	} `json:"order"`
	Card struct {
		Number   string `json:"number"`
		ExpMonth string `json:"exp_month"`
		ExpYear  string `json:"exp_year"`
		CVC      string `json:"cvc"`
		Holder   string `json:"holder"`
	} `json:"card"`
}

// checkoutHandler is what Valet calls with the card substituted by the VGS
// proxy. The Luhn check on number proves the alias was revealed upstream.
func (a *app) checkoutHandler(w http.ResponseWriter, r *http.Request) {
	var req checkoutRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&req); err != nil {
		writeJSON(w, 400, map[string]string{"error": "bad json"})
		return
	}
	if len(req.Order.Items) == 0 {
		writeJSON(w, 400, map[string]string{"error": "empty order"})
		return
	}
	var total int64
	for _, it := range req.Order.Items {
		p := a.store.byID(it.ID)
		if p == nil {
			writeJSON(w, 400, map[string]string{"error": "unknown product " + it.ID})
			return
		}
		if it.Qty < 1 || it.Qty > 10 {
			writeJSON(w, 400, map[string]string{"error": "bad qty"})
			return
		}
		total += p.PriceCents * int64(it.Qty)
	}
	// A tok_ alias (unrevealed) fails Luhn → decline. Never log req.Card.
	if !luhn(req.Card.Number) {
		writeJSON(w, 402, map[string]string{"error": "card_declined", "reason": "invalid card number"})
		return
	}
	last4 := req.Card.Number[len(req.Card.Number)-4:]
	id := a.store.nextID.Add(1)
	o := order{
		ID:         "ord_" + time.Now().Format("20060102") + "_" + itoa(id),
		TotalCents: total, Last4: last4,
		Items: req.Order.Items, CreatedAt: time.Now().UTC(),
	}
	a.mu.Lock()
	a.orders = append(a.orders, o)
	a.mu.Unlock()
	writeJSON(w, 200, map[string]any{
		"order_id": o.ID, "status": "paid", "total_cents": total, "last4": last4,
	})
}

func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	b := [20]byte{}
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

func (a *app) ordersHandler(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	out := make([]order, len(a.orders))
	copy(out, a.orders)
	a.mu.Unlock()
	writeJSON(w, 200, map[string]any{"orders": out})
}
