// Package mock is an in-memory issuer driver for tests and demos: it mints
// Luhn-valid test PANs (BIN 411111) without any keys.
package mock

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	mrand "math/rand/v2"
	"sync"
	"time"

	"github.com/joalavedra/valet/internal/edge/issuer"
)

type entry struct {
	spec   issuer.CardSpec
	fields issuer.Fields
	closed bool
}

// Mock issues fake cards entirely in memory.
type Mock struct {
	mu    sync.Mutex
	cards map[string]*entry
}

func New() *Mock { return &Mock{cards: map[string]*entry{}} }

func (m *Mock) Name() string { return "mock" }

func (m *Mock) Capabilities() issuer.Caps {
	return issuer.Caps{MerchantLock: true, Cap: true, SingleUse: true, Reveal: true}
}

func (m *Mock) Issue(_ context.Context, spec issuer.CardSpec) (issuer.Card, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return issuer.Card{}, err
	}
	number := testPAN()
	exp := spec.ExpiresAt
	if exp.IsZero() || exp.Before(time.Now()) {
		exp = time.Now().AddDate(1, 0, 0)
	}
	c := issuer.Card{
		ID: "mock_" + hex.EncodeToString(b), Brand: "visa", Last4: number[len(number)-4:],
		ExpMonth: fmt.Sprintf("%02d", exp.Month()), ExpYear: fmt.Sprintf("%d", exp.Year()),
		Holder: "VALET AGENT", Status: "active",
	}
	m.mu.Lock()
	m.cards[c.ID] = &entry{
		spec: spec,
		fields: issuer.Fields{
			Number: number, ExpMonth: c.ExpMonth, ExpYear: c.ExpYear,
			CVC: fmt.Sprintf("%03d", mrand.IntN(1000)), Holder: c.Holder,
		},
	}
	m.mu.Unlock()
	return c, nil
}

func (m *Mock) Reveal(_ context.Context, cardID string) (issuer.Fields, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.cards[cardID]
	if !ok || e.closed {
		return issuer.Fields{}, fmt.Errorf("mock: card %q not active", cardID)
	}
	return e.fields, nil
}

func (m *Mock) Close(_ context.Context, cardID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if e, ok := m.cards[cardID]; ok {
		e.closed = true
		e.fields.Zero()
	}
	return nil // idempotent
}

// testPAN returns a Luhn-valid 16-digit number under test BIN 411111.
func testPAN() string {
	digits := make([]int, 16)
	digits[0], digits[1], digits[2], digits[3], digits[4], digits[5] = 4, 1, 1, 1, 1, 1
	for i := 6; i < 15; i++ {
		digits[i] = mrand.IntN(10)
	}
	sum := 0
	for i := 14; i >= 0; i-- { // positions 1..15 (check digit excluded)
		d := digits[i]
		if (15-i)%2 == 1 {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
	}
	digits[15] = (10 - sum%10) % 10
	out := make([]byte, 16)
	for i, d := range digits {
		out[i] = byte('0' + d)
	}
	return string(out)
}

func init() { issuer.Register("mock", New()) }
