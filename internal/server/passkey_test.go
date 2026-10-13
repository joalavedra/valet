package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"

	"github.com/joalavedra/valet/internal/store"
)

var b64 = base64.RawURLEncoding

// softAuthenticator is a minimal WebAuthn platform authenticator: a P-256
// key, "none" attestation, user verification always performed.
type softAuthenticator struct {
	t          *testing.T
	key        *ecdsa.PrivateKey
	id         []byte
	origin     string
	count      uint32
	userHandle []byte
}

func newSoftAuthenticator(t *testing.T, origin string) *softAuthenticator {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	id := make([]byte, 16)
	rand.Read(id)
	return &softAuthenticator{t: t, key: k, id: id, origin: origin}
}

// publicKey pulls options.publicKey out of a Valet begin/challenge reply.
func publicKey(t *testing.T, out map[string]any) map[string]any {
	t.Helper()
	o, _ := out["options"].(map[string]any)
	pk, _ := o["publicKey"].(map[string]any)
	if pk == nil {
		t.Fatalf("no options.publicKey in %v", out)
	}
	return pk
}

func (a *softAuthenticator) clientData(typ, challenge string) []byte {
	cd, _ := json.Marshal(map[string]any{"type": typ, "challenge": challenge, "origin": a.origin, "crossOrigin": false})
	return cd
}

func (a *softAuthenticator) authData(rpID string, flags byte, attested []byte) []byte {
	h := sha256.Sum256([]byte(rpID))
	out := append(h[:], flags)
	out = binary.BigEndian.AppendUint32(out, a.count)
	return append(out, attested...)
}

// create answers navigator.credentials.create.
func (a *softAuthenticator) create(pk map[string]any) json.RawMessage {
	a.t.Helper()
	rp := pk["rp"].(map[string]any)
	user := pk["user"].(map[string]any)
	a.userHandle, _ = b64.DecodeString(user["id"].(string))
	enc, _ := cbor.CoreDetEncOptions().EncMode()
	cose, err := enc.Marshal(map[int]any{1: 2, 3: -7, -1: 1,
		-2: a.key.PublicKey.X.FillBytes(make([]byte, 32)), -3: a.key.PublicKey.Y.FillBytes(make([]byte, 32))})
	if err != nil {
		a.t.Fatal(err)
	}
	cred := make([]byte, 16) // AAGUID
	cred = binary.BigEndian.AppendUint16(cred, uint16(len(a.id)))
	cred = append(append(cred, a.id...), cose...)
	att, _ := enc.Marshal(map[string]any{"fmt": "none", "attStmt": map[string]any{},
		"authData": a.authData(rp["id"].(string), 0x45, cred)}) // UP|UV|AT
	out, _ := json.Marshal(map[string]any{
		"id": b64.EncodeToString(a.id), "rawId": b64.EncodeToString(a.id), "type": "public-key",
		"response": map[string]any{
			"clientDataJSON":    b64.EncodeToString(a.clientData("webauthn.create", pk["challenge"].(string))),
			"attestationObject": b64.EncodeToString(att),
		},
	})
	return out
}

// get answers navigator.credentials.get.
func (a *softAuthenticator) get(pk map[string]any) json.RawMessage {
	a.t.Helper()
	a.count++
	ad := a.authData(pk["rpId"].(string), 0x05, nil) // UP|UV
	cd := a.clientData("webauthn.get", pk["challenge"].(string))
	cdh := sha256.Sum256(cd)
	digest := sha256.Sum256(append(append([]byte{}, ad...), cdh[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, a.key, digest[:])
	if err != nil {
		a.t.Fatal(err)
	}
	out, _ := json.Marshal(map[string]any{
		"id": b64.EncodeToString(a.id), "rawId": b64.EncodeToString(a.id), "type": "public-key",
		"response": map[string]any{
			"clientDataJSON":    b64.EncodeToString(cd),
			"authenticatorData": b64.EncodeToString(ad),
			"signature":         b64.EncodeToString(sig),
			"userHandle":        b64.EncodeToString(a.userHandle),
		},
	})
	return out
}

// stepUpFor runs a challenge for an action and answers it.
func stepUpFor(t *testing.T, srv *Server, own string, a *softAuthenticator, req map[string]any) map[string]any {
	t.Helper()
	code, out := doJSON(t, srv, "POST", "/v1/owner/passkeys/challenge", own, req)
	if code != 200 {
		t.Fatalf("challenge %v: %d %v", req, code, out)
	}
	return map[string]any{"session_id": out["session_id"], "assertion": a.get(publicKey(t, out))}
}

func enroll(t *testing.T, srv *Server, own string, a *softAuthenticator, proof map[string]any) (int, map[string]any) {
	t.Helper()
	var body any
	if proof != nil {
		body = map[string]any{"passkey": proof}
	}
	code, out := doJSON(t, srv, "POST", "/v1/owner/passkeys/register/begin", own, body)
	if code != 200 {
		return code, out
	}
	return doJSON(t, srv, "POST", "/v1/owner/passkeys/register/finish", own, map[string]any{
		"session_id": out["session_id"], "name": "phone", "credential": a.create(publicKey(t, out)),
	})
}

func TestPasskeyStepUpOnApprove(t *testing.T) {
	t.Setenv("VALET_PASSKEY_ORIGINS", "https://demo.example")
	srv, st, dek, tok, own := approvalServer(t, "card")
	h := addCard(t, st, srv, dek, "amex")
	work := addCard(t, st, srv, dek, "work")
	request := func() string {
		t.Helper()
		code, out := doJSON(t, srv, "POST", "/v1/grants", tok, map[string]any{"handle": h, "purpose": "coffee"})
		if code != 202 {
			t.Fatalf("want 202, got %d %v", code, out)
		}
		return out["request_id"].(string)
	}
	phone := newSoftAuthenticator(t, "https://demo.example")

	// Nothing enrolled: no gate, and no challenge to start.
	code, out := doJSON(t, srv, "GET", "/v1/owner/passkeys", own, nil)
	if code != 200 || out["configured"] != true || out["required"] != false {
		t.Fatalf("initial state: %d %v", code, out)
	}
	code, _ = doJSON(t, srv, "POST", "/v1/owner/passkeys/challenge", own, map[string]any{"action": "register"})
	if code != 409 {
		t.Fatalf("challenge with none enrolled: want 409, got %d", code)
	}

	// The first passkey enrolls with the owner token alone.
	if code, out := enroll(t, srv, own, phone, nil); code != 200 || out["name"] != "phone" {
		t.Fatalf("enroll: %d %v", code, out)
	}
	_, out = doJSON(t, srv, "GET", "/v1/owner/passkeys", own, nil)
	if out["required"] != true || len(out["passkeys"].([]any)) != 1 {
		t.Fatalf("after enroll: %v", out)
	}

	// Approve now needs an assertion.
	rid := request()
	code, out = doJSON(t, srv, "POST", "/v1/owner/approvals/"+rid+"/approve", own, nil)
	if code != 403 || out["error"] != "passkey_required" {
		t.Fatalf("approve without passkey: %d %v", code, out)
	}
	// Bound to the handle: a proof for the requested card can't approve with another.
	proof := stepUpFor(t, srv, own, phone, map[string]any{"action": "approve", "approval_id": rid})
	code, _ = doJSON(t, srv, "POST", "/v1/owner/approvals/"+rid+"/approve", own, map[string]any{"handle": work, "passkey": proof})
	if code != 403 {
		t.Fatalf("handle swapped after challenge: want 403, got %d", code)
	}
	// Bound to the request: a proof for another request is refused.
	other := request()
	proof = stepUpFor(t, srv, own, phone, map[string]any{"action": "approve", "approval_id": other})
	code, _ = doJSON(t, srv, "POST", "/v1/owner/approvals/"+rid+"/approve", own, map[string]any{"passkey": proof})
	if code != 403 {
		t.Fatalf("proof for another request: want 403, got %d", code)
	}
	// From the wrong origin: refused.
	phish := &softAuthenticator{t: t, key: phone.key, id: phone.id, origin: "https://evil.example", userHandle: phone.userHandle}
	proof = stepUpFor(t, srv, own, phish, map[string]any{"action": "approve", "approval_id": rid})
	code, _ = doJSON(t, srv, "POST", "/v1/owner/approvals/"+rid+"/approve", own, map[string]any{"passkey": proof})
	if code != 403 {
		t.Fatalf("wrong origin: want 403, got %d", code)
	}
	// The right proof approves, once.
	proof = stepUpFor(t, srv, own, phone, map[string]any{"action": "approve", "approval_id": rid, "handle": work})
	code, out = doJSON(t, srv, "POST", "/v1/owner/approvals/"+rid+"/approve", own, map[string]any{"handle": work, "passkey": proof})
	if code != 200 || out["handle"] != work {
		t.Fatalf("approve with passkey: %d %v", code, out)
	}
	code, _ = doJSON(t, srv, "POST", "/v1/owner/approvals/"+other+"/approve", own, map[string]any{"passkey": proof})
	if code != 403 {
		t.Fatalf("replayed proof: want 403, got %d", code)
	}
	entries, _ := st.ListAuditRecent(20)
	found := false
	for _, e := range entries {
		if e.Decision == "granted" && strings.Contains(e.Detail, `"passkey_id":"`+b64.EncodeToString(phone.id)+`"`) {
			found = true
		}
	}
	if !found {
		t.Fatalf("audit should name the passkey: %+v", entries)
	}
	// Deny never needs one.
	code, _ = doJSON(t, srv, "POST", "/v1/owner/approvals/"+other+"/deny", own, nil)
	if code != 200 {
		t.Fatalf("deny: want 200, got %d", code)
	}

	// The owner token alone can't enroll another authenticator or remove one.
	laptop := newSoftAuthenticator(t, "https://demo.example")
	if code, out := enroll(t, srv, own, laptop, nil); code != 403 || out["error"] != "passkey_required" {
		t.Fatalf("second enroll without step-up: %d %v", code, out)
	}
	pid := b64.EncodeToString(phone.id)
	code, _ = doJSON(t, srv, "DELETE", "/v1/owner/passkeys/"+pid, own, nil)
	if code != 403 {
		t.Fatalf("delete without step-up: want 403, got %d", code)
	}
	// With a step-up from the enrolled passkey, both work.
	proof = stepUpFor(t, srv, own, phone, map[string]any{"action": "register"})
	if code, out := enroll(t, srv, own, laptop, proof); code != 200 {
		t.Fatalf("second enroll with step-up: %d %v", code, out)
	}
	// A delete proof is bound to the passkey it names.
	proof = stepUpFor(t, srv, own, phone, map[string]any{"action": "delete", "passkey_id": b64.EncodeToString(laptop.id)})
	code, _ = doJSON(t, srv, "DELETE", "/v1/owner/passkeys/"+pid, own, map[string]any{"passkey": proof})
	if code != 403 {
		t.Fatalf("delete proof for another passkey: want 403, got %d", code)
	}
	proof = stepUpFor(t, srv, own, laptop, map[string]any{"action": "delete", "passkey_id": pid})
	code, _ = doJSON(t, srv, "DELETE", "/v1/owner/passkeys/"+pid, own, map[string]any{"passkey": proof})
	if code != 200 {
		t.Fatalf("delete with step-up: want 200, got %d", code)
	}
	_, out = doJSON(t, srv, "GET", "/v1/owner/passkeys", own, nil)
	if len(out["passkeys"].([]any)) != 1 {
		t.Fatalf("want 1 passkey left, got %v", out)
	}
}

func TestPasskeyUnconfiguredFailsClosed(t *testing.T) {
	t.Setenv("VALET_PASSKEY_ORIGINS", "")
	t.Setenv("VALET_PUBLIC_URL", "")
	srv, st, dek, tok, own := approvalServer(t, "card")
	h := addCard(t, st, srv, dek, "amex")
	code, out := doJSON(t, srv, "POST", "/v1/owner/passkeys/register/begin", own, nil)
	if code != 503 {
		t.Fatalf("begin unconfigured: want 503, got %d %v", code, out)
	}
	// A passkey enrolled earlier (config since removed) must not silently
	// turn the step-up off.
	if err := st.AddPasskey(&store.Passkey{ID: "old", Name: "old", Credential: "{}"}); err != nil {
		t.Fatal(err)
	}
	_, out = doJSON(t, srv, "POST", "/v1/grants", tok, map[string]any{"handle": h})
	code, _ = doJSON(t, srv, "POST", "/v1/owner/approvals/"+out["request_id"].(string)+"/approve", own, nil)
	if code != 503 {
		t.Fatalf("approve with passkey enrolled but unconfigured: want 503, got %d", code)
	}
}
