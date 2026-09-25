package crypto

import (
	"bytes"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	dek, err := GenerateDEK()
	if err != nil {
		t.Fatal(err)
	}
	salt, err := GenerateSalt()
	if err != nil {
		t.Fatal(err)
	}
	kek := DeriveKEK("correct horse", salt)
	wrapped, err := WrapDEK(dek, kek)
	if err != nil {
		t.Fatal(err)
	}
	dek2, err := UnwrapDEK(wrapped, kek)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(dek, dek2) {
		t.Fatal("DEK round-trip mismatch")
	}

	ct, err := Encrypt(dek, []byte("hunter2"))
	if err != nil {
		t.Fatal(err)
	}
	pt, err := Decrypt(dek, ct)
	if err != nil {
		t.Fatal(err)
	}
	if string(pt) != "hunter2" {
		t.Fatalf("got %q", pt)
	}
}

func TestWrongPassword(t *testing.T) {
	dek, _ := GenerateDEK()
	salt, _ := GenerateSalt()
	wrapped, _ := WrapDEK(dek, DeriveKEK("right", salt))
	if _, err := UnwrapDEK(wrapped, DeriveKEK("wrong", salt)); err == nil {
		t.Fatal("expected failure with wrong password")
	}
}

func TestTamper(t *testing.T) {
	dek, _ := GenerateDEK()
	ct, _ := Encrypt(dek, []byte("secret"))
	ct[len(ct)-1] ^= 0xff
	if _, err := Decrypt(dek, ct); err == nil {
		t.Fatal("expected failure on tampered ciphertext")
	}
}
