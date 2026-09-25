// Package crypto implements Valet's envelope encryption: a random DEK
// (AES-256-GCM) encrypts secrets at rest, and a KEK derived from the master
// password via Argon2id wraps the DEK.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"

	"golang.org/x/crypto/argon2"
)

const (
	dekLen    = 32
	saltLen   = 16
	argonTime = 3
	argonMem  = 64 * 1024
	argonPar  = 2
	kekLen    = 32
)

var ErrBadKey = errors.New("crypto: decryption failed (wrong key or corrupted data)")

// GenerateDEK returns a fresh random 32-byte data encryption key.
func GenerateDEK() ([]byte, error) {
	dek := make([]byte, dekLen)
	_, err := rand.Read(dek)
	return dek, err
}

// GenerateSalt returns a fresh random salt for key derivation.
func GenerateSalt() ([]byte, error) {
	s := make([]byte, saltLen)
	_, err := rand.Read(s)
	return s, err
}

// DeriveKEK derives a key-encryption key from a master password and salt.
func DeriveKEK(password string, salt []byte) []byte {
	return argon2.IDKey([]byte(password), salt, argonTime, argonMem, argonPar, kekLen)
}

func gcm(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func seal(key, plaintext []byte) ([]byte, error) {
	aead, err := gcm(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return aead.Seal(nonce, nonce, plaintext, nil), nil
}

func open(key, ciphertext []byte) ([]byte, error) {
	aead, err := gcm(key)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < aead.NonceSize() {
		return nil, ErrBadKey
	}
	nonce, ct := ciphertext[:aead.NonceSize()], ciphertext[aead.NonceSize():]
	pt, err := aead.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, fmt.Errorf("%w", ErrBadKey)
	}
	return pt, nil
}

// WrapDEK encrypts dek under kek. Returns nonce||ciphertext.
func WrapDEK(dek, kek []byte) ([]byte, error) { return seal(kek, dek) }

// UnwrapDEK decrypts a wrapped DEK.
func UnwrapDEK(wrapped, kek []byte) ([]byte, error) { return open(kek, wrapped) }

// Encrypt encrypts plaintext under dek. Returns nonce||ciphertext.
func Encrypt(dek, plaintext []byte) ([]byte, error) { return seal(dek, plaintext) }

// Decrypt decrypts ciphertext produced by Encrypt.
func Decrypt(dek, ciphertext []byte) ([]byte, error) { return open(dek, ciphertext) }
