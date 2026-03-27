package auth

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

var ErrWebAuthnChallengeNotFound = errors.New("webauthn challenge not found")

type WebAuthnChallenge struct {
	ID         string
	Username   string
	Challenge  string
	Operation  string
	CreatedAt  time.Time
	ExpiresAt  time.Time
	RemoteAddr string
}

type WebAuthnChallengeManager struct {
	mu        sync.RWMutex
	items     map[string]WebAuthnChallenge
	lifetime  time.Duration
}

func NewWebAuthnChallengeManager(lifetime time.Duration) *WebAuthnChallengeManager {
	if lifetime <= 0 {
		lifetime = 5 * time.Minute
	}
	return &WebAuthnChallengeManager{items: make(map[string]WebAuthnChallenge), lifetime: lifetime}
}

func (m *WebAuthnChallengeManager) Create(_ context.Context, username string, operation string, remoteAddr string) (WebAuthnChallenge, error) {
	id, err := randomToken(24)
	if err != nil {
		return WebAuthnChallenge{}, err
	}
	challenge, err := GenerateWebAuthnChallenge()
	if err != nil {
		return WebAuthnChallenge{}, err
	}
	item := WebAuthnChallenge{
		ID:         id,
		Username:   strings.TrimSpace(username),
		Challenge:  challenge,
		Operation:  strings.TrimSpace(operation),
		CreatedAt:  time.Now(),
		ExpiresAt:  time.Now().Add(m.lifetime),
		RemoteAddr: remoteAddr,
	}
	m.mu.Lock()
	m.items[id] = item
	m.mu.Unlock()
	return item, nil
}

func (m *WebAuthnChallengeManager) Get(_ context.Context, id string) (WebAuthnChallenge, error) {
	m.mu.RLock()
	item, ok := m.items[id]
	m.mu.RUnlock()
	if !ok {
		return WebAuthnChallenge{}, ErrWebAuthnChallengeNotFound
	}
	if time.Now().After(item.ExpiresAt) {
		m.Delete(context.Background(), id)
		return WebAuthnChallenge{}, ErrWebAuthnChallengeNotFound
	}
	return item, nil
}

func (m *WebAuthnChallengeManager) Delete(_ context.Context, id string) {
	m.mu.Lock()
	delete(m.items, id)
	m.mu.Unlock()
}

func GenerateWebAuthnChallenge() (string, error) {
	buffer := make([]byte, 32)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	return Base64URLEncode(buffer), nil
}

func Base64URLEncode(value []byte) string {
	return base64.RawURLEncoding.EncodeToString(value)
}

func Base64URLDecode(value string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(strings.TrimSpace(value))
}

type ParsedClientData struct {
	Type      string `json:"type"`
	Challenge string `json:"challenge"`
	Origin    string `json:"origin"`
}

func ParseClientData(clientDataJSON string) (ParsedClientData, []byte, error) {
	raw, err := Base64URLDecode(clientDataJSON)
	if err != nil {
		return ParsedClientData{}, nil, err
	}
	var parsed ParsedClientData
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return ParsedClientData{}, nil, err
	}
	return parsed, raw, nil
}

func VerifyWebAuthnAssertion(publicKeySPKI string, rpID string, clientDataJSON string, authenticatorData string, signature string, expectedChallenge string, expectedOrigin string) (uint32, error) {
	clientData, clientDataRaw, err := ParseClientData(clientDataJSON)
	if err != nil {
		return 0, fmt.Errorf("parse client data: %w", err)
	}
	if clientData.Type != "webauthn.get" {
		return 0, fmt.Errorf("unexpected client data type")
	}
	if clientData.Challenge != expectedChallenge {
		return 0, fmt.Errorf("challenge mismatch")
	}
	if strings.TrimSpace(clientData.Origin) != strings.TrimSpace(expectedOrigin) {
		return 0, fmt.Errorf("origin mismatch")
	}
	authenticatorBytes, err := Base64URLDecode(authenticatorData)
	if err != nil {
		return 0, fmt.Errorf("decode authenticator data: %w", err)
	}
	if len(authenticatorBytes) < 37 {
		return 0, fmt.Errorf("authenticator data is too short")
	}
	rpHash := sha256.Sum256([]byte(strings.TrimSpace(rpID)))
	if string(authenticatorBytes[:32]) != string(rpHash[:]) {
		return 0, fmt.Errorf("rp id hash mismatch")
	}
	if authenticatorBytes[32]&0x01 == 0 {
		return 0, fmt.Errorf("user presence flag missing")
	}
	clientHash := sha256.Sum256(clientDataRaw)
	signedPayload := append(append([]byte{}, authenticatorBytes...), clientHash[:]...)
	publicKeyBytes, err := Base64URLDecode(publicKeySPKI)
	if err != nil {
		return 0, fmt.Errorf("decode public key: %w", err)
	}
	parsedKey, err := x509.ParsePKIXPublicKey(publicKeyBytes)
	if err != nil {
		return 0, fmt.Errorf("parse public key: %w", err)
	}
	ecdsaKey, ok := parsedKey.(*ecdsa.PublicKey)
	if !ok {
		return 0, fmt.Errorf("unsupported public key type")
	}
	signatureBytes, err := Base64URLDecode(signature)
	if err != nil {
		return 0, fmt.Errorf("decode signature: %w", err)
	}
	hash := sha256.Sum256(signedPayload)
	if !ecdsa.VerifyASN1(ecdsaKey, hash[:], signatureBytes) {
		return 0, fmt.Errorf("signature verification failed")
	}
	signCount := uint32(authenticatorBytes[33])<<24 | uint32(authenticatorBytes[34])<<16 | uint32(authenticatorBytes[35])<<8 | uint32(authenticatorBytes[36])
	return signCount, nil
}