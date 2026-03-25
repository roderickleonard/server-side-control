package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sync"
	"time"
)

var ErrSessionNotFound = errors.New("session not found")

type Session struct {
	ID         string
	Identity   Identity
	CreatedAt  time.Time
	ExpiresAt  time.Time
	RemoteAddr string
}

type SessionManager struct {
	mu       sync.RWMutex
	sessions map[string]Session
	lifetime time.Duration
}

func NewSessionManager(lifetime time.Duration) *SessionManager {
	if lifetime <= 0 {
		lifetime = 12 * time.Hour
	}
	return &SessionManager{
		sessions: make(map[string]Session),
		lifetime: lifetime,
	}
}

func (m *SessionManager) Create(_ context.Context, identity Identity, remoteAddr string) (Session, error) {
	id, err := randomToken(32)
	if err != nil {
		return Session{}, err
	}

	session := Session{
		ID:         id,
		Identity:   identity,
		CreatedAt:  time.Now(),
		ExpiresAt:  time.Now().Add(m.lifetime),
		RemoteAddr: remoteAddr,
	}

	m.mu.Lock()
	m.sessions[id] = session
	m.mu.Unlock()

	return session, nil
}

func (m *SessionManager) Get(_ context.Context, id string) (Session, error) {
	m.mu.RLock()
	session, ok := m.sessions[id]
	m.mu.RUnlock()
	if !ok {
		return Session{}, ErrSessionNotFound
	}
	if time.Now().After(session.ExpiresAt) {
		m.Delete(context.Background(), id)
		return Session{}, ErrSessionNotFound
	}
	return session, nil
}

func (m *SessionManager) Delete(_ context.Context, id string) {
	m.mu.Lock()
	delete(m.sessions, id)
	m.mu.Unlock()
}

func randomToken(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}
