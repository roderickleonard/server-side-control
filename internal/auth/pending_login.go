package auth

import (
	"context"
	"errors"
	"sync"
	"time"
)

var ErrPendingLoginNotFound = errors.New("pending login not found")

type PendingLogin struct {
	ID         string
	Identity   Identity
	CreatedAt  time.Time
	ExpiresAt  time.Time
	RemoteAddr string
}

type PendingLoginManager struct {
	mu        sync.RWMutex
	logins    map[string]PendingLogin
	lifetime  time.Duration
}

func NewPendingLoginManager(lifetime time.Duration) *PendingLoginManager {
	if lifetime <= 0 {
		lifetime = 5 * time.Minute
	}
	return &PendingLoginManager{logins: make(map[string]PendingLogin), lifetime: lifetime}
}

func (m *PendingLoginManager) Create(_ context.Context, identity Identity, remoteAddr string) (PendingLogin, error) {
	id, err := randomToken(24)
	if err != nil {
		return PendingLogin{}, err
	}
	login := PendingLogin{
		ID:         id,
		Identity:   identity,
		CreatedAt:  time.Now(),
		ExpiresAt:  time.Now().Add(m.lifetime),
		RemoteAddr: remoteAddr,
	}
	m.mu.Lock()
	m.logins[id] = login
	m.mu.Unlock()
	return login, nil
}

func (m *PendingLoginManager) Get(_ context.Context, id string) (PendingLogin, error) {
	m.mu.RLock()
	login, ok := m.logins[id]
	m.mu.RUnlock()
	if !ok {
		return PendingLogin{}, ErrPendingLoginNotFound
	}
	if time.Now().After(login.ExpiresAt) {
		m.Delete(context.Background(), id)
		return PendingLogin{}, ErrPendingLoginNotFound
	}
	return login, nil
}

func (m *PendingLoginManager) Delete(_ context.Context, id string) {
	m.mu.Lock()
	delete(m.logins, id)
	m.mu.Unlock()
}