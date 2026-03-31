package auth

import (
	"errors"
	"sync"
	"time"
)

var ErrRateLimitExceeded = errors.New("too many login attempts, please try again later")

type loginAttempt struct {
	count     int
	firstSeen time.Time
	blockedAt time.Time
}

// LoginRateLimiter tracks failed login attempts per IP address and per username.
// It allows at most maxAttempts failures within window before blocking for blockDuration.
type LoginRateLimiter struct {
	mu          sync.Mutex
	byIP        map[string]*loginAttempt
	byUsername  map[string]*loginAttempt
	maxAttempts int
	window      time.Duration
	blockFor    time.Duration
}

func NewLoginRateLimiter(maxAttempts int, window, blockFor time.Duration) *LoginRateLimiter {
	if maxAttempts <= 0 {
		maxAttempts = 10
	}
	if window <= 0 {
		window = 10 * time.Minute
	}
	if blockFor <= 0 {
		blockFor = 15 * time.Minute
	}
	return &LoginRateLimiter{
		byIP:        make(map[string]*loginAttempt),
		byUsername:  make(map[string]*loginAttempt),
		maxAttempts: maxAttempts,
		window:      window,
		blockFor:    blockFor,
	}
}

// Check returns ErrRateLimitExceeded if the IP or username is currently blocked.
func (r *LoginRateLimiter) Check(ip, username string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	if err := r.checkKey(r.byIP, ip, now); err != nil {
		return err
	}
	if username != "" {
		if err := r.checkKey(r.byUsername, username, now); err != nil {
			return err
		}
	}
	return nil
}

func (r *LoginRateLimiter) checkKey(m map[string]*loginAttempt, key string, now time.Time) error {
	a, ok := m[key]
	if !ok {
		return nil
	}
	if !a.blockedAt.IsZero() {
		if now.Before(a.blockedAt.Add(r.blockFor)) {
			return ErrRateLimitExceeded
		}
		delete(m, key)
		return nil
	}
	return nil
}

// RecordFailure records a failed login attempt for the given IP and username.
func (r *LoginRateLimiter) RecordFailure(ip, username string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	r.recordKey(r.byIP, ip, now)
	if username != "" {
		r.recordKey(r.byUsername, username, now)
	}
}

func (r *LoginRateLimiter) recordKey(m map[string]*loginAttempt, key string, now time.Time) {
	a, ok := m[key]
	if !ok {
		m[key] = &loginAttempt{count: 1, firstSeen: now}
		return
	}
	if now.After(a.firstSeen.Add(r.window)) {
		m[key] = &loginAttempt{count: 1, firstSeen: now}
		return
	}
	a.count++
	if a.count >= r.maxAttempts {
		a.blockedAt = now
	}
}

// RecordSuccess resets failure counters for the given IP and username.
func (r *LoginRateLimiter) RecordSuccess(ip, username string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.byIP, ip)
	if username != "" {
		delete(r.byUsername, username)
	}
}
