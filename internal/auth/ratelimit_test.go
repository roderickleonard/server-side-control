package auth

import (
	"testing"
	"time"
)

func TestLoginRateLimiter(t *testing.T) {
	t.Run("fresh limiter allows first request", func(t *testing.T) {
		rl := NewLoginRateLimiter(5, time.Minute, time.Minute)
		if err := rl.Check("1.2.3.4", "alice"); err != nil {
			t.Errorf("Check on fresh limiter returned %v; want nil", err)
		}
	})

	t.Run("after maxAttempts-1 failures Check still returns nil", func(t *testing.T) {
		rl := NewLoginRateLimiter(5, time.Minute, time.Minute)
		for i := 0; i < 4; i++ {
			rl.RecordFailure("1.2.3.4", "alice")
		}
		if err := rl.Check("1.2.3.4", "alice"); err != nil {
			t.Errorf("Check after maxAttempts-1 failures = %v; want nil", err)
		}
	})

	t.Run("after maxAttempts failures Check returns ErrRateLimitExceeded", func(t *testing.T) {
		rl := NewLoginRateLimiter(5, time.Minute, time.Minute)
		for i := 0; i < 5; i++ {
			rl.RecordFailure("1.2.3.4", "alice")
		}
		if err := rl.Check("1.2.3.4", "alice"); err != ErrRateLimitExceeded {
			t.Errorf("Check after maxAttempts failures = %v; want ErrRateLimitExceeded", err)
		}
	})

	t.Run("RecordSuccess resets the counter so Check passes again", func(t *testing.T) {
		rl := NewLoginRateLimiter(5, time.Minute, time.Minute)
		for i := 0; i < 5; i++ {
			rl.RecordFailure("1.2.3.4", "alice")
		}
		// Blocked now.
		if err := rl.Check("1.2.3.4", "alice"); err != ErrRateLimitExceeded {
			t.Fatalf("expected blocked before RecordSuccess; got %v", err)
		}
		rl.RecordSuccess("1.2.3.4", "alice")
		if err := rl.Check("1.2.3.4", "alice"); err != nil {
			t.Errorf("Check after RecordSuccess = %v; want nil", err)
		}
	})

	t.Run("block expires: Check passes after blockFor has elapsed", func(t *testing.T) {
		rl := NewLoginRateLimiter(3, time.Minute, 5*time.Minute)
		for i := 0; i < 3; i++ {
			rl.RecordFailure("5.5.5.5", "bob")
		}
		// Confirm blocked.
		if err := rl.Check("5.5.5.5", "bob"); err != ErrRateLimitExceeded {
			t.Fatalf("expected blocked; got %v", err)
		}

		// Manually wind back blockedAt so the block appears expired.
		rl.mu.Lock()
		if a, ok := rl.byIP["5.5.5.5"]; ok {
			a.blockedAt = time.Now().Add(-6 * time.Minute)
		}
		if a, ok := rl.byUsername["bob"]; ok {
			a.blockedAt = time.Now().Add(-6 * time.Minute)
		}
		rl.mu.Unlock()

		if err := rl.Check("5.5.5.5", "bob"); err != nil {
			t.Errorf("Check after block expired = %v; want nil", err)
		}
	})

	t.Run("cleanup removes entries whose window has elapsed (not blocked)", func(t *testing.T) {
		rl := NewLoginRateLimiter(10, time.Minute, 5*time.Minute)
		rl.RecordFailure("9.9.9.9", "carol")

		// Manually backdate firstSeen so the window appears expired.
		rl.mu.Lock()
		if a, ok := rl.byIP["9.9.9.9"]; ok {
			a.firstSeen = time.Now().Add(-2 * time.Minute)
		}
		if a, ok := rl.byUsername["carol"]; ok {
			a.firstSeen = time.Now().Add(-2 * time.Minute)
		}
		rl.mu.Unlock()

		rl.cleanup()

		rl.mu.Lock()
		_, ipExists := rl.byIP["9.9.9.9"]
		_, unExists := rl.byUsername["carol"]
		rl.mu.Unlock()

		if ipExists {
			t.Error("cleanup did not remove expired IP entry")
		}
		if unExists {
			t.Error("cleanup did not remove expired username entry")
		}
	})

	t.Run("cleanup removes entries whose blockFor has elapsed", func(t *testing.T) {
		rl := NewLoginRateLimiter(3, time.Minute, 5*time.Minute)
		for i := 0; i < 3; i++ {
			rl.RecordFailure("7.7.7.7", "dave")
		}

		// Wind back blockedAt past blockFor.
		rl.mu.Lock()
		if a, ok := rl.byIP["7.7.7.7"]; ok {
			a.blockedAt = time.Now().Add(-10 * time.Minute)
		}
		if a, ok := rl.byUsername["dave"]; ok {
			a.blockedAt = time.Now().Add(-10 * time.Minute)
		}
		rl.mu.Unlock()

		rl.cleanup()

		rl.mu.Lock()
		_, ipExists := rl.byIP["7.7.7.7"]
		_, unExists := rl.byUsername["dave"]
		rl.mu.Unlock()

		if ipExists {
			t.Error("cleanup did not remove expired blocked IP entry")
		}
		if unExists {
			t.Error("cleanup did not remove expired blocked username entry")
		}
	})

	t.Run("cleanup does not remove entries still within the block window", func(t *testing.T) {
		rl := NewLoginRateLimiter(3, time.Minute, 15*time.Minute)
		for i := 0; i < 3; i++ {
			rl.RecordFailure("8.8.8.8", "eve")
		}

		rl.cleanup()

		rl.mu.Lock()
		_, ipExists := rl.byIP["8.8.8.8"]
		_, unExists := rl.byUsername["eve"]
		rl.mu.Unlock()

		if !ipExists {
			t.Error("cleanup removed an IP entry that should still be blocked")
		}
		if !unExists {
			t.Error("cleanup removed a username entry that should still be blocked")
		}
	})

	t.Run("block by IP only: different user on same IP is also blocked", func(t *testing.T) {
		rl := NewLoginRateLimiter(3, time.Minute, 5*time.Minute)
		for i := 0; i < 3; i++ {
			rl.RecordFailure("3.3.3.3", "user1")
		}
		// A different username coming from the same IP should be blocked.
		if err := rl.Check("3.3.3.3", "user2"); err != ErrRateLimitExceeded {
			t.Errorf("Check(blocked IP, other user) = %v; want ErrRateLimitExceeded", err)
		}
	})

	t.Run("block by username only: different IP with same username is also blocked", func(t *testing.T) {
		rl := NewLoginRateLimiter(3, time.Minute, 5*time.Minute)
		for i := 0; i < 3; i++ {
			rl.RecordFailure("10.0.0.1", "targeted")
		}
		// A different IP attempting the same username should be blocked.
		if err := rl.Check("10.0.0.2", "targeted"); err != ErrRateLimitExceeded {
			t.Errorf("Check(other IP, blocked username) = %v; want ErrRateLimitExceeded", err)
		}
	})

	t.Run("block by IP does not affect a different IP", func(t *testing.T) {
		rl := NewLoginRateLimiter(3, time.Minute, 5*time.Minute)
		for i := 0; i < 3; i++ {
			rl.RecordFailure("11.0.0.1", "nobody")
		}
		// Completely different IP and username should be fine.
		if err := rl.Check("11.0.0.99", "other"); err != nil {
			t.Errorf("Check(clean IP, clean user) = %v; want nil", err)
		}
	})

	t.Run("empty username skips username check", func(t *testing.T) {
		rl := NewLoginRateLimiter(3, time.Minute, 5*time.Minute)
		// Fill up failures without a username; the username map should stay empty.
		for i := 0; i < 3; i++ {
			rl.RecordFailure("12.0.0.1", "")
		}
		rl.mu.Lock()
		usernameMapLen := len(rl.byUsername)
		rl.mu.Unlock()
		if usernameMapLen != 0 {
			t.Errorf("byUsername has %d entries; want 0 when username is empty", usernameMapLen)
		}
	})

	t.Run("failures within window accumulate; reset after window passes", func(t *testing.T) {
		rl := NewLoginRateLimiter(3, time.Minute, 5*time.Minute)
		rl.RecordFailure("13.0.0.1", "frank")
		rl.RecordFailure("13.0.0.1", "frank")

		// Wind firstSeen back past the window to simulate expiry.
		rl.mu.Lock()
		if a, ok := rl.byIP["13.0.0.1"]; ok {
			a.firstSeen = time.Now().Add(-2 * time.Minute)
		}
		if a, ok := rl.byUsername["frank"]; ok {
			a.firstSeen = time.Now().Add(-2 * time.Minute)
		}
		rl.mu.Unlock()

		// Next failure should start a fresh counter.
		rl.RecordFailure("13.0.0.1", "frank")

		rl.mu.Lock()
		ipCount := rl.byIP["13.0.0.1"].count
		unCount := rl.byUsername["frank"].count
		rl.mu.Unlock()

		if ipCount != 1 {
			t.Errorf("IP count after window reset = %d; want 1", ipCount)
		}
		if unCount != 1 {
			t.Errorf("username count after window reset = %d; want 1", unCount)
		}
	})

	t.Run("zero maxAttempts defaults to 10", func(t *testing.T) {
		rl := NewLoginRateLimiter(0, time.Minute, 5*time.Minute)
		if rl.maxAttempts != 10 {
			t.Errorf("maxAttempts = %d; want 10", rl.maxAttempts)
		}
	})

	t.Run("zero window defaults to 10 minutes", func(t *testing.T) {
		rl := NewLoginRateLimiter(5, 0, 5*time.Minute)
		if rl.window != 10*time.Minute {
			t.Errorf("window = %v; want 10m", rl.window)
		}
	})

	t.Run("zero blockFor defaults to 15 minutes", func(t *testing.T) {
		rl := NewLoginRateLimiter(5, time.Minute, 0)
		if rl.blockFor != 15*time.Minute {
			t.Errorf("blockFor = %v; want 15m", rl.blockFor)
		}
	})
}
