package auth

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestSessionManager(t *testing.T) {
	ctx := context.Background()

	t.Run("Create then Get returns the session with correct identity", func(t *testing.T) {
		sm := NewSessionManager(time.Hour)
		identity := Identity{Username: "alice", DisplayName: "Alice", AuthProvider: "test"}

		session, err := sm.Create(ctx, identity, "127.0.0.1")
		if err != nil {
			t.Fatalf("Create returned error: %v", err)
		}
		if session.ID == "" {
			t.Fatal("Create returned session with empty ID")
		}

		got, err := sm.Get(ctx, session.ID)
		if err != nil {
			t.Fatalf("Get returned error: %v", err)
		}
		if got.Identity.Username != identity.Username {
			t.Errorf("Identity.Username = %q; want %q", got.Identity.Username, identity.Username)
		}
		if got.Identity.DisplayName != identity.DisplayName {
			t.Errorf("Identity.DisplayName = %q; want %q", got.Identity.DisplayName, identity.DisplayName)
		}
		if got.Identity.AuthProvider != identity.AuthProvider {
			t.Errorf("Identity.AuthProvider = %q; want %q", got.Identity.AuthProvider, identity.AuthProvider)
		}
		if got.RemoteAddr != "127.0.0.1" {
			t.Errorf("RemoteAddr = %q; want %q", got.RemoteAddr, "127.0.0.1")
		}
	})

	t.Run("Get on non-existent ID returns ErrSessionNotFound", func(t *testing.T) {
		sm := NewSessionManager(time.Hour)
		_, err := sm.Get(ctx, "does-not-exist")
		if !errors.Is(err, ErrSessionNotFound) {
			t.Errorf("Get(unknown) = %v; want ErrSessionNotFound", err)
		}
	})

	t.Run("Delete then Get returns ErrSessionNotFound", func(t *testing.T) {
		sm := NewSessionManager(time.Hour)
		identity := Identity{Username: "bob"}

		session, err := sm.Create(ctx, identity, "10.0.0.1")
		if err != nil {
			t.Fatalf("Create returned error: %v", err)
		}

		sm.Delete(ctx, session.ID)

		_, err = sm.Get(ctx, session.ID)
		if !errors.Is(err, ErrSessionNotFound) {
			t.Errorf("Get after Delete = %v; want ErrSessionNotFound", err)
		}
	})

	t.Run("Get on expired session returns ErrSessionNotFound", func(t *testing.T) {
		sm := NewSessionManager(time.Hour)
		identity := Identity{Username: "carol"}

		session, err := sm.Create(ctx, identity, "192.168.1.1")
		if err != nil {
			t.Fatalf("Create returned error: %v", err)
		}

		// Manually expire the session by replacing it in the internal map.
		sm.mu.Lock()
		expired := sm.sessions[session.ID]
		expired.ExpiresAt = time.Now().Add(-time.Second)
		sm.sessions[session.ID] = expired
		sm.mu.Unlock()

		_, err = sm.Get(ctx, session.ID)
		if !errors.Is(err, ErrSessionNotFound) {
			t.Errorf("Get on expired session = %v; want ErrSessionNotFound", err)
		}
	})

	t.Run("expired session is removed from map after Get", func(t *testing.T) {
		sm := NewSessionManager(time.Hour)
		identity := Identity{Username: "dave"}

		session, err := sm.Create(ctx, identity, "10.0.0.2")
		if err != nil {
			t.Fatalf("Create returned error: %v", err)
		}

		// Expire the session.
		sm.mu.Lock()
		expired := sm.sessions[session.ID]
		expired.ExpiresAt = time.Now().Add(-time.Second)
		sm.sessions[session.ID] = expired
		sm.mu.Unlock()

		// Trigger cleanup via Get.
		_, _ = sm.Get(ctx, session.ID)

		// The entry should now be gone.
		sm.mu.RLock()
		_, still := sm.sessions[session.ID]
		sm.mu.RUnlock()
		if still {
			t.Error("expired session was not removed from the map after Get")
		}
	})

	t.Run("zero lifetime defaults to 12 hours", func(t *testing.T) {
		sm := NewSessionManager(0)
		identity := Identity{Username: "eve"}

		before := time.Now()
		session, err := sm.Create(ctx, identity, "::1")
		after := time.Now()
		if err != nil {
			t.Fatalf("Create returned error: %v", err)
		}

		wantMin := before.Add(12 * time.Hour)
		wantMax := after.Add(12 * time.Hour)

		if session.ExpiresAt.Before(wantMin) || session.ExpiresAt.After(wantMax) {
			t.Errorf("ExpiresAt = %v; want within [%v, %v]", session.ExpiresAt, wantMin, wantMax)
		}

		dur := session.ExpiresAt.Sub(session.CreatedAt)
		if dur < 12*time.Hour-time.Second || dur > 12*time.Hour+time.Second {
			t.Errorf("ExpiresAt - CreatedAt = %v; want approximately 12h", dur)
		}
	})

	t.Run("multiple sessions coexist independently", func(t *testing.T) {
		sm := NewSessionManager(time.Hour)

		s1, _ := sm.Create(ctx, Identity{Username: "user1"}, "1.1.1.1")
		s2, _ := sm.Create(ctx, Identity{Username: "user2"}, "2.2.2.2")

		got1, err := sm.Get(ctx, s1.ID)
		if err != nil || got1.Identity.Username != "user1" {
			t.Errorf("unexpected result for session 1: %v, %v", got1.Identity.Username, err)
		}

		got2, err := sm.Get(ctx, s2.ID)
		if err != nil || got2.Identity.Username != "user2" {
			t.Errorf("unexpected result for session 2: %v, %v", got2.Identity.Username, err)
		}

		// Delete one; the other should still exist.
		sm.Delete(ctx, s1.ID)
		_, err = sm.Get(ctx, s2.ID)
		if err != nil {
			t.Errorf("Get(s2) after deleting s1 returned error: %v", err)
		}
	})
}

func TestPendingLoginManager(t *testing.T) {
	ctx := context.Background()

	t.Run("Create then Get returns the pending login with correct identity", func(t *testing.T) {
		plm := NewPendingLoginManager(time.Hour)
		identity := Identity{Username: "alice", DisplayName: "Alice", AuthProvider: "test"}

		login, err := plm.Create(ctx, identity, "127.0.0.1")
		if err != nil {
			t.Fatalf("Create returned error: %v", err)
		}
		if login.ID == "" {
			t.Fatal("Create returned pending login with empty ID")
		}

		got, err := plm.Get(ctx, login.ID)
		if err != nil {
			t.Fatalf("Get returned error: %v", err)
		}
		if got.Identity.Username != identity.Username {
			t.Errorf("Identity.Username = %q; want %q", got.Identity.Username, identity.Username)
		}
		if got.RemoteAddr != "127.0.0.1" {
			t.Errorf("RemoteAddr = %q; want %q", got.RemoteAddr, "127.0.0.1")
		}
	})

	t.Run("Get on non-existent ID returns ErrPendingLoginNotFound", func(t *testing.T) {
		plm := NewPendingLoginManager(time.Hour)
		_, err := plm.Get(ctx, "no-such-id")
		if !errors.Is(err, ErrPendingLoginNotFound) {
			t.Errorf("Get(unknown) = %v; want ErrPendingLoginNotFound", err)
		}
	})

	t.Run("Delete then Get returns ErrPendingLoginNotFound", func(t *testing.T) {
		plm := NewPendingLoginManager(time.Hour)
		identity := Identity{Username: "bob"}

		login, err := plm.Create(ctx, identity, "10.0.0.1")
		if err != nil {
			t.Fatalf("Create returned error: %v", err)
		}

		plm.Delete(ctx, login.ID)

		_, err = plm.Get(ctx, login.ID)
		if !errors.Is(err, ErrPendingLoginNotFound) {
			t.Errorf("Get after Delete = %v; want ErrPendingLoginNotFound", err)
		}
	})

	t.Run("Get on expired pending login returns ErrPendingLoginNotFound", func(t *testing.T) {
		plm := NewPendingLoginManager(time.Hour)
		identity := Identity{Username: "carol"}

		login, err := plm.Create(ctx, identity, "192.168.0.1")
		if err != nil {
			t.Fatalf("Create returned error: %v", err)
		}

		// Manually expire the pending login via the internal map.
		plm.mu.Lock()
		expired := plm.logins[login.ID]
		expired.ExpiresAt = time.Now().Add(-time.Second)
		plm.logins[login.ID] = expired
		plm.mu.Unlock()

		_, err = plm.Get(ctx, login.ID)
		if !errors.Is(err, ErrPendingLoginNotFound) {
			t.Errorf("Get on expired pending login = %v; want ErrPendingLoginNotFound", err)
		}
	})

	t.Run("expired pending login is removed from map after Get", func(t *testing.T) {
		plm := NewPendingLoginManager(time.Hour)
		identity := Identity{Username: "dave"}

		login, err := plm.Create(ctx, identity, "10.1.1.1")
		if err != nil {
			t.Fatalf("Create returned error: %v", err)
		}

		// Expire it.
		plm.mu.Lock()
		expired := plm.logins[login.ID]
		expired.ExpiresAt = time.Now().Add(-time.Second)
		plm.logins[login.ID] = expired
		plm.mu.Unlock()

		_, _ = plm.Get(ctx, login.ID)

		plm.mu.RLock()
		_, still := plm.logins[login.ID]
		plm.mu.RUnlock()
		if still {
			t.Error("expired pending login was not removed from map after Get")
		}
	})

	t.Run("zero lifetime defaults to 5 minutes", func(t *testing.T) {
		plm := NewPendingLoginManager(0)
		identity := Identity{Username: "eve"}

		before := time.Now()
		login, err := plm.Create(ctx, identity, "::1")
		after := time.Now()
		if err != nil {
			t.Fatalf("Create returned error: %v", err)
		}

		wantMin := before.Add(5 * time.Minute)
		wantMax := after.Add(5 * time.Minute)
		if login.ExpiresAt.Before(wantMin) || login.ExpiresAt.After(wantMax) {
			t.Errorf("ExpiresAt = %v; want within [%v, %v]", login.ExpiresAt, wantMin, wantMax)
		}

		dur := login.ExpiresAt.Sub(login.CreatedAt)
		if dur < 5*time.Minute-time.Second || dur > 5*time.Minute+time.Second {
			t.Errorf("ExpiresAt - CreatedAt = %v; want approximately 5m", dur)
		}
	})
}
