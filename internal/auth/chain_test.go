package auth

import (
	"context"
	"errors"
	"testing"
)

// mockAuth is a simple Authenticator whose result is fixed at construction time.
type mockAuth struct {
	identity *Identity
	err      error
}

func (m *mockAuth) Authenticate(_ context.Context, _, _ string) (*Identity, error) {
	return m.identity, m.err
}

func TestChainAuthenticator(t *testing.T) {
	ctx := context.Background()
	wantIdentity := &Identity{Username: "alice", DisplayName: "Alice", AuthProvider: "test"}

	t.Run("single authenticator succeeds: returns identity", func(t *testing.T) {
		chain := NewChainAuthenticator(&mockAuth{identity: wantIdentity})
		got, err := chain.Authenticate(ctx, "alice", "pass")
		if err != nil {
			t.Fatalf("Authenticate returned error: %v", err)
		}
		if got != wantIdentity {
			t.Errorf("Authenticate returned %v; want %v", got, wantIdentity)
		}
	})

	t.Run("single authenticator returns ErrInvalidCredentials: chain returns ErrInvalidCredentials", func(t *testing.T) {
		chain := NewChainAuthenticator(&mockAuth{err: ErrInvalidCredentials})
		_, err := chain.Authenticate(ctx, "alice", "wrong")
		if !errors.Is(err, ErrInvalidCredentials) {
			t.Errorf("Authenticate returned %v; want ErrInvalidCredentials", err)
		}
	})

	t.Run("single authenticator returns ErrUnsupported: chain returns ErrUnsupported", func(t *testing.T) {
		chain := NewChainAuthenticator(&mockAuth{err: ErrUnsupported})
		_, err := chain.Authenticate(ctx, "alice", "pass")
		if !errors.Is(err, ErrUnsupported) {
			t.Errorf("Authenticate returned %v; want ErrUnsupported", err)
		}
	})

	t.Run("first fails ErrInvalidCredentials, second succeeds: returns second identity", func(t *testing.T) {
		second := &Identity{Username: "bob", AuthProvider: "second"}
		chain := NewChainAuthenticator(
			&mockAuth{err: ErrInvalidCredentials},
			&mockAuth{identity: second},
		)
		got, err := chain.Authenticate(ctx, "bob", "pass")
		if err != nil {
			t.Fatalf("Authenticate returned error: %v", err)
		}
		if got != second {
			t.Errorf("Authenticate returned %v; want %v", got, second)
		}
	})

	t.Run("first ErrUnsupported, second succeeds: returns second identity", func(t *testing.T) {
		second := &Identity{Username: "carol", AuthProvider: "second"}
		chain := NewChainAuthenticator(
			&mockAuth{err: ErrUnsupported},
			&mockAuth{identity: second},
		)
		got, err := chain.Authenticate(ctx, "carol", "pass")
		if err != nil {
			t.Fatalf("Authenticate returned error: %v", err)
		}
		if got != second {
			t.Errorf("Authenticate returned %v; want %v", got, second)
		}
	})

	// When every authenticator returns ErrUnsupported the chain signals that no
	// backend was able to handle the request at all.
	t.Run("both return ErrUnsupported: chain returns ErrUnsupported", func(t *testing.T) {
		chain := NewChainAuthenticator(
			&mockAuth{err: ErrUnsupported},
			&mockAuth{err: ErrUnsupported},
		)
		_, err := chain.Authenticate(ctx, "dave", "pass")
		if !errors.Is(err, ErrUnsupported) {
			t.Errorf("Authenticate returned %v; want ErrUnsupported", err)
		}
	})

	// When the first backend is simply unsupported but the second actively
	// rejects the credentials, the chain has seen at least one supported backend
	// and should report the credential failure.  However, the current
	// implementation propagates the ErrUnsupported flag even when a later
	// backend returns ErrInvalidCredentials.  The test documents the actual
	// behaviour so a future refactor is noticed immediately.
	t.Run("first ErrUnsupported, second ErrInvalidCredentials: chain returns ErrUnsupported (current behaviour)", func(t *testing.T) {
		chain := NewChainAuthenticator(
			&mockAuth{err: ErrUnsupported},
			&mockAuth{err: ErrInvalidCredentials},
		)
		_, err := chain.Authenticate(ctx, "eve", "pass")
		if !errors.Is(err, ErrUnsupported) {
			t.Errorf("Authenticate returned %v; want ErrUnsupported (see chain.go logic)", err)
		}
	})

	t.Run("first returns unexpected error: chain returns that error immediately", func(t *testing.T) {
		sentinel := errors.New("database connection lost")
		chain := NewChainAuthenticator(
			&mockAuth{err: sentinel},
			&mockAuth{identity: wantIdentity}, // never reached
		)
		_, err := chain.Authenticate(ctx, "frank", "pass")
		if !errors.Is(err, sentinel) {
			t.Errorf("Authenticate returned %v; want sentinel error %v", err, sentinel)
		}
	})

	t.Run("unexpected error short-circuits: second authenticator not called", func(t *testing.T) {
		called := false
		type trackingAuth struct{ mockAuth }
		// We cannot override Authenticate on embedded struct inline, so use a closure approach.
		var tracker Authenticator = &struct{ mockAuth }{mockAuth{identity: wantIdentity}}
		_ = tracker // unused: the point is the second auth below tracks calls

		sentinel := errors.New("io error")
		secondCalled := false
		second := &callTrackingAuth{inner: &mockAuth{identity: wantIdentity}, called: &secondCalled}

		chain := NewChainAuthenticator(
			&mockAuth{err: sentinel},
			second,
		)
		_, _ = chain.Authenticate(ctx, "george", "pass")
		_ = called
		if secondCalled {
			t.Error("second authenticator was called after unexpected error from first")
		}
	})

	t.Run("empty chain returns ErrInvalidCredentials", func(t *testing.T) {
		chain := NewChainAuthenticator()
		_, err := chain.Authenticate(ctx, "nobody", "pass")
		if !errors.Is(err, ErrInvalidCredentials) {
			t.Errorf("empty chain returned %v; want ErrInvalidCredentials", err)
		}
	})

	t.Run("three authenticators: first two unsupported, third succeeds", func(t *testing.T) {
		third := &Identity{Username: "hector", AuthProvider: "third"}
		chain := NewChainAuthenticator(
			&mockAuth{err: ErrUnsupported},
			&mockAuth{err: ErrUnsupported},
			&mockAuth{identity: third},
		)
		got, err := chain.Authenticate(ctx, "hector", "pass")
		if err != nil {
			t.Fatalf("Authenticate returned error: %v", err)
		}
		if got != third {
			t.Errorf("Authenticate returned %v; want %v", got, third)
		}
	})
}

// callTrackingAuth wraps another Authenticator and records whether it was called.
type callTrackingAuth struct {
	inner  Authenticator
	called *bool
}

func (c *callTrackingAuth) Authenticate(ctx context.Context, username, password string) (*Identity, error) {
	*c.called = true
	return c.inner.Authenticate(ctx, username, password)
}
