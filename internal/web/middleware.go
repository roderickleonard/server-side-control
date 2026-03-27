package web

import (
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/kaganyegin/server-side-control/internal/auth"
)

func (a *App) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started := time.Now()
		next.ServeHTTP(w, r)
		a.logger.Info("http request", "method", r.Method, "path", r.URL.Path, "duration", time.Since(started))
	})
}

func (a *App) sessionMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" || r.URL.Path == "/login" || r.URL.Path == "/login/passkey/begin" || r.URL.Path == "/login/passkey/finish" || r.URL.Path == "/webhooks/site-deploy" || strings.HasPrefix(r.URL.Path, "/static/") {
			next.ServeHTTP(w, r)
			return
		}

		session, err := a.currentSession(r)
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		next.ServeHTTP(w, r.WithContext(auth.ContextWithIdentity(r.Context(), session.Identity)))
	})
}

func (a *App) currentSession(r *http.Request) (auth.Session, error) {
	cookie, err := r.Cookie(a.cfg.SessionCookieName)
	if err != nil {
		return auth.Session{}, err
	}

	session, err := a.sessions.Get(r.Context(), cookie.Value)
	if err != nil {
		return auth.Session{}, err
	}
	if session.RemoteAddr != "" && session.RemoteAddr != a.clientAddress(r) {
		return auth.Session{}, errors.New("remote address mismatch")
	}
	return session, nil
}

func (a *App) clientAddress(r *http.Request) string {
	if forwardedFor := strings.TrimSpace(r.Header.Get("X-Forwarded-For")); forwardedFor != "" {
		parts := strings.Split(forwardedFor, ",")
		if len(parts) > 0 {
			return strings.TrimSpace(parts[0])
		}
	}

	if realIP := strings.TrimSpace(r.Header.Get("X-Real-IP")); realIP != "" {
		return realIP
	}

	host, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr))
	if err == nil {
		return host
	}

	return strings.TrimSpace(r.RemoteAddr)
}

func (a *App) setSessionCookie(w http.ResponseWriter, r *http.Request, session auth.Session) {
	http.SetCookie(w, &http.Cookie{
		Name:     a.cfg.SessionCookieName,
		Value:    session.ID,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   a.requestUsesHTTPS(r),
		Expires:  session.ExpiresAt,
	})
}

func (a *App) pendingLoginCookieName() string {
	return a.cfg.SessionCookieName + "_pending_login"
}

func (a *App) currentPendingLogin(r *http.Request) (auth.PendingLogin, error) {
	cookie, err := r.Cookie(a.pendingLoginCookieName())
	if err != nil {
		return auth.PendingLogin{}, err
	}
	login, err := a.pendingLogins.Get(r.Context(), cookie.Value)
	if err != nil {
		return auth.PendingLogin{}, err
	}
	if login.RemoteAddr != "" && login.RemoteAddr != a.clientAddress(r) {
		return auth.PendingLogin{}, errors.New("remote address mismatch")
	}
	return login, nil
}

func (a *App) setPendingLoginCookie(w http.ResponseWriter, r *http.Request, login auth.PendingLogin) {
	http.SetCookie(w, &http.Cookie{
		Name:     a.pendingLoginCookieName(),
		Value:    login.ID,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   a.requestUsesHTTPS(r),
		Expires:  login.ExpiresAt,
	})
}

func (a *App) requestUsesHTTPS(r *http.Request) bool {
	if r != nil {
		if r.TLS != nil {
			return true
		}
		if strings.EqualFold(strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")), "https") {
			return true
		}
		return false
	}
	parsed, err := url.Parse(strings.TrimSpace(a.cfg.BaseURL))
	if err != nil {
		return false
	}
	return strings.EqualFold(parsed.Scheme, "https")
}

func (a *App) clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     a.cfg.SessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}

func (a *App) clearPendingLoginCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     a.pendingLoginCookieName(),
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}

func (a *App) requestHost(r *http.Request) string {
	if forwardedHost := strings.TrimSpace(r.Header.Get("X-Forwarded-Host")); forwardedHost != "" {
		parts := strings.Split(forwardedHost, ",")
		return strings.TrimSpace(parts[0])
	}
	return strings.TrimSpace(r.Host)
}

func (a *App) requestOrigin(r *http.Request) string {
	scheme := "http"
	if a.requestUsesHTTPS(r) {
		scheme = "https"
	}
	return scheme + "://" + a.requestHost(r)
}
