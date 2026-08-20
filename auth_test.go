package homelabauth

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func testProvider(t *testing.T) *Provider {
	t.Helper()
	return &Provider{config: Config{CookieName: "test_session", StateCookieName: "test_state", SessionSecret: []byte("0123456789abcdef0123456789abcdef"), SessionDuration: time.Hour, InsecureCookies: true}, logger: slog.Default()}
}

func TestNewRejectsUnsafeConfiguration(t *testing.T) {
	_, err := New(context.Background(), Config{Issuer: "https://id.example", ClientID: "client", RedirectURL: "https://app.example/callback", SessionSecret: []byte("too-short")})
	if err == nil {
		t.Fatal("New accepted a short session secret")
	}
}

func TestSessionCookieRoundTripAndTamper(t *testing.T) {
	p := testProvider(t)
	recorder := httptest.NewRecorder()
	identity := Identity{Subject: "user-1", Groups: []string{"admins"}}
	if err := p.setSessionCookie(recorder, identity); err != nil {
		t.Fatalf("setSessionCookie: %v", err)
	}
	cookie := recorder.Result().Cookies()[0]
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.AddCookie(cookie)
	got, ok := p.IdentityFromRequest(request)
	if !ok || got.Subject != identity.Subject || got.Groups[0] != "admins" {
		t.Fatalf("IdentityFromRequest = %#v, %v", got, ok)
	}

	cookie.Value += "x"
	tampered := httptest.NewRequest(http.MethodGet, "/", nil)
	tampered.AddCookie(cookie)
	if _, ok := p.IdentityFromRequest(tampered); ok {
		t.Fatal("tampered cookie was accepted")
	}
}

func TestRequireGroups(t *testing.T) {
	p := testProvider(t)
	protected := p.RequireGroups([]string{"admins"}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		identity, ok := IdentityFromContext(r.Context())
		if !ok || identity.Subject != "admin" {
			t.Fatal("protected handler did not receive identity")
		}
		w.WriteHeader(http.StatusNoContent)
	}))

	allowed := httptest.NewRecorder()
	p.setSessionCookie(allowed, Identity{Subject: "admin", Groups: []string{"admins"}})
	allowedRequest := httptest.NewRequest(http.MethodGet, "/settings", nil)
	allowedRequest.AddCookie(allowed.Result().Cookies()[0])
	protected.ServeHTTP(allowed, allowedRequest)
	if allowed.Code != http.StatusNoContent {
		t.Fatalf("allowed status = %d", allowed.Code)
	}

	denied := httptest.NewRecorder()
	p.setSessionCookie(denied, Identity{Subject: "viewer", Groups: []string{"viewers"}})
	deniedRequest := httptest.NewRequest(http.MethodGet, "/settings", nil)
	deniedRequest.AddCookie(denied.Result().Cookies()[0])
	protected.ServeHTTP(denied, deniedRequest)
	if denied.Code != http.StatusForbidden {
		t.Fatalf("denied status = %d", denied.Code)
	}
}

func TestValidateConfigRejectsUnsafeConfiguration(t *testing.T) {
	base := Config{
		Issuer:          "https://id.example",
		ClientID:        "client",
		ClientSecret:    "secret",
		RedirectURL:     "https://app.example/auth/callback",
		SessionSecret:   []byte("0123456789abcdef0123456789abcdef"),
		CookieName:      "__Host-session",
		StateCookieName: "__Host-state",
		SessionDuration: time.Hour,
	}

	for name, config := range map[string]Config{
		"missing client secret":    func() Config { value := base; value.ClientSecret = ""; return value }(),
		"HTTP production redirect": func() Config { value := base; value.RedirectURL = "http://app.example/auth/callback"; return value }(),
		"non-local insecure redirect": func() Config {
			value := base
			value.InsecureCookies = true
			value.RedirectURL = "http://app.example/auth/callback"
			return value
		}(),
		"host cookie domain": func() Config { value := base; value.CookieDomain = "example.com"; return value }(),
		"long session":       func() Config { value := base; value.SessionDuration = maxSessionTTL + time.Second; return value }(),
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateConfig(config); err == nil {
				t.Fatal("validateConfig accepted unsafe configuration")
			}
		})
	}
}

func TestLogoutHandlerRequiresPOST(t *testing.T) {
	p := testProvider(t)
	recorder := httptest.NewRecorder()
	p.LogoutHandler(recorder, httptest.NewRequest(http.MethodGet, "/auth/logout", nil))
	if recorder.Code != http.StatusMethodNotAllowed {
		t.Fatalf("logout GET status = %d", recorder.Code)
	}
	if got := recorder.Header().Get("Allow"); got != http.MethodPost {
		t.Fatalf("Allow = %q", got)
	}
}
