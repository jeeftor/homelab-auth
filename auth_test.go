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
	return &Provider{config: Config{CookieName: "test_session", SessionSecret: []byte("0123456789abcdef0123456789abcdef"), SessionDuration: time.Hour, InsecureCookies: true}, logger: slog.Default()}
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
