// Package homelabauth provides small, secure OIDC handlers for self-hosted Go applications.
package homelabauth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

const (
	defaultCookieName = "__Host-homelab_auth"
	localCookieName   = "homelab_auth"
	stateLifetime     = 10 * time.Minute
	defaultSessionTTL = 8 * time.Hour
	maxSessionTTL     = 24 * time.Hour
)

// Config configures an OIDC client and its signed session cookie.
// SessionSecret must be a unique, random value of at least 32 bytes.
type Config struct {
	Issuer        string
	ClientID      string
	ClientSecret  string
	RedirectURL   string
	SessionSecret []byte

	CookieName      string
	StateCookieName string
	CookieDomain    string
	SessionDuration time.Duration
	InsecureCookies bool // Set only for local HTTP development.
	Logger          *slog.Logger
}

// Identity is the verified identity stored in the signed session cookie.
type Identity struct {
	Subject string   `json:"sub"`
	Email   string   `json:"email,omitempty"`
	Name    string   `json:"name,omitempty"`
	Groups  []string `json:"groups,omitempty"`
}

// Provider owns the OIDC client, signed state, and signed session cookies.
type Provider struct {
	config   Config
	provider *oidc.Provider
	verifier *oidc.IDTokenVerifier
	oauth    oauth2.Config
	logger   *slog.Logger
}

// New discovers the issuer and constructs a Provider.
func New(ctx context.Context, config Config) (*Provider, error) {
	if config.CookieName == "" {
		config.CookieName = defaultCookieName
		if config.InsecureCookies {
			config.CookieName = localCookieName
		}
	}
	if config.StateCookieName == "" {
		config.StateCookieName = config.CookieName + "_oidc_state"
	}
	if config.SessionDuration <= 0 {
		config.SessionDuration = defaultSessionTTL
	}
	if err := validateConfig(config); err != nil {
		return nil, err
	}
	if config.Logger == nil {
		config.Logger = slog.Default()
	}

	issuer, err := oidc.NewProvider(ctx, config.Issuer)
	if err != nil {
		return nil, fmt.Errorf("discover OIDC issuer: %w", err)
	}

	return &Provider{
		config:   config,
		provider: issuer,
		verifier: issuer.Verifier(&oidc.Config{ClientID: config.ClientID}),
		oauth: oauth2.Config{
			ClientID:     config.ClientID,
			ClientSecret: config.ClientSecret,
			Endpoint:     issuer.Endpoint(),
			RedirectURL:  config.RedirectURL,
			Scopes:       []string{oidc.ScopeOpenID, "profile", "email", "groups"},
		},
		logger: config.Logger,
	}, nil
}

// LoginHandler redirects a user to the configured identity provider using PKCE.
func (p *Provider) LoginHandler(w http.ResponseWriter, r *http.Request) {
	state, err := randomValue(32)
	if err != nil {
		p.logger.Error("OIDC login could not create state")
		http.Error(w, "unable to start login", http.StatusInternalServerError)
		return
	}
	nonce, err := randomValue(32)
	if err != nil {
		p.logger.Error("OIDC login could not create nonce")
		http.Error(w, "unable to start login", http.StatusInternalServerError)
		return
	}
	verifier, err := randomValue(32)
	if err != nil {
		p.logger.Error("OIDC login could not create PKCE verifier")
		http.Error(w, "unable to start login", http.StatusInternalServerError)
		return
	}

	p.setStateCookie(w, stateRecord{State: state, Nonce: nonce, Verifier: verifier, ExpiresAt: time.Now().Add(stateLifetime)})
	p.logger.Debug("OIDC login started")
	http.Redirect(w, r, p.oauth.AuthCodeURL(state, oidc.Nonce(nonce), oauth2.S256ChallengeOption(verifier)), http.StatusFound)
}

// CallbackHandler validates the authorization response and creates a signed session.
func (p *Provider) CallbackHandler(w http.ResponseWriter, r *http.Request) {
	stored, err := p.readState(r)
	if err != nil || stored.ExpiresAt.Before(time.Now()) || !secureEqual(stored.State, r.URL.Query().Get("state")) {
		p.clearStateCookie(w)
		p.logger.Warn("OIDC callback rejected", "reason", "invalid_state")
		http.Error(w, "invalid login state", http.StatusBadRequest)
		return
	}
	p.clearStateCookie(w)

	token, err := p.oauth.Exchange(r.Context(), r.URL.Query().Get("code"), oauth2.VerifierOption(stored.Verifier))
	if err != nil {
		p.logger.Warn("OIDC callback rejected", "reason", "code_exchange_failed")
		http.Error(w, "login failed", http.StatusUnauthorized)
		return
	}
	idToken, ok := token.Extra("id_token").(string)
	if !ok || idToken == "" {
		p.logger.Warn("OIDC callback rejected", "reason", "missing_id_token")
		http.Error(w, "login failed", http.StatusUnauthorized)
		return
	}
	verified, err := p.verifier.Verify(r.Context(), idToken)
	if err != nil {
		p.logger.Warn("OIDC callback rejected", "reason", "invalid_id_token")
		http.Error(w, "login failed", http.StatusUnauthorized)
		return
	}
	if !secureEqual(verified.Nonce, stored.Nonce) {
		p.logger.Warn("OIDC callback rejected", "reason", "invalid_nonce")
		http.Error(w, "login failed", http.StatusUnauthorized)
		return
	}

	var claims struct {
		Subject string   `json:"sub"`
		Email   string   `json:"email"`
		Name    string   `json:"name"`
		Groups  []string `json:"groups"`
	}
	if err := verified.Claims(&claims); err != nil || claims.Subject == "" {
		p.logger.Warn("OIDC callback rejected", "reason", "invalid_claims")
		http.Error(w, "login failed", http.StatusUnauthorized)
		return
	}

	identity := Identity{Subject: claims.Subject, Email: claims.Email, Name: claims.Name, Groups: claims.Groups}
	if err := p.setSessionCookie(w, identity); err != nil {
		p.logger.Error("OIDC session could not be created")
		http.Error(w, "login failed", http.StatusInternalServerError)
		return
	}
	p.logger.Info("OIDC session established", "group_count", len(identity.Groups))
	http.Redirect(w, r, "/", http.StatusFound)
}

// LogoutHandler clears the current session cookie and redirects to the site root.
func (p *Provider) LogoutHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	p.clearSessionCookie(w)
	p.logger.Info("OIDC session ended")
	http.Redirect(w, r, "/", http.StatusFound)
}

// IdentityFromRequest returns the verified session identity, if one is present.
func (p *Provider) IdentityFromRequest(r *http.Request) (Identity, bool) {
	cookie, err := r.Cookie(p.config.CookieName)
	if err != nil {
		return Identity{}, false
	}
	var session sessionRecord
	if err := p.decodeSigned(cookie.Value, &session); err != nil || session.ExpiresAt.Before(time.Now()) || session.Identity.Subject == "" {
		return Identity{}, false
	}
	return session.Identity, true
}

// RequireAuthenticated protects next and exposes the identity through IdentityFromContext.
func (p *Provider) RequireAuthenticated(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		identity, ok := p.IdentityFromRequest(r)
		if !ok {
			http.Error(w, "authentication required", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), identityContextKey{}, identity)))
	})
}

// RequireGroups protects next so that the user belongs to at least one required group.
func (p *Provider) RequireGroups(groups []string, next http.Handler) http.Handler {
	return p.RequireAuthenticated(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		identity, _ := IdentityFromContext(r.Context())
		if !hasAnyGroup(identity.Groups, groups) {
			p.logger.Warn("OIDC authorization denied", "subject", identity.Subject)
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	}))
}

type identityContextKey struct{}

// IdentityFromContext returns the authenticated identity installed by RequireAuthenticated.
func IdentityFromContext(ctx context.Context) (Identity, bool) {
	identity, ok := ctx.Value(identityContextKey{}).(Identity)
	return identity, ok
}

type stateRecord struct {
	State     string    `json:"state"`
	Nonce     string    `json:"nonce"`
	Verifier  string    `json:"verifier"`
	ExpiresAt time.Time `json:"expires_at"`
}

type sessionRecord struct {
	Identity  Identity  `json:"identity"`
	ExpiresAt time.Time `json:"expires_at"`
}

func (p *Provider) setStateCookie(w http.ResponseWriter, state stateRecord) {
	value, _ := p.encodeSigned(state)
	p.setCookie(w, p.config.StateCookieName, value, int(stateLifetime.Seconds()))
}

func (p *Provider) readState(r *http.Request) (stateRecord, error) {
	cookie, err := r.Cookie(p.config.StateCookieName)
	if err != nil {
		return stateRecord{}, err
	}
	var state stateRecord
	return state, p.decodeSigned(cookie.Value, &state)
}

func (p *Provider) clearStateCookie(w http.ResponseWriter) {
	p.setCookie(w, p.config.StateCookieName, "", -1)
}

func (p *Provider) setSessionCookie(w http.ResponseWriter, identity Identity) error {
	value, err := p.encodeSigned(sessionRecord{Identity: identity, ExpiresAt: time.Now().Add(p.config.SessionDuration)})
	if err != nil {
		return err
	}
	p.setCookie(w, p.config.CookieName, value, int(p.config.SessionDuration.Seconds()))
	return nil
}

func (p *Provider) clearSessionCookie(w http.ResponseWriter) {
	p.setCookie(w, p.config.CookieName, "", -1)
}

func (p *Provider) setCookie(w http.ResponseWriter, name, value string, maxAge int) {
	http.SetCookie(w, &http.Cookie{Name: name, Value: value, Path: "/", Domain: p.config.CookieDomain, MaxAge: maxAge, HttpOnly: true, Secure: !p.config.InsecureCookies, SameSite: http.SameSiteLaxMode})
}

func (p *Provider) encodeSigned(value any) (string, error) {
	payload, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	encoded := base64.RawURLEncoding.EncodeToString(payload)
	mac := hmac.New(sha256.New, p.config.SessionSecret)
	_, _ = mac.Write([]byte(encoded))
	return encoded + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}

func (p *Provider) decodeSigned(value string, destination any) error {
	parts := strings.Split(value, ".")
	if len(parts) != 2 {
		return errors.New("invalid signed value")
	}
	provided, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return errors.New("decode signature")
	}
	mac := hmac.New(sha256.New, p.config.SessionSecret)
	_, _ = mac.Write([]byte(parts[0]))
	if !hmac.Equal(provided, mac.Sum(nil)) {
		return errors.New("invalid signature")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return errors.New("decode payload")
	}
	return json.Unmarshal(payload, destination)
}

func randomValue(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}

func secureEqual(left, right string) bool { return hmac.Equal([]byte(left), []byte(right)) }

func hasAnyGroup(actual, required []string) bool {
	for _, candidate := range actual {
		for _, wanted := range required {
			if candidate == wanted {
				return true
			}
		}
	}
	return false
}

func validateConfig(config Config) error {
	if strings.TrimSpace(config.Issuer) == "" || strings.TrimSpace(config.ClientID) == "" || strings.TrimSpace(config.ClientSecret) == "" || strings.TrimSpace(config.RedirectURL) == "" {
		return errors.New("issuer, client ID, client secret, and redirect URL are required")
	}
	if len(config.SessionSecret) < 32 {
		return errors.New("session secret must contain at least 32 random bytes")
	}
	if config.SessionDuration > maxSessionTTL {
		return fmt.Errorf("session duration must not exceed %s", maxSessionTTL)
	}

	redirectURL, err := url.Parse(config.RedirectURL)
	if err != nil || redirectURL.Host == "" {
		return errors.New("redirect URL must be an absolute URL")
	}
	if config.InsecureCookies {
		if redirectURL.Scheme != "http" || !isLoopbackHost(redirectURL.Hostname()) {
			return errors.New("insecure cookies require an HTTP localhost redirect URL")
		}
	} else if redirectURL.Scheme != "https" {
		return errors.New("redirect URL must use HTTPS when insecure cookies are disabled")
	}
	if strings.HasPrefix(config.CookieName, "__Host-") && (config.InsecureCookies || config.CookieDomain != "") {
		return errors.New("__Host- cookies require secure cookies and no cookie domain")
	}
	for _, name := range []string{config.CookieName, config.StateCookieName} {
		if err := (&http.Cookie{Name: name, Value: "x", Path: "/"}).Valid(); err != nil {
			return fmt.Errorf("invalid cookie name %q: %w", name, err)
		}
	}
	return nil
}

func isLoopbackHost(host string) bool {
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}
