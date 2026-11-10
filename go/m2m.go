package gk

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	apiKeyPrefix = "gk_live_"
	keyTTL       = 60 * time.Second // a revoked key works this long at most (ADR-0059)
	deadKeyTTL   = 10 * time.Second
)

type keyEntry struct {
	p     *Principal // nil: inactive
	until time.Time
}

// verifyKey introspects an API key with the API's own client credentials
// and caches the answer; any failure refuses (ADR-0057, ADR-0059).
func (s *SDK) verifyKey(ctx context.Context, raw string) (*Principal, error) {
	sum := sha256.Sum256([]byte(raw))
	now := s.now()
	s.keyMu.Lock()
	e, ok := s.keyCache[sum]
	s.keyMu.Unlock()
	if !ok || !now.Before(e.until) {
		p, err := s.introspect(ctx, raw)
		if err != nil {
			return nil, err
		}
		e = keyEntry{p: p, until: now.Add(keyTTL)}
		if p == nil {
			e.until = now.Add(deadKeyTTL)
		}
		s.keyMu.Lock()
		if s.keyCache == nil {
			s.keyCache = map[[32]byte]keyEntry{}
		}
		s.keyCache[sum] = e
		s.keyMu.Unlock()
	}
	if e.p == nil {
		return nil, fmt.Errorf("%w: inactive API key", ErrInvalidToken)
	}
	cp := *e.p
	return &cp, nil
}

func (s *SDK) introspect(ctx context.Context, raw string) (*Principal, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.cfg.Issuer+"/oauth2/introspect",
		strings.NewReader(url.Values{"token": {raw}}.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(s.cfg.ClientID, s.cfg.ClientSecret)
	resp, err := s.cfg.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: introspect: %v", ErrInvalidToken, err)
	}
	defer func() { _ = resp.Body.Close() }()
	var r struct {
		Active      bool     `json:"active"`
		TokenType   string   `json:"token_type"`
		Sub         string   `json:"sub"`
		OwnerType   string   `json:"owner_type"`
		Scope       string   `json:"scope"`
		Tid         string   `json:"tid"`
		Permissions []string `json:"permissions"`
	}
	if resp.StatusCode != http.StatusOK || json.NewDecoder(resp.Body).Decode(&r) != nil {
		return nil, fmt.Errorf("%w: introspect status %d", ErrInvalidToken, resp.StatusCode)
	}
	if !r.Active || r.TokenType != "api_key" {
		return nil, nil
	}
	return &Principal{Sub: r.Sub, TenantID: r.Tid, Permissions: r.Permissions, Scopes: strings.Fields(r.Scope),
		APIKey: true, OwnerType: r.OwnerType}, nil
}

// ClientCredentials fetches and caches an m2m access token (FR-M1,
// ADR-0059). It is safe for concurrent use; callers share one request.
type ClientCredentials struct {
	TokenURL, ClientID, ClientSecret string
	Scope, Audience                  string
	HTTPClient                       *http.Client

	mu    sync.Mutex
	tok   string
	until time.Time
}

// Token returns a token valid for at least another minute.
func (c *ClientCredentials) Token(ctx context.Context) (string, error) {
	c.mu.Lock() // held across the fetch: concurrent callers wait for one request
	defer c.mu.Unlock()
	if c.tok != "" && time.Now().Before(c.until) {
		return c.tok, nil
	}
	form := url.Values{"grant_type": {"client_credentials"}}
	if c.Scope != "" {
		form.Set("scope", c.Scope)
	}
	if c.Audience != "" {
		form.Set("audience", c.Audience)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(url.QueryEscape(c.ClientID), url.QueryEscape(c.ClientSecret))
	hc := c.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: 5 * time.Second}
	}
	resp, err := hc.Do(req)
	if err != nil {
		return "", fmt.Errorf("gk: client credentials: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	var r struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	if resp.StatusCode != http.StatusOK || json.NewDecoder(resp.Body).Decode(&r) != nil || r.AccessToken == "" {
		return "", fmt.Errorf("gk: client credentials: status %d", resp.StatusCode)
	}
	c.tok, c.until = r.AccessToken, time.Now().Add(time.Duration(r.ExpiresIn)*time.Second-time.Minute)
	return c.tok, nil
}
