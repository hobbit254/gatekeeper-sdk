package gk

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Checks on behalf of a user (FR-Z16, ADR-0119): the product's own client
// credentials (scope authz:check) plus the user's id, for users whose tokens
// are DPoP-bound and can't be forwarded. Gatekeeper answers only for users
// with a live sign-in through this client.

// ErrNotServed is Gatekeeper refusing to check a user who has no live sign-in through this client.
var ErrNotServed = errors.New("gk: the user has no live sign-in through this client")

// ErrNoClientCredentials is an on-behalf check without Config.ClientID and ClientSecret.
var ErrNoClientCredentials = errors.New("gk: on-behalf checks need the client's id and secret")

type ccToken struct {
	mu      sync.Mutex
	token   string
	expires time.Time
}

// clientToken is the client's authz:check token, cached until a minute before it expires.
func (s *SDK) clientToken(ctx context.Context) (string, error) {
	if s.cfg.ClientID == "" || s.cfg.ClientSecret == "" {
		return "", ErrNoClientCredentials
	}
	c := &s.cc
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token != "" && s.now().Before(c.expires) {
		return c.token, nil
	}
	form := url.Values{"grant_type": {"client_credentials"}, "scope": {"authz:check"}}
	if s.cfg.Audience != "" {
		form.Set("audience", s.cfg.Audience)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.cfg.Issuer+"/oauth2/token", strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(url.QueryEscape(s.cfg.ClientID), url.QueryEscape(s.cfg.ClientSecret)) // RFC 6749 §2.3.1
	resp, err := s.cfg.HTTPClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrCheckUnavailable, err)
	}
	defer func() { _ = resp.Body.Close() }()
	var tok struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if resp.StatusCode != http.StatusOK || json.NewDecoder(resp.Body).Decode(&tok) != nil || tok.AccessToken == "" {
		return "", fmt.Errorf("%w: client credentials refused (status %d)", ErrCheckUnavailable, resp.StatusCode)
	}
	c.token, c.expires = tok.AccessToken, s.now().Add(time.Duration(tok.ExpiresIn)*time.Second-time.Minute)
	return c.token, nil
}

// CanOnFor decides permission on resource for userID with the product's client credentials.
func (s *SDK) CanOnFor(ctx context.Context, userID, permission, resource string) (ResourceDecision, error) {
	tok, err := s.clientToken(ctx)
	if err != nil {
		return ResourceDecision{}, err
	}
	var d ResourceDecision
	err = s.authz(ctx, tok, "/v1/authz/check", map[string]string{"user_id": userID, "permission": permission, "resource": resource}, &d)
	return d, err
}

// CanOnEachFor decides permission on each resource for userID, in order, 200 to a request.
func (s *SDK) CanOnEachFor(ctx context.Context, userID, permission string, resources []string) ([]ResourceDecision, error) {
	tok, err := s.clientToken(ctx)
	if err != nil {
		return nil, err
	}
	return s.canOnEach(ctx, tok, userID, permission, resources)
}
