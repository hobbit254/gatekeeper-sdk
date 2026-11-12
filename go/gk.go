// Package gk is the Gatekeeper Go SDK: verify access tokens offline, hydrate
// a Principal, resolve permissions from the client's role map and guard
// routes (docs/INTEGRATION.md, docs/TOKENS.md, ADR-0005).
package gk

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

// Config configures one API. Issuer is https://auth.<domain>/t/<tenant>;
// Audience is this API's identifier (enforced on every token); ClientID and
// ClientSecret identify the client whose role map resolves permissions.
type Config struct {
	Issuer       string
	Audience     string
	ClientID     string
	ClientSecret string
	HTTPClient   *http.Client
	// Leeway is the clock skew allowed on exp (default and maximum 60 s).
	Leeway time.Duration
	// PublicURL is this API's external origin (https://api.example.com) for
	// checking DPoP proofs behind a proxy; empty uses the request's own.
	PublicURL string
}

// Principal is the authenticated subject of a request.
type Principal struct {
	Sub         string
	TenantID    string
	OrgID       string
	ClientID    string
	Roles       []string
	Permissions []string
	Scopes      []string
	AMR         []string
	AuthTime    time.Time
	RV          int64
	SID         string // browser session (ADR-0044)
	JTI         string
	// Actor is the admin acting as Sub, and ImpersonationEndsAt when that
	// ends; empty unless the token is an impersonation (ADR-0058). Show a banner.
	Actor               string
	ImpersonationEndsAt time.Time
	// APIKey marks a principal from a gk_live_ key (ADR-0057); OwnerType is
	// "user" or "service_account".
	APIKey    bool
	OwnerType string
	// JKT is the DPoP key the token is bound to (cnf.jkt), or "" (ADR-0070).
	JKT string
	// StepUp is how recent a second factor each held permission needs, from
	// the role map; RequirePermission enforces it (ADR-0097).
	StepUp map[string]time.Duration
	// Entitlements are the customer's plan and features from the token, or
	// nil when the tenant set none (ADR-0098).
	Entitlements *Entitlements
}

// Entitlements are a customer's plan and paid-for features (ADR-0098).
type Entitlements struct {
	Plan     string   `json:"plan"`
	Features []string `json:"features"`
}

// HasFeature reports whether the token's entitlements include feature.
func (p *Principal) HasFeature(feature string) bool {
	return p.Entitlements != nil && slices.Contains(p.Entitlements.Features, feature)
}

// machine principals (API keys, client-credentials tokens) are never asked to step up (ADR-0056).
func (p *Principal) machine() bool { return p.APIKey || len(p.AMR) == 0 }

// Can reports whether the principal holds permission (exact key; wildcards
// are already expanded in the role map).
func (p *Principal) Can(permission string) bool { return slices.Contains(p.Permissions, permission) }

// ErrInvalidToken wraps every verification failure.
var ErrInvalidToken = errors.New("gk: invalid token")

// SDK verifies tokens for one API. It is safe for concurrent use.
type SDK struct {
	cfg  Config
	deny Denylist
	now  func() time.Time
	jtis jtiCache

	keyMu    sync.Mutex
	keyCache map[[32]byte]keyEntry

	mu         sync.Mutex
	keys       jose.JSONWebKeySet
	lastFetch  time.Time
	roleMap    map[string][]string
	roleStepUp map[string]int // permission → seconds (ADR-0097)
	roleMapRV  int64
	roleMapSet bool
}

// New returns an SDK for cfg.
func New(cfg Config) *SDK {
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 5 * time.Second}
	}
	if cfg.Leeway <= 0 || cfg.Leeway > time.Minute {
		cfg.Leeway = time.Minute
	}
	cfg.Issuer = strings.TrimSuffix(cfg.Issuer, "/")
	cfg.PublicURL = strings.TrimSuffix(cfg.PublicURL, "/")
	return &SDK{cfg: cfg, now: time.Now}
}

const jwksCooldown = 30 * time.Second

// Verify runs the TOKENS.md checklist and returns the Principal.
func (s *SDK) Verify(ctx context.Context, raw string) (*Principal, error) {
	if strings.HasPrefix(raw, apiKeyPrefix) {
		return s.verifyKey(ctx, raw)
	}
	jws, err := jose.ParseSigned(raw, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil || len(jws.Signatures) != 1 {
		return nil, fmt.Errorf("%w: parse", ErrInvalidToken)
	}
	h := jws.Signatures[0].Protected
	if typ, _ := h.ExtraHeaders[jose.HeaderType].(string); !strings.EqualFold(typ, "at+jwt") {
		return nil, fmt.Errorf("%w: typ", ErrInvalidToken)
	}
	key, err := s.key(ctx, h.KeyID)
	if err != nil {
		return nil, err
	}
	payload, err := jws.Verify(key)
	if err != nil {
		return nil, fmt.Errorf("%w: signature", ErrInvalidToken)
	}
	var c struct {
		Iss      string   `json:"iss"`
		Sub      string   `json:"sub"`
		Aud      audience `json:"aud"`
		Exp      int64    `json:"exp"`
		ClientID string   `json:"client_id"`
		Tid      string   `json:"tid"`
		Org      string   `json:"org"`
		Roles    []string `json:"roles"`
		RV       int64    `json:"rv"`
		Scope    string   `json:"scope"`
		AMR      []string `json:"amr"`
		AuthTime int64    `json:"auth_time"`
		SID      string   `json:"sid"`
		JTI      string   `json:"jti"`
		Act      *struct {
			Sub    string `json:"sub"`
			EndsAt int64  `json:"ends_at"`
		} `json:"act"`
		Cnf *struct {
			JKT string `json:"jkt"`
		} `json:"cnf"`
		Entitlements *Entitlements `json:"entitlements"`
	}
	if err := json.Unmarshal(payload, &c); err != nil {
		return nil, fmt.Errorf("%w: claims", ErrInvalidToken)
	}
	switch {
	case time.Now().After(time.Unix(c.Exp, 0).Add(s.cfg.Leeway)):
		return nil, fmt.Errorf("%w: expired", ErrInvalidToken)
	case c.Iss != s.cfg.Issuer:
		return nil, fmt.Errorf("%w: iss", ErrInvalidToken)
	case !slices.Contains(c.Aud, s.cfg.Audience):
		return nil, fmt.Errorf("%w: aud", ErrInvalidToken)
	}
	if s.deny != nil {
		denied, err := s.deny.Denied(ctx, c.SID, c.JTI)
		if err != nil || denied { // an unreachable denylist refuses: fail closed (ADR-0048)
			return nil, fmt.Errorf("%w: denied", errors.Join(ErrInvalidToken, err))
		}
	}
	perms, stepUp, err := s.permissions(ctx, c.Roles, c.RV)
	if err != nil {
		return nil, err
	}
	p := &Principal{Sub: c.Sub, TenantID: c.Tid, OrgID: c.Org, ClientID: c.ClientID, Roles: c.Roles,
		Permissions: perms, Scopes: strings.Fields(c.Scope), AMR: c.AMR, AuthTime: time.Unix(c.AuthTime, 0), RV: c.RV,
		SID: c.SID, JTI: c.JTI, StepUp: stepUp, Entitlements: c.Entitlements}
	if c.Act != nil {
		p.Actor, p.ImpersonationEndsAt = c.Act.Sub, time.Unix(c.Act.EndsAt, 0)
	}
	if c.Cnf != nil {
		p.JKT = c.Cnf.JKT
	}
	return p, nil
}

// key returns the public key for kid, refetching the JWKS once on an unknown
// kid, at most every 30 s.
func (s *SDK) key(ctx context.Context, kid string) (any, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if k := s.keys.Key(kid); len(k) == 1 {
		return k[0].Key, nil
	}
	if time.Since(s.lastFetch) < jwksCooldown {
		return nil, fmt.Errorf("%w: unknown kid", ErrInvalidToken)
	}
	s.lastFetch = time.Now()
	var set jose.JSONWebKeySet
	if err := s.getJSON(ctx, s.cfg.Issuer+"/.well-known/jwks.json", false, &set); err != nil {
		return nil, err
	}
	s.keys = set
	if k := s.keys.Key(kid); len(k) == 1 {
		return k[0].Key, nil
	}
	return nil, fmt.Errorf("%w: unknown kid", ErrInvalidToken)
}

// permissions resolves roles through the cached role map, refetching when the
// token's rv is newer than the cached one.
func (s *SDK) permissions(ctx context.Context, roles []string, rv int64) ([]string, map[string]time.Duration, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.roleMapSet || rv > s.roleMapRV {
		var rm struct {
			RV     int64               `json:"rv"`
			Roles  map[string][]string `json:"roles"`
			StepUp map[string]int      `json:"step_up"`
		}
		if err := s.getJSON(ctx, s.cfg.Issuer+"/v1/clients/"+s.cfg.ClientID+"/role-map", true, &rm); err != nil {
			return nil, nil, err
		}
		s.roleMap, s.roleStepUp, s.roleMapRV, s.roleMapSet = rm.Roles, rm.StepUp, rm.RV, true
	}
	seen := map[string]bool{}
	var out []string
	var stepUp map[string]time.Duration
	for _, r := range roles {
		for _, p := range s.roleMap[r] {
			if seen[p] {
				continue
			}
			seen[p] = true
			out = append(out, p)
			if w := s.roleStepUp[p]; w > 0 {
				if stepUp == nil {
					stepUp = map[string]time.Duration{}
				}
				stepUp[p] = time.Duration(w) * time.Second
			}
		}
	}
	return out, stepUp, nil
}

func (s *SDK) getJSON(ctx context.Context, url string, auth bool, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	if auth && s.cfg.ClientSecret != "" {
		req.SetBasicAuth(s.cfg.ClientID, s.cfg.ClientSecret)
	}
	resp, err := s.cfg.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("gk: fetch %s: %w", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("gk: fetch %s: status %d", url, resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(v)
}

// audience accepts aud as a string or an array (RFC 7519).
type audience []string

func (a *audience) UnmarshalJSON(b []byte) error {
	var one string
	if json.Unmarshal(b, &one) == nil {
		*a = []string{one}
		return nil
	}
	var many []string
	err := json.Unmarshal(b, &many)
	*a = many
	return err
}

type ctxKey struct{}

// FromContext returns the Principal Middleware stored.
func FromContext(ctx context.Context) (*Principal, bool) {
	p, ok := ctx.Value(ctxKey{}).(*Principal)
	return p, ok
}

// Middleware verifies the access token on every request. Failures are 401
// with WWW-Authenticate: Bearer error="invalid_token" (TOKENS.md). A
// DPoP-bound token is accepted only as "DPoP <token>" with a valid proof in
// the DPoP header (ADR-0070).
func (s *SDK) Middleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			raw, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
			dpop := false
			if !ok {
				raw, dpop = strings.CutPrefix(r.Header.Get("Authorization"), "DPoP ")
				ok = dpop
			}
			if !ok || raw == "" {
				w.Header().Set("WWW-Authenticate", `Bearer`)
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			p, err := s.Verify(r.Context(), raw)
			switch {
			case err != nil:
			case p.JKT != "" && !dpop, p.JKT == "" && dpop:
				err = fmt.Errorf("%w: wrong scheme", ErrInvalidDPoP)
			case p.JKT != "":
				err = s.VerifyDPoP(p, raw, r.Header.Get("DPoP"), r.Method, s.requestURL(r))
			}
			if err != nil && (dpop || (p != nil && p.JKT != "")) {
				w.Header().Set("WWW-Authenticate", `DPoP error="invalid_token", algs="ES256 RS256 EdDSA"`)
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			if err != nil {
				w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, p)))
		})
	}
}

// RequirePermission answers 403 unless the Principal holds permission, and
// 401 with the RFC 9470 challenge when the permission's step-up window from
// the role map has passed (ADR-0097). Direct grants need /v1/authz/check (ADR-0005).
func RequirePermission(permission string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p, ok := FromContext(r.Context())
			if !ok || !p.Can(permission) {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			if window := p.StepUp[permission]; window > 0 && !p.machine() && !p.FreshMFA(window) {
				w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer error="insufficient_user_authentication", max_age="%d", acr_values="mfa"`,
					int(window.Seconds())))
				http.Error(w, "step-up required", http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// FreshMFA reports whether the principal signed in with a second factor
// ("mfa" in amr) no longer ago than maxAge (ADR-0046).
func (p *Principal) FreshMFA(maxAge time.Duration) bool {
	return slices.Contains(p.AMR, "mfa") && time.Since(p.AuthTime) <= maxAge
}

// RequireStepUp answers 401 with the RFC 9470 challenge unless the principal
// has a second factor within maxAge. The client re-runs authorize with
// max_age and acr_values=mfa, then retries.
func RequireStepUp(maxAge time.Duration) func(http.Handler) http.Handler {
	secs := int(maxAge.Seconds())
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p, ok := FromContext(r.Context())
			if !ok || !p.FreshMFA(maxAge) {
				w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer error="insufficient_user_authentication", max_age="%d"`, secs))
				http.Error(w, "step-up required", http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
