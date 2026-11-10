package gk

import (
	"crypto"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

// ErrInvalidDPoP wraps every DPoP proof failure (RFC 9449, ADR-0070).
var ErrInvalidDPoP = errors.New("gk: invalid DPoP proof")

const (
	dpopSkew    = 60 * time.Second
	jtiCapacity = 100_000
)

// jtiCache remembers proof ids until they could no longer be accepted.
// shortcut: per process; several API replicas each keep their own, so a
// proof could replay once per replica within 2 minutes. Use a shared store if that matters.
type jtiCache struct {
	mu   sync.Mutex
	seen map[string]time.Time
}

func (c *jtiCache) fresh(id string, now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.seen == nil {
		c.seen = map[string]time.Time{}
	}
	if len(c.seen) >= jtiCapacity {
		for k, until := range c.seen {
			if now.After(until) {
				delete(c.seen, k)
			}
		}
		if len(c.seen) >= jtiCapacity {
			return false // full of live ids: refuse rather than forget (fail closed)
		}
	}
	if until, ok := c.seen[id]; ok && now.Before(until) {
		return false
	}
	c.seen[id] = now.Add(2 * dpopSkew)
	return true
}

func htu(raw string) (string, bool) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "", false
	}
	u.RawQuery, u.Fragment, u.RawFragment = "", "", ""
	return u.String(), true
}

// VerifyDPoP checks a request's proof for a DPoP-bound principal: signed by
// the bound key (cnf.jkt), for this method and URL (query ignored), with
// ath of accessToken, iat within 60 s, and a jti not seen before.
func (s *SDK) VerifyDPoP(p *Principal, accessToken, proof, method, requestURL string) error {
	if p == nil || p.JKT == "" {
		return fmt.Errorf("%w: the token is not DPoP-bound", ErrInvalidDPoP)
	}
	jws, err := jose.ParseSigned(proof, []jose.SignatureAlgorithm{jose.ES256, jose.RS256, jose.EdDSA})
	if err != nil || len(jws.Signatures) != 1 {
		return fmt.Errorf("%w: parse", ErrInvalidDPoP)
	}
	h := jws.Signatures[0].Protected
	jwk := h.JSONWebKey
	if typ, _ := h.ExtraHeaders[jose.HeaderType].(string); typ != "dpop+jwt" || jwk == nil || !jwk.IsPublic() || !jwk.Valid() {
		return fmt.Errorf("%w: header", ErrInvalidDPoP)
	}
	payload, err := jws.Verify(jwk)
	if err != nil {
		return fmt.Errorf("%w: signature", ErrInvalidDPoP)
	}
	var c struct {
		HTM string  `json:"htm"`
		HTU string  `json:"htu"`
		IAT float64 `json:"iat"`
		JTI string  `json:"jti"`
		ATH string  `json:"ath"`
	}
	if json.Unmarshal(payload, &c) != nil || c.JTI == "" {
		return fmt.Errorf("%w: claims", ErrInvalidDPoP)
	}
	want, ok1 := htu(requestURL)
	got, ok2 := htu(c.HTU)
	if !ok1 || !ok2 || got != want || c.HTM != method {
		return fmt.Errorf("%w: htm or htu", ErrInvalidDPoP)
	}
	now := s.now()
	if iat := time.Unix(int64(c.IAT), 0); iat.Before(now.Add(-dpopSkew)) || iat.After(now.Add(dpopSkew)) {
		return fmt.Errorf("%w: iat", ErrInvalidDPoP)
	}
	sum := sha256.Sum256([]byte(accessToken))
	if subtle.ConstantTimeCompare([]byte(c.ATH), []byte(base64.RawURLEncoding.EncodeToString(sum[:]))) != 1 {
		return fmt.Errorf("%w: ath", ErrInvalidDPoP)
	}
	tp, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil || subtle.ConstantTimeCompare([]byte(base64.RawURLEncoding.EncodeToString(tp)), []byte(p.JKT)) != 1 {
		return fmt.Errorf("%w: another key", ErrInvalidDPoP)
	}
	if !s.jtis.fresh(p.JKT+":"+c.JTI, now) {
		return fmt.Errorf("%w: replayed", ErrInvalidDPoP)
	}
	return nil
}

// requestURL is the URL a client signed: Config.PublicURL plus the path
// when set (behind a proxy), else this request's own scheme, host and path.
func (s *SDK) requestURL(r *http.Request) string {
	if s.cfg.PublicURL != "" {
		return s.cfg.PublicURL + r.URL.Path
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + r.Host + r.URL.Path
}
