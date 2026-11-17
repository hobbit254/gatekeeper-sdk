package gk

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

// ID tokens and userinfo, plain or encrypted to the client (FR-S15, ADR-0121).

// unwrap returns the signed JWT inside raw: raw itself when it is a JWS, else
// raw decrypted with Config.DecryptionKey.
func (s *SDK) unwrap(raw string) (string, error) {
	if strings.Count(raw, ".") != 4 {
		return raw, nil
	}
	if s.cfg.DecryptionKey == nil {
		return "", fmt.Errorf("%w: encrypted, and no DecryptionKey is configured", ErrInvalidToken)
	}
	jwe, err := jose.ParseEncrypted(raw, []jose.KeyAlgorithm{jose.ECDH_ES_A256KW, jose.RSA_OAEP_256}, []jose.ContentEncryption{jose.A256GCM})
	if err != nil {
		return "", fmt.Errorf("%w: parse JWE", ErrInvalidToken)
	}
	inner, err := jwe.Decrypt(s.cfg.DecryptionKey)
	if err != nil {
		return "", fmt.Errorf("%w: decrypt", ErrInvalidToken)
	}
	return string(inner), nil
}

// signedClaims verifies a signed ID token or userinfo JWT from the issuer and
// returns its claims. ES256 or EdDSA (a client can opt in, ADR-0124); the key
// named by kid must be of the alg's type. Access tokens never come here.
func (s *SDK) signedClaims(ctx context.Context, raw string) (map[string]any, error) {
	jws, err := jose.ParseSigned(raw, []jose.SignatureAlgorithm{jose.ES256, jose.EdDSA})
	if err != nil || len(jws.Signatures) != 1 {
		return nil, fmt.Errorf("%w: parse", ErrInvalidToken)
	}
	h := jws.Signatures[0].Protected
	key, err := s.key(ctx, h.KeyID)
	if err != nil {
		return nil, err
	}
	if !keyFits(h.Algorithm, key) {
		return nil, fmt.Errorf("%w: alg %s does not match key %s", ErrInvalidToken, h.Algorithm, h.KeyID)
	}
	payload, err := jws.Verify(key)
	if err != nil {
		return nil, fmt.Errorf("%w: signature", ErrInvalidToken)
	}
	var c map[string]any
	if err := json.Unmarshal(payload, &c); err != nil {
		return nil, fmt.Errorf("%w: claims", ErrInvalidToken)
	}
	if c["iss"] != s.cfg.Issuer {
		return nil, fmt.Errorf("%w: iss", ErrInvalidToken)
	}
	return c, nil
}

func audHas(aud any, want string) bool {
	switch a := aud.(type) {
	case string:
		return a == want
	case []any:
		return slices.Contains(a, any(want))
	}
	return false
}

// VerifyIDToken checks an ID token for Config.ClientID (decrypting it first
// when encrypted): signature, iss, aud, exp and nonce. It returns the claims.
func (s *SDK) VerifyIDToken(ctx context.Context, raw, nonce string) (map[string]any, error) {
	inner, err := s.unwrap(raw)
	if err != nil {
		return nil, err
	}
	c, err := s.signedClaims(ctx, inner)
	if err != nil {
		return nil, err
	}
	exp, _ := c["exp"].(float64)
	switch {
	case !audHas(c["aud"], s.cfg.ClientID):
		return nil, fmt.Errorf("%w: aud", ErrInvalidToken)
	case s.now().After(time.Unix(int64(exp), 0).Add(s.cfg.Leeway)):
		return nil, fmt.Errorf("%w: expired", ErrInvalidToken)
	case nonce != "" && c["nonce"] != nonce:
		return nil, fmt.Errorf("%w: nonce", ErrInvalidToken)
	}
	return c, nil
}

// UserInfo fetches the user's claims with accessToken. An encrypted answer is
// decrypted and its signature, iss and aud checked.
func (s *SDK) UserInfo(ctx context.Context, accessToken string) (map[string]any, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.cfg.Issuer+"/oauth2/userinfo", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err := s.cfg.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: userinfo status %d", ErrInvalidToken, resp.StatusCode)
	}
	if !strings.HasPrefix(resp.Header.Get("Content-Type"), "application/jwt") {
		var c map[string]any
		return c, json.Unmarshal(body, &c)
	}
	inner, err := s.unwrap(strings.TrimSpace(string(body)))
	if err != nil {
		return nil, err
	}
	c, err := s.signedClaims(ctx, inner)
	if err != nil {
		return nil, err
	}
	if !audHas(c["aud"], s.cfg.ClientID) {
		return nil, fmt.Errorf("%w: aud", ErrInvalidToken)
	}
	return c, nil
}

// keyFits reports whether key is the kind alg signs with.
func keyFits(alg string, key any) bool {
	switch key.(type) {
	case *ecdsa.PublicKey:
		return alg == string(jose.ES256)
	case ed25519.PublicKey:
		return alg == string(jose.EdDSA)
	}
	return false
}
