package gk

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// FR-S19 (ADR-0124): EdDSA ID tokens verify; access tokens stay ES256; the
// key named by kid must be of the alg's type.
func TestEdDSAIDTokens(t *testing.T) {
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	edPub, edKey, _ := ed25519.GenerateKey(rand.Reader)
	set := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
		{Key: &ecKey.PublicKey, KeyID: "ec", Algorithm: "ES256", Use: "sig"},
		{Key: edPub, KeyID: "ed", Algorithm: "EdDSA", Use: "sig"},
	}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _ = json.NewEncoder(w).Encode(set) }))
	defer srv.Close()
	sign := func(alg jose.SignatureAlgorithm, key any, kid, typ string, claims map[string]any) string {
		opts := (&jose.SignerOptions{}).WithHeader("kid", kid).WithType(jose.ContentType(typ))
		sg, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: key}, opts)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := json.Marshal(claims)
		obj, _ := sg.Sign(b)
		out, _ := obj.CompactSerialize()
		return out
	}
	now := time.Now().Unix()
	id := map[string]any{"iss": srv.URL, "aud": "web", "sub": "u1", "exp": now + 300, "iat": now, "nonce": "n"}
	sdk := New(Config{Issuer: srv.URL, Audience: "api", ClientID: "web", HTTPClient: srv.Client()})
	ctx := context.Background()

	if c, err := sdk.VerifyIDToken(ctx, sign(jose.EdDSA, edKey, "ed", "JWT", id), "n"); err != nil || c["sub"] != "u1" {
		t.Fatalf("EdDSA ID token: %v %v", c, err)
	}
	if _, err := sdk.VerifyIDToken(ctx, sign(jose.ES256, ecKey, "ec", "JWT", id), "n"); err != nil {
		t.Fatalf("ES256 ID token: %v", err)
	}
	// The Ed25519 key signing, but the header naming the P-256 key's kid: refused.
	if _, err := sdk.VerifyIDToken(ctx, sign(jose.EdDSA, edKey, "ec", "JWT", id), "n"); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("EdDSA under an EC kid: %v", err)
	}
	if _, err := sdk.VerifyIDToken(ctx, sign(jose.ES256, ecKey, "ed", "JWT", id), "n"); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("ES256 under an Ed25519 kid: %v", err)
	}
	at := map[string]any{"iss": srv.URL, "aud": "api", "sub": "u1", "exp": now + 300, "iat": now, "client_id": "web", "jti": "j"}
	if _, err := sdk.Verify(ctx, sign(jose.EdDSA, edKey, "ed", "at+jwt", at)); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("an EdDSA access token must be refused: %v", err)
	}
}
