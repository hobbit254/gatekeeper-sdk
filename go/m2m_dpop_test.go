package gk

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	jose "github.com/go-jose/go-jose/v4"
)

// proofClaims verifies a proof's signature with its embedded key and returns its claims and the key's thumbprint.
func proofClaims(t *testing.T, proof string) (map[string]any, string) {
	t.Helper()
	jws, err := jose.ParseSigned(proof, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		t.Fatal(err)
	}
	jwk := jws.Signatures[0].Protected.JSONWebKey
	payload, err := jws.Verify(jwk)
	if err != nil {
		t.Fatal(err)
	}
	var c map[string]any
	_ = json.Unmarshal(payload, &c)
	tp, _ := jwk.Thumbprint(crypto.SHA256)
	return c, base64.RawURLEncoding.EncodeToString(tp)
}

// FR-S12: the helper binds its token to the key, retries once for the server's nonce, and signs API calls.
func TestClientCredentialsWithDPoPKey(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("DPoP-Nonce", "n-1")
		c, _ := proofClaims(t, r.Header.Get("DPoP"))
		if c["htm"] != "POST" || c["htu"] != "http://"+r.Host+"/oauth2/token" {
			t.Errorf("proof %v", c)
		}
		if c["nonce"] != "n-1" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"use_dpop_nonce"}`))
			return
		}
		_, _ = w.Write([]byte(`{"access_token":"tok-1","token_type":"DPoP","expires_in":600}`))
	}))
	defer srv.Close()
	cc := &ClientCredentials{TokenURL: srv.URL + "/oauth2/token", ClientID: "batch", ClientSecret: "s", DPoPKey: key}
	tok, err := cc.Token(context.Background())
	if err != nil || tok != "tok-1" || calls != 2 {
		t.Fatalf("token %q %v after %d calls", tok, err, calls)
	}

	proof, err := cc.Proof("GET", "https://api.example.test/v1/things?page=2", tok)
	if err != nil {
		t.Fatal(err)
	}
	c, jkt := proofClaims(t, proof)
	if c["nonce"] != "n-1" {
		t.Fatalf("API proofs carry the latest nonce: %v", c)
	}
	sdk := New(Config{Issuer: "https://issuer.test"})
	if err := sdk.VerifyDPoP(&Principal{JKT: jkt}, tok, proof, "GET", "https://api.example.test/v1/things"); err != nil {
		t.Fatal(err)
	}
}

func TestClientCredentialsGivesUpAfterOneNonceRetry(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		w.Header().Set("DPoP-Nonce", strings.Repeat("x", calls)) // a new nonce every time
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"use_dpop_nonce"}`))
	}))
	defer srv.Close()
	cc := &ClientCredentials{TokenURL: srv.URL, ClientID: "batch", ClientSecret: "s", DPoPKey: key}
	if _, err := cc.Token(context.Background()); err == nil || calls != 2 {
		t.Fatalf("err %v after %d calls", err, calls)
	}
	if _, err := (&ClientCredentials{}).Proof("GET", "https://x.test/", "t"); err == nil {
		t.Fatal("Proof without a key must fail")
	}
}
