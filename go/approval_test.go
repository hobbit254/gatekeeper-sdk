package gk

import (
	"context"
	"crypto/ecdsa"
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

// FR-Z21 (ADR-0145): an approval verifies only for its requester and client,
// signed by a published key with typ approval+jwt; spending maps 409 and 422.
func TestApprovals(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	set := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "k1", Algorithm: "ES256", Use: "sig"}}}
	var spendStatus int
	var spent map[string]any
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/jwks.json", func(w http.ResponseWriter, _ *http.Request) { _ = json.NewEncoder(w).Encode(set) })
	mux.HandleFunc("/v1/approvals/spend", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer at" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_ = json.NewDecoder(r.Body).Decode(&spent)
		w.WriteHeader(spendStatus)
		_ = json.NewEncoder(w).Encode(map[string]any{"approval_id": "a1", "status": "spent", "approver_id": "boss", "amount": 300000})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	sign := func(k *ecdsa.PrivateKey, typ string, claims map[string]any) string {
		sg, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: k}, (&jose.SignerOptions{}).WithHeader("kid", "k1").WithType(jose.ContentType(typ)))
		b, _ := json.Marshal(claims)
		obj, _ := sg.Sign(b)
		out, _ := obj.CompactSerialize()
		return out
	}
	now := time.Now().Unix()
	claims := func(edit map[string]any) map[string]any {
		c := map[string]any{"iss": srv.URL, "aud": "pos", "jti": "a1", "sub": "boss", "req": "cashier", "perm": "sale:refund",
			"res": "sale:42", "amt": 300000, "cur": "KES", "org": "o1", "method": "pin", "iat": now, "exp": now + 120}
		for k, v := range edit {
			c[k] = v
		}
		return c
	}
	sdk := New(Config{Issuer: srv.URL, Audience: "api", HTTPClient: srv.Client()})
	ctx := context.Background()
	p := &Principal{Sub: "cashier", ClientID: "pos"}

	a, err := sdk.VerifyApproval(ctx, sign(key, "approval+jwt", claims(nil)), p)
	if err != nil || a.Approver != "boss" || a.Amount == nil || *a.Amount != 300000 || a.Permission != "sale:refund" || a.Method != "pin" {
		t.Fatalf("a good approval: %+v %v", a, err)
	}
	for name, raw := range map[string]string{
		"another typ":       sign(key, "at+jwt", claims(nil)),
		"another key":       sign(other, "approval+jwt", claims(nil)),
		"another issuer":    sign(key, "approval+jwt", claims(map[string]any{"iss": "https://evil.test"})),
		"another client":    sign(key, "approval+jwt", claims(map[string]any{"aud": "web"})),
		"another requester": sign(key, "approval+jwt", claims(map[string]any{"req": "someone"})),
	} {
		if _, err := sdk.VerifyApproval(ctx, raw, p); !errors.Is(err, ErrApprovalMismatch) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := sdk.VerifyApproval(ctx, sign(key, "approval+jwt", claims(map[string]any{"exp": now - 60})), p); !errors.Is(err, ErrApprovalClosed) {
		t.Errorf("expired: %v", err)
	}

	amount := int64(300000)
	spendStatus = http.StatusOK
	if a, err := sdk.SpendApproval(ctx, "at", "tok", "sale:refund", "sale:42", &amount); err != nil || a.ID != "a1" || a.Approver != "boss" {
		t.Fatalf("spend: %+v %v", a, err)
	}
	if spent["token"] != "tok" || spent["amount"] != float64(300000) || spent["resource"] != "sale:42" {
		t.Errorf("spend body: %v", spent)
	}
	spent = nil
	if _, err := sdk.SpendApproval(ctx, "at", "tok", "sale:void", "sale:42", nil); err != nil || spent["amount"] != nil {
		t.Errorf("no amount sends none: %v %v", spent, err)
	}
	for status, want := range map[int]error{http.StatusConflict: ErrApprovalClosed, http.StatusUnprocessableEntity: ErrApprovalMismatch, http.StatusBadGateway: ErrCheckUnavailable} {
		spendStatus = status
		if _, err := sdk.SpendApproval(ctx, "at", "tok", "sale:refund", "sale:42", &amount); !errors.Is(err, want) {
			t.Errorf("status %d: %v", status, err)
		}
	}
}
