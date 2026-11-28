package gk

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// FR-M5 (ADR-0146): read-mode support access keeps only read permissions;
// write mode keeps them all; a token whose act has no mode is read.
func TestSupportSessionModes(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	set := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "k1", Algorithm: "ES256", Use: "sig"}}}
	withRead := true
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/jwks.json", func(w http.ResponseWriter, _ *http.Request) { _ = json.NewEncoder(w).Encode(set) })
	mux.HandleFunc("/v1/clients/web/role-map", func(w http.ResponseWriter, _ *http.Request) {
		rm := map[string]any{"rv": 1, "roles": map[string][]string{"ops": {"report:read", "report:list", "report:export"}}}
		if withRead {
			rm["read"] = []string{"report:read", "report:list"}
		}
		_ = json.NewEncoder(w).Encode(rm)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	token := func(act map[string]any) string {
		sg, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key}, (&jose.SignerOptions{}).WithHeader("kid", "k1").WithType("at+jwt"))
		c := map[string]any{"iss": srv.URL, "aud": "api", "sub": "u1", "client_id": "web", "jti": "j", "roles": []string{"ops"}, "rv": 1,
			"exp": time.Now().Add(time.Minute).Unix()}
		if act != nil {
			c["act"] = act
		}
		b, _ := json.Marshal(c)
		obj, _ := sg.Sign(b)
		out, _ := obj.CompactSerialize()
		return out
	}
	ctx := context.Background()
	verify := func(act map[string]any) *Principal {
		sdk := New(Config{Issuer: srv.URL, Audience: "api", ClientID: "web", HTTPClient: srv.Client()})
		p, err := sdk.Verify(ctx, token(act))
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	if p := verify(nil); p.ActorMode != "" || len(p.Permissions) != 3 {
		t.Errorf("no actor: %+v", p)
	}
	p := verify(map[string]any{"sub": "admin", "ends_at": time.Now().Add(time.Hour).Unix(), "mode": "read"})
	if p.ActorMode != ActorRead || !p.Can("report:list") || p.Can("report:export") {
		t.Errorf("read mode: %v %v", p.ActorMode, p.Permissions)
	}
	if p := verify(map[string]any{"sub": "admin", "mode": "write"}); p.ActorMode != ActorWrite || !p.Can("report:export") {
		t.Errorf("write mode: %v %v", p.ActorMode, p.Permissions)
	}
	if p := verify(map[string]any{"sub": "admin"}); p.ActorMode != ActorRead || p.Can("report:export") {
		t.Errorf("no mode is read: %v %v", p.ActorMode, p.Permissions)
	}
	withRead = false
	p = verify(map[string]any{"sub": "admin", "mode": "read"})
	if !slices.Equal(p.Permissions, []string{"report:read"}) || !strings.HasSuffix(p.Permissions[0], ":read") {
		t.Errorf("an older server's map: only :read keys: %v", p.Permissions)
	}
}
