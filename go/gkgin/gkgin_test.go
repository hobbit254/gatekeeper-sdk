package gkgin

import (
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

	"github.com/gin-gonic/gin"
	jose "github.com/go-jose/go-jose/v4"

	gk "github.com/hobbit254/gatekeeper-sdk/go"
)

type spy struct {
	testing.TB
	errors, logs []string
}

func (s *spy) Helper()                      {}
func (s *spy) Errorf(f string, args ...any) { s.errors = append(s.errors, f) }
func (s *spy) Logf(f string, args ...any)   { s.logs = append(s.logs, f) }

func ok(c *gin.Context) { c.String(200, "ok") }

// FR-S20 (ADR-0153): gin routes whose handler isn't wrapped fail, listed;
// each wrapper keeps its own permission; unused permissions are listed.
func TestEveryGinRouteGuarded(t *testing.T) {
	gin.SetMode(gin.TestMode)
	sdk := gk.New(gk.Config{Issuer: "https://auth.test/t/acme", Audience: "api", ClientID: "web"})
	r := gin.New()
	r.Use(Middleware(sdk))
	r.GET("/orders", RequirePermission("order:read", ok))
	r.POST("/orders/:id/refund", RequirePermissionOn(sdk, "order:refund", func(c *gin.Context) string { return "order:" + c.Param("id") }, ok))
	r.GET("/health", Public(ok))
	r.GET("/me", SignedIn(ok))
	rep := Check(r, Options{Permissions: []string{"order:read", "order:refund", "order:export"}})
	if len(rep.Unguarded) != 0 || !slices.Equal(rep.Unused, []string{"order:export"}) {
		t.Fatalf("all guarded: %+v", rep)
	}
	r.POST("/orders", ok)
	r.DELETE("/orders/:id", ok)
	rep = Check(r, Options{Ignore: []string{"DELETE /orders/:id"}})
	if !slices.Equal(rep.Unguarded, []string{"POST /orders"}) {
		t.Fatalf("unguarded: %v", rep.Unguarded)
	}
	s := &spy{TB: t}
	AssertEveryRouteGuarded(s, r, Options{Permissions: []string{"order:export"}})
	if len(s.errors) != 1 || len(s.logs) != 1 || !strings.Contains(s.errors[0], "no Gatekeeper guard") {
		t.Fatalf("one failure, one note: %v %v", s.errors, s.logs)
	}
	s = &spy{TB: t}
	AssertEveryRouteGuarded(s, r, Options{Permissions: []string{"order:export"}, FailOnUnused: true, Ignore: []string{"/orders", "/orders/:id"}})
	if len(s.errors) != 1 {
		t.Fatalf("FailOnUnused: %v", s.errors)
	}
}

// The guards still guard: no token is 401, and the handler doesn't run.
func TestGinGuardsRefuse(t *testing.T) {
	gin.SetMode(gin.TestMode)
	sdk := gk.New(gk.Config{Issuer: "https://auth.test/t/acme", Audience: "api", ClientID: "web"})
	ran := false
	r := gin.New()
	r.Use(Middleware(sdk))
	r.GET("/orders", RequirePermission("order:read", func(c *gin.Context) { ran = true }))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/orders", nil))
	if w.Code != http.StatusUnauthorized || ran {
		t.Fatalf("status %d ran %v", w.Code, ran)
	}
	open := gin.New()
	open.GET("/orders", RequirePermission("order:read", func(c *gin.Context) { ran = true }))
	w = httptest.NewRecorder()
	open.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/orders", nil))
	if w.Code != http.StatusForbidden || ran {
		t.Fatalf("no principal: status %d ran %v", w.Code, ran)
	}
	g, found := GuardOf(RequirePermission("x:y", ok))
	if !found || g.Permission != "x:y" {
		t.Fatalf("mark: %+v %v", g, found)
	}
	if _, found := GuardOf(ok); found {
		t.Fatal("a plain handler has no mark")
	}
}

// RequirePermissionOn asks Gatekeeper about the resource this request names.
func TestGinResourceGuard(t *testing.T) {
	gin.SetMode(gin.TestMode)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	set := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "k1", Algorithm: "ES256", Use: "sig"}}}
	var asked string
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/jwks.json", func(w http.ResponseWriter, _ *http.Request) { _ = json.NewEncoder(w).Encode(set) })
	mux.HandleFunc("/v1/clients/web/role-map", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"rv": 1, "roles": map[string][]string{}})
	})
	mux.HandleFunc("/v1/authz/check", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		asked = body["resource"]
		_ = json.NewEncoder(w).Encode(map[string]any{"allow": body["resource"] == "order:42", "matched_by": "relation:owner"})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	sg, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key}, (&jose.SignerOptions{}).WithHeader("kid", "k1").WithType("at+jwt"))
	b, _ := json.Marshal(map[string]any{"iss": srv.URL, "aud": "api", "sub": "u1", "client_id": "web", "jti": "j", "rv": 1, "exp": time.Now().Add(time.Minute).Unix()})
	obj, _ := sg.Sign(b)
	tok, _ := obj.CompactSerialize()
	sdk := gk.New(gk.Config{Issuer: srv.URL, Audience: "api", ClientID: "web", HTTPClient: srv.Client()})
	r := gin.New()
	r.Use(Middleware(sdk))
	r.POST("/orders/:id/refund", RequirePermissionOn(sdk, "order:refund", func(c *gin.Context) string { return "order:" + c.Param("id") }, ok))
	for id, want := range map[string]int{"42": 200, "43": 403} {
		req := httptest.NewRequest(http.MethodPost, "/orders/"+id+"/refund", nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != want || asked != "order:"+id {
			t.Fatalf("order %s: status %d, asked about %q", id, w.Code, asked)
		}
	}
}
