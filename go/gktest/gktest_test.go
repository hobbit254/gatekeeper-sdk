package gktest

import (
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	gk "github.com/hobbit254/gatekeeper-sdk/go"
)

// spy records failures instead of failing.
type spy struct {
	testing.TB
	errors, logs []string
}

func (s *spy) Helper()                          {}
func (s *spy) Errorf(f string, args ...any)     { s.errors = append(s.errors, f) }
func (s *spy) Logf(f string, args ...any)       { s.logs = append(s.logs, f) }
func ok(w http.ResponseWriter, _ *http.Request) {}

// logging is someone else's middleware that unwraps.
type logging struct{ next http.Handler }

func (l logging) ServeHTTP(w http.ResponseWriter, r *http.Request) { l.next.ServeHTTP(w, r) }
func (l logging) Unwrap() http.Handler                             { return l.next }

// FR-S20 (ADR-0149): unmarked routes fail, listed; marks are found through
// Middleware and unwrapping middleware; unused permissions are listed.
func TestEveryRouteGuarded(t *testing.T) {
	sdk := gk.New(gk.Config{Issuer: "https://auth.test/t/acme", Audience: "api", ClientID: "web"})
	auth := sdk.Middleware()
	mux := NewMux()
	mux.Handle("GET /orders", auth(gk.RequirePermission("order:read")(http.HandlerFunc(ok))))
	mux.Handle("POST /orders/{id}/refund", logging{auth(sdk.RequirePermissionOn("order:refund", func(r *http.Request) string { return "order:" + r.PathValue("id") })(http.HandlerFunc(ok)))})
	mux.Handle("GET /health", gk.Public()(http.HandlerFunc(ok)))
	mux.Handle("GET /me", auth(gk.SignedIn()(http.HandlerFunc(ok))))
	mux.Handle("DELETE /account", auth(gk.RequireStepUp(5*time.Minute)(http.HandlerFunc(ok))))
	rep := Check(mux.Routes(), Options{Permissions: []string{"order:read", "order:refund", "order:export"}})
	if len(rep.Unguarded) != 0 || !slices.Equal(rep.Unused, []string{"order:export"}) {
		t.Fatalf("all guarded: %+v", rep)
	}

	mux.HandleFunc("GET /orders/export", ok)
	mux.Handle("POST /orders", auth(http.HandlerFunc(ok)))                                              // a token, but no decision about what it may do
	mux.Handle("GET /admin", struct{ http.Handler }{gk.RequirePermission("x:y")(http.HandlerFunc(ok))}) // hidden by middleware that doesn't unwrap
	rep = Check(mux.Routes(), Options{Ignore: []string{"GET /orders/export"}})
	if !slices.Equal(rep.Unguarded, []string{"GET /admin", "POST /orders"}) {
		t.Fatalf("unguarded: %v", rep.Unguarded)
	}

	s := &spy{TB: t}
	AssertEveryRouteGuarded(s, mux.Routes(), Options{Permissions: []string{"order:export"}})
	if len(s.errors) != 1 || len(s.logs) != 1 {
		t.Fatalf("one failure listing the routes, one note on unused: %v %v", s.errors, s.logs)
	}
	s = &spy{TB: t}
	AssertEveryRouteGuarded(s, []Route{{Method: "GET", Pattern: "/x", Handler: gk.Public()(http.HandlerFunc(ok))}},
		Options{Permissions: []string{"order:export"}, FailOnUnused: true})
	if len(s.errors) != 1 || !strings.Contains(s.errors[0], "no route guards") {
		t.Fatalf("FailOnUnused: %v", s.errors)
	}
}

// SignedIn still refuses a request without a Principal.
func TestSignedInNeedsAPrincipal(t *testing.T) {
	rec := &recorder{header: http.Header{}}
	gk.SignedIn()(http.HandlerFunc(ok)).ServeHTTP(rec, &http.Request{Header: http.Header{}})
	if rec.code != http.StatusUnauthorized {
		t.Fatalf("status %d", rec.code)
	}
}

type recorder struct {
	header http.Header
	code   int
}

func (r *recorder) Header() http.Header         { return r.header }
func (r *recorder) Write(b []byte) (int, error) { return len(b), nil }
func (r *recorder) WriteHeader(c int)           { r.code = c }
