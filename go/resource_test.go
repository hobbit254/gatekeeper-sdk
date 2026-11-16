package gk

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// fakeAuthz answers checks: campaign:1 is allowed, campaign:2 needs step-up, others are denied.
func fakeAuthz(t *testing.T, calls *int) *httptest.Server {
	decide := func(res string) ResourceDecision {
		switch res {
		case "campaign:1":
			return ResourceDecision{Allow: true, MatchedBy: "relation:can_edit"}
		case "campaign:2":
			return ResourceDecision{MatchedBy: "step_up_required", MaxAge: 300}
		}
		return ResourceDecision{MatchedBy: "none"}
	}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*calls++
		if r.Header.Get("Authorization") != "Bearer tok" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/v1/authz/check":
			var b map[string]string
			_ = json.NewDecoder(r.Body).Decode(&b)
			_ = json.NewEncoder(w).Encode(decide(b["resource"]))
		case "/v1/authz/check-batch":
			var b struct{ Checks []map[string]string }
			_ = json.NewDecoder(r.Body).Decode(&b)
			out := []ResourceDecision{}
			for _, c := range b.Checks {
				out = append(out, decide(c["resource"]))
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"results": out})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

func TestCanOnAsksEveryTime(t *testing.T) {
	calls := 0
	srv := fakeAuthz(t, &calls)
	defer srv.Close()
	s := New(Config{Issuer: srv.URL, HTTPClient: srv.Client()})
	for range 2 {
		d, err := s.CanOn(context.Background(), "tok", "campaign:update", "campaign:1")
		if err != nil || !d.Allow || d.MatchedBy != "relation:can_edit" {
			t.Fatalf("CanOn = %+v, %v", d, err)
		}
	}
	if calls != 2 {
		t.Fatalf("no cache: want 2 calls, got %d", calls)
	}
	ds, err := s.CanOnEach(context.Background(), "tok", "campaign:update", []string{"campaign:1", "campaign:3", "campaign:2"})
	if err != nil || len(ds) != 3 || !ds[0].Allow || ds[1].Allow || ds[2].MaxAge != 300 {
		t.Fatalf("CanOnEach = %+v, %v", ds, err)
	}
	if _, err := s.CanOn(context.Background(), "wrong", "campaign:update", "campaign:1"); err == nil {
		t.Fatal("a refused call is an error, not a deny")
	}
}

func TestRequirePermissionOn(t *testing.T) {
	calls := 0
	srv := fakeAuthz(t, &calls)
	defer srv.Close()
	s := New(Config{Issuer: srv.URL, HTTPClient: srv.Client()})
	h := s.RequirePermissionOn("campaign:update", func(r *http.Request) string { return r.URL.Query().Get("c") })(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	run := func(res, auth string, verified bool) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/?c="+res, nil)
		req.Header.Set("Authorization", auth)
		if verified {
			req = req.WithContext(context.WithValue(req.Context(), ctxKey{}, &Principal{Sub: "u"}))
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	for name, c := range map[string]struct {
		res, auth string
		verified  bool
		want      int
	}{
		"allowed":                {"campaign:1", "Bearer tok", true, 200},
		"denied":                 {"campaign:3", "Bearer tok", true, 403},
		"step-up":                {"campaign:2", "Bearer tok", true, 401},
		"not through Middleware": {"campaign:1", "Bearer tok", false, 403},
		"a DPoP token":           {"campaign:1", "DPoP tok", true, 403},
		"Gatekeeper refuses":     {"campaign:1", "Bearer other", true, 503},
	} {
		if got := run(c.res, c.auth, c.verified); got.Code != c.want {
			t.Errorf("%s: %d, want %d", name, got.Code, c.want)
		}
	}
	if got := run("campaign:2", "Bearer tok", true).Header().Get("WWW-Authenticate"); got != `Bearer error="insufficient_user_authentication", max_age="300", acr_values="mfa"` {
		t.Errorf("challenge %q", got)
	}
}

// FR-Z16 (ADR-0119): a DPoP-bound principal is checked with the client's own credentials.
func TestRequirePermissionOnChecksDPoPUsersOnBehalf(t *testing.T) {
	tokens := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth2/token" {
			tokens++
			id, secret, _ := r.BasicAuth()
			if id != "shop" || secret != "s3cret" || r.FormValue("scope") != "authz:check" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "cc", "expires_in": 300})
			return
		}
		var b map[string]string
		_ = json.NewDecoder(r.Body).Decode(&b)
		if r.Header.Get("Authorization") != "Bearer cc" || b["user_id"] != "u-1" {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"type":"https://gatekeeper.dev/problems/user-not-served"}`))
			return
		}
		_ = json.NewEncoder(w).Encode(ResourceDecision{Allow: b["resource"] == "campaign:1"})
	}))
	defer srv.Close()
	run := func(s *SDK, sub string) int {
		h := s.RequirePermissionOn("campaign:update", func(*http.Request) string { return "campaign:1" })(
			http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
		req := httptest.NewRequest(http.MethodPost, "/", nil)
		req.Header.Set("Authorization", "DPoP tok")
		req = req.WithContext(context.WithValue(req.Context(), ctxKey{}, &Principal{Sub: sub, JKT: "thumb"}))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	with := New(Config{Issuer: srv.URL, HTTPClient: srv.Client(), ClientID: "shop", ClientSecret: "s3cret"})
	if got := run(with, "u-1"); got != 200 {
		t.Fatalf("served user: %d", got)
	}
	if got := run(with, "u-2"); got != 403 {
		t.Fatalf("not served: %d", got)
	}
	if tokens != 1 {
		t.Fatalf("the client token is cached: %d fetches", tokens)
	}
	if got := run(New(Config{Issuer: srv.URL, HTTPClient: srv.Client(), ClientID: "shop"}), "u-1"); got != 403 {
		t.Fatalf("no secret: refused as before, got %d", got)
	}
	if _, err := New(Config{Issuer: srv.URL, HTTPClient: srv.Client()}).CanOnFor(context.Background(), "u-1", "campaign:update", "campaign:1"); err != ErrNoClientCredentials {
		t.Fatalf("CanOnFor without credentials: %v", err)
	}
}
