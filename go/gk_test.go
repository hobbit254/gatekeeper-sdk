package gk

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAudienceAcceptsStringOrArray(t *testing.T) {
	for in, want := range map[string][]string{`"api"`: {"api"}, `["a","b"]`: {"a", "b"}} {
		var a audience
		if err := json.Unmarshal([]byte(in), &a); err != nil || len(a) != len(want) || a[0] != want[0] {
			t.Fatalf("%s: got %v, %v", in, a, err)
		}
	}
}

func TestMiddlewareRejectsMissingAndBadTokens(t *testing.T) {
	sdk := New(Config{Issuer: "http://127.0.0.1:1/t/x", Audience: "api", ClientID: "api"})
	h := sdk.Middleware()(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("must not be reached") }))
	for _, auth := range []string{"", "Bearer ", "Bearer not.a.jwt", "Basic abc"} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		if auth != "" {
			req.Header.Set("Authorization", auth)
		}
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized || rec.Header().Get("WWW-Authenticate") == "" {
			t.Fatalf("%q: got %d %q", auth, rec.Code, rec.Header().Get("WWW-Authenticate"))
		}
	}
}

func TestRequirePermission(t *testing.T) {
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	guard := RequirePermission("campaign:publish")(ok)
	for name, tc := range map[string]struct {
		p    *Principal
		want int
	}{
		"no principal":    {nil, http.StatusForbidden},
		"lacks it":        {&Principal{Permissions: []string{"campaign:read"}}, http.StatusForbidden},
		"holds it":        {&Principal{Permissions: []string{"campaign:read", "campaign:publish"}}, http.StatusOK},
		"no wildcard hit": {&Principal{Permissions: []string{"campaign:*"}}, http.StatusForbidden},
	} {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		if tc.p != nil {
			req = req.WithContext(context.WithValue(req.Context(), ctxKey{}, tc.p))
		}
		rec := httptest.NewRecorder()
		guard.ServeHTTP(rec, req)
		if rec.Code != tc.want {
			t.Fatalf("%s: got %d, want %d", name, rec.Code, tc.want)
		}
	}
}
