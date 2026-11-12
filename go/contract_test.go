package gk

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"testing"
	"time"
)

// vectors is sdk/contract/vectors.json, shared by every SDK (ADR-0038).
type vectors struct {
	Issuer       string          `json:"issuer"`
	Audience     string          `json:"audience"`
	ClientID     string          `json:"client_id"`
	ClientSecret string          `json:"client_secret"`
	JWKS         json.RawMessage `json:"jwks"`
	RoleMap      json.RawMessage `json:"role_map"`
	Cases        []struct {
		Name, Token, Permission, Expect string
	} `json:"cases"`
	Denylist struct {
		SIDs  []string `json:"sids"`
		JTIs  []string `json:"jtis"`
		Cases []struct {
			Name, Token, Permission, Expect string
		} `json:"cases"`
	} `json:"denylist"`
	StepUp []struct {
		Name, Token string
		MaxAge      int  `json:"max_age"`
		Fresh       bool `json:"fresh"`
	} `json:"step_up"`
	PermissionStepUp []struct {
		Name, Token, Permission, Expect string
		MaxAge                          int `json:"max_age"`
	} `json:"permission_step_up"`
	Entitlements struct {
		Token, Plan, Plain string
		Features, Has      []string
		Lacks              []string
	} `json:"entitlements"`
	Impersonation struct {
		Token  string `json:"token"`
		Actor  string `json:"actor"`
		EndsAt int64  `json:"ends_at"`
		Plain  string `json:"plain"`
	} `json:"impersonation"`
	DPoP struct {
		Token  string `json:"token"`
		JKT    string `json:"jkt"`
		Now    int64  `json:"now"`
		Method string `json:"method"`
		URL    string `json:"url"`
		Cases  []struct {
			Name, Proof, Expect string
		} `json:"cases"`
	} `json:"dpop"`
	APIKeys struct {
		Introspection map[string]json.RawMessage `json:"introspection"`
		Subject       string                     `json:"subject"`
		Cases         []struct {
			Name, Token, Permission, Expect string
		} `json:"cases"`
	} `json:"api_keys"`
}

// fixedServer answers the two SDK fetches from the vectors file.
type fixedServer struct{ v vectors }

func (f fixedServer) RoundTrip(r *http.Request) (*http.Response, error) {
	body, code := []byte(`{}`), http.StatusNotFound
	switch r.URL.String() {
	case f.v.Issuer + "/oauth2/introspect":
		body, code = []byte(`{"error":"invalid_client"}`), http.StatusUnauthorized
		if u, p, ok := r.BasicAuth(); ok && u == f.v.ClientID && p == f.v.ClientSecret && r.ParseForm() == nil {
			body, code = []byte(`{"active":false}`), http.StatusOK
			if canned, ok := f.v.APIKeys.Introspection[r.PostForm.Get("token")]; ok {
				body = canned
			}
		}
	case f.v.Issuer + "/.well-known/jwks.json":
		body, code = f.v.JWKS, http.StatusOK
	case f.v.Issuer + "/v1/clients/" + f.v.ClientID + "/role-map":
		if u, p, ok := r.BasicAuth(); ok && u == f.v.ClientID && p == f.v.ClientSecret {
			body, code = f.v.RoleMap, http.StatusOK
		} else {
			code = http.StatusUnauthorized
		}
	}
	return &http.Response{StatusCode: code, Body: io.NopCloser(bytes.NewReader(body)), Header: http.Header{}, Request: r}, nil
}

func TestContractVectors(t *testing.T) {
	raw, err := os.ReadFile("../contract/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v vectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	for _, c := range v.Cases {
		t.Run(c.Name, func(t *testing.T) {
			sdk := New(Config{Issuer: v.Issuer, Audience: v.Audience, ClientID: v.ClientID, ClientSecret: v.ClientSecret,
				HTTPClient: &http.Client{Transport: fixedServer{v}}})
			p, err := sdk.Verify(context.Background(), c.Token)
			got := "reject"
			if err == nil {
				got = map[bool]string{true: "allow", false: "deny"}[p.Can(c.Permission)]
			}
			if got != c.Expect {
				t.Fatalf("got %s, want %s (err %v)", got, c.Expect, err)
			}
		})
	}
}

func TestContractStepUp(t *testing.T) {
	raw, err := os.ReadFile("../contract/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v vectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	for _, c := range v.StepUp {
		t.Run(c.Name, func(t *testing.T) {
			sdk := New(Config{Issuer: v.Issuer, Audience: v.Audience, ClientID: v.ClientID, ClientSecret: v.ClientSecret,
				HTTPClient: &http.Client{Transport: fixedServer{v}}})
			p, err := sdk.Verify(context.Background(), c.Token)
			if err != nil {
				t.Fatal(err)
			}
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/", nil).WithContext(context.WithValue(context.Background(), ctxKey{}, p))
			RequireStepUp(time.Duration(c.MaxAge)*time.Second)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusOK)
			})).ServeHTTP(rec, req)
			if got := rec.Code == http.StatusOK; got != c.Fresh {
				t.Fatalf("fresh: got %v, want %v", got, c.Fresh)
			}
			if !c.Fresh && rec.Header().Get("WWW-Authenticate") != fmt.Sprintf(`Bearer error="insufficient_user_authentication", max_age="%d"`, c.MaxAge) {
				t.Fatalf("challenge: %q", rec.Header().Get("WWW-Authenticate"))
			}
		})
	}
}

type setDenylist struct{ sids, jtis []string }

func (d setDenylist) Denied(_ context.Context, sid, jti string) (bool, error) {
	return slices.Contains(d.sids, sid) || slices.Contains(d.jtis, jti), nil
}

func TestContractDenylist(t *testing.T) {
	raw, err := os.ReadFile("../contract/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v vectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	for _, c := range v.Denylist.Cases {
		t.Run(c.Name, func(t *testing.T) {
			sdk := New(Config{Issuer: v.Issuer, Audience: v.Audience, ClientID: v.ClientID, ClientSecret: v.ClientSecret,
				HTTPClient: &http.Client{Transport: fixedServer{v}}}).WithDenylist(setDenylist{v.Denylist.SIDs, v.Denylist.JTIs})
			p, err := sdk.Verify(context.Background(), c.Token)
			got := "reject"
			if err == nil {
				got = map[bool]string{true: "allow", false: "deny"}[p.Can(c.Permission)]
			}
			if got != c.Expect {
				t.Fatalf("got %s, want %s (%v)", got, c.Expect, err)
			}
		})
	}
	t.Run("an unreachable denylist refuses", func(t *testing.T) {
		sdk := New(Config{Issuer: v.Issuer, Audience: v.Audience, ClientID: v.ClientID, ClientSecret: v.ClientSecret,
			HTTPClient: &http.Client{Transport: fixedServer{v}}}).WithDenylist(brokenDenylist{})
		if _, err := sdk.Verify(context.Background(), v.Denylist.Cases[0].Token); err == nil {
			t.Fatal("want an error")
		}
	})
}

type brokenDenylist struct{}

func (brokenDenylist) Denied(context.Context, string, string) (bool, error) {
	return false, errors.New("redis down")
}

func loadVectors(t *testing.T) vectors {
	t.Helper()
	raw, err := os.ReadFile("../contract/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v vectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func vectorSDK(v vectors) *SDK {
	return New(Config{Issuer: v.Issuer, Audience: v.Audience, ClientID: v.ClientID, ClientSecret: v.ClientSecret,
		HTTPClient: &http.Client{Transport: fixedServer{v}}})
}

func TestContractEntitlements(t *testing.T) {
	v := loadVectors(t)
	p, err := vectorSDK(v).Verify(context.Background(), v.Entitlements.Token)
	if err != nil {
		t.Fatal(err)
	}
	if p.Entitlements == nil || p.Entitlements.Plan != v.Entitlements.Plan || !slices.Equal(p.Entitlements.Features, v.Entitlements.Features) {
		t.Fatalf("entitlements %+v", p.Entitlements)
	}
	for _, f := range v.Entitlements.Has {
		if !p.HasFeature(f) {
			t.Errorf("HasFeature(%q) = false", f)
		}
	}
	for _, f := range v.Entitlements.Lacks {
		if p.HasFeature(f) {
			t.Errorf("HasFeature(%q) = true", f)
		}
	}
	p, err = vectorSDK(v).Verify(context.Background(), v.Entitlements.Plain)
	if err != nil || p.Entitlements != nil || p.HasFeature(v.Entitlements.Has[0]) {
		t.Fatalf("a token without the claim has none: %+v %v", p.Entitlements, err)
	}
}

func TestContractImpersonation(t *testing.T) {
	v := loadVectors(t)
	p, err := vectorSDK(v).Verify(context.Background(), v.Impersonation.Token)
	if err != nil {
		t.Fatal(err)
	}
	if p.Actor != v.Impersonation.Actor || p.ImpersonationEndsAt.Unix() != v.Impersonation.EndsAt {
		t.Fatalf("actor %q ends %v", p.Actor, p.ImpersonationEndsAt)
	}
	p, err = vectorSDK(v).Verify(context.Background(), v.Impersonation.Plain)
	if err != nil || p.Actor != "" || !p.ImpersonationEndsAt.IsZero() {
		t.Fatalf("a plain token is not impersonation: %+v %v", p, err)
	}
}

func TestContractAPIKeys(t *testing.T) {
	v := loadVectors(t)
	for _, c := range v.APIKeys.Cases {
		t.Run(c.Name, func(t *testing.T) {
			p, err := vectorSDK(v).Verify(context.Background(), c.Token)
			got := "reject"
			if err == nil {
				got = map[bool]string{true: "allow", false: "deny"}[p.Can(c.Permission)]
				if !p.APIKey || p.Sub != v.APIKeys.Subject || p.FreshMFA(time.Hour) {
					t.Fatalf("principal %+v", p)
				}
			}
			if got != c.Expect {
				t.Fatalf("got %s, want %s (%v)", got, c.Expect, err)
			}
		})
	}
}

func TestContractDPoP(t *testing.T) {
	v := loadVectors(t)
	sdk := vectorSDK(v)
	sdk.now = func() time.Time { return time.Unix(v.DPoP.Now, 0) }
	p, err := sdk.Verify(context.Background(), v.DPoP.Token)
	if err != nil || p.JKT != v.DPoP.JKT {
		t.Fatalf("bound token: %+v %v", p, err)
	}
	for _, c := range v.DPoP.Cases { // in order: one replay cache
		err := sdk.VerifyDPoP(p, v.DPoP.Token, c.Proof, v.DPoP.Method, v.DPoP.URL)
		if got := map[bool]string{true: "allow", false: "reject"}[err == nil]; got != c.Expect {
			t.Fatalf("%s: got %s, want %s (%v)", c.Name, got, c.Expect, err)
		}
	}
}

func TestDPoPMiddlewareRefusesABoundTokenAsBearer(t *testing.T) {
	v := loadVectors(t)
	sdk := vectorSDK(v)
	h := sdk.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	for _, auth := range []string{"Bearer " + v.DPoP.Token, "DPoP " + v.DPoP.Token, "DPoP " + v.Impersonation.Plain} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, v.DPoP.URL, nil)
		req.Header.Set("Authorization", auth)
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized || rec.Header().Get("WWW-Authenticate") == "" {
			t.Fatalf("%.20s: status %d", auth, rec.Code)
		}
	}
}

func TestContractPermissionStepUp(t *testing.T) {
	raw, err := os.ReadFile("../contract/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v vectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	if len(v.PermissionStepUp) == 0 {
		t.Fatal("no permission_step_up cases")
	}
	for _, c := range v.PermissionStepUp {
		t.Run(c.Name, func(t *testing.T) {
			sdk := New(Config{Issuer: v.Issuer, Audience: v.Audience, ClientID: v.ClientID, ClientSecret: v.ClientSecret,
				HTTPClient: &http.Client{Transport: fixedServer{v}}})
			p, err := sdk.Verify(context.Background(), c.Token)
			if err != nil {
				t.Fatal(err)
			}
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/", nil).WithContext(context.WithValue(context.Background(), ctxKey{}, p))
			RequirePermission(c.Permission)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusOK)
			})).ServeHTTP(rec, req)
			want := map[string]int{"allow": http.StatusOK, "deny": http.StatusForbidden, "step_up": http.StatusUnauthorized}[c.Expect]
			if rec.Code != want {
				t.Fatalf("got %d, want %d", rec.Code, want)
			}
			if c.Expect == "step_up" && rec.Header().Get("WWW-Authenticate") !=
				fmt.Sprintf(`Bearer error="insufficient_user_authentication", max_age="%d", acr_values="mfa"`, c.MaxAge) {
				t.Fatalf("challenge: %q", rec.Header().Get("WWW-Authenticate"))
			}
		})
	}
}
