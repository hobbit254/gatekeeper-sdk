package gk

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"testing"
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
}

// fixedServer answers the two SDK fetches from the vectors file.
type fixedServer struct{ v vectors }

func (f fixedServer) RoundTrip(r *http.Request) (*http.Response, error) {
	body, code := []byte(`{}`), http.StatusNotFound
	switch r.URL.String() {
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
