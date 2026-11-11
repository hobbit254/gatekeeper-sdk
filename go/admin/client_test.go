package admin

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewSendsTheBearerToTheTenantIssuer(t *testing.T) {
	var got *http.Request
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"items":[]}`))
	}))
	defer srv.Close()
	c, err := New(srv.URL+"/t/acme/", func(context.Context) (string, error) { return "tok", nil })
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.AdminListClientsWithResponse(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode() != 200 || got.URL.Path != "/t/acme/v1/admin/clients" || got.Header.Get("Authorization") != "Bearer tok" {
		t.Fatalf("status %d path %s auth %q", resp.StatusCode(), got.URL.Path, got.Header.Get("Authorization"))
	}
}
