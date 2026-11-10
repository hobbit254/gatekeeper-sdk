package gk

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type countingServer struct {
	fixedServer
	introspections atomic.Int32
}

func (c *countingServer) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.Path == "/t/acme/oauth2/introspect" {
		c.introspections.Add(1)
	}
	return c.fixedServer.RoundTrip(r)
}

func TestAPIKeysAreCachedForAMinute(t *testing.T) {
	v := loadVectors(t)
	srv := &countingServer{fixedServer: fixedServer{v}}
	sdk := New(Config{Issuer: v.Issuer, Audience: v.Audience, ClientID: v.ClientID, ClientSecret: v.ClientSecret,
		HTTPClient: &http.Client{Transport: srv}})
	now := time.Now()
	sdk.now = func() time.Time { return now }
	key := v.APIKeys.Cases[0].Token
	for range 3 {
		if _, err := sdk.Verify(context.Background(), key); err != nil {
			t.Fatal(err)
		}
	}
	if n := srv.introspections.Load(); n != 1 {
		t.Fatalf("introspected %d times", n)
	}
	now = now.Add(61 * time.Second)
	_, _ = sdk.Verify(context.Background(), key)
	if n := srv.introspections.Load(); n != 2 {
		t.Fatalf("after a minute: introspected %d times", n)
	}
}

func TestAPIKeyIntrospectionFailureRefuses(t *testing.T) {
	v := loadVectors(t)
	sdk := New(Config{Issuer: v.Issuer, Audience: v.Audience, ClientID: v.ClientID, ClientSecret: "wrong", // the server answers 401
		HTTPClient: &http.Client{Transport: fixedServer{v}}})
	if _, err := sdk.Verify(context.Background(), v.APIKeys.Cases[0].Token); err == nil {
		t.Fatal("want an error")
	}
}

func TestClientCredentialsCachesAndSharesOneRequest(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		u, p, ok := r.BasicAuth()
		if !ok || u != "svc-job" || p != "s3cret" || r.FormValue("grant_type") != "client_credentials" || r.FormValue("audience") != "api" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		time.Sleep(20 * time.Millisecond)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"tok-1","token_type":"bearer","expires_in":600}`))
	}))
	defer srv.Close()
	cc := &ClientCredentials{TokenURL: srv.URL, ClientID: "svc-job", ClientSecret: "s3cret", Audience: "api"}
	var wg sync.WaitGroup
	for range 5 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if tok, err := cc.Token(context.Background()); err != nil || tok != "tok-1" {
				t.Errorf("token %q %v", tok, err)
			}
		}()
	}
	wg.Wait()
	if _, err := cc.Token(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n := calls.Load(); n != 1 {
		t.Fatalf("token endpoint called %d times", n)
	}
	bad := &ClientCredentials{TokenURL: srv.URL, ClientID: "svc-job", ClientSecret: "nope"}
	if _, err := bad.Token(context.Background()); err == nil {
		t.Fatal("want an error")
	}
}
