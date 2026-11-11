// Package admin is the typed Gatekeeper admin API client, generated from
// sdk/admin-openapi.json (FR-D13, ADR-0088). admin.gen.go is generated:
// regenerate with `make sdk-clients`, never edit it.
package admin

import (
	"context"
	"net/http"
	"strings"
)

// TokenSource returns the bearer token for a request: a tenant admin's
// access token, or a service account's client-credentials token
// (gk.ClientCredentials.Token).
type TokenSource func(ctx context.Context) (string, error)

// New returns an admin client for the tenant issuer, such as
// https://auth.example.com/t/acme. Every request carries token's bearer.
func New(issuer string, token TokenSource, opts ...ClientOption) (*ClientWithResponses, error) {
	bearer := WithRequestEditorFn(func(ctx context.Context, req *http.Request) error {
		t, err := token(ctx)
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+t)
		return nil
	})
	return NewClientWithResponses(strings.TrimSuffix(issuer, "/"), append([]ClientOption{bearer}, opts...)...)
}
