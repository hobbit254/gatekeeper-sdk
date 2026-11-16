package gk

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// Resource checks ask Gatekeeper, with the caller's own token, whether its
// subject holds a permission on one resource: roles, grants and OpenFGA
// relations (FR-Z12, ADR-0108). Nothing is cached, so a removed relation
// applies to the next call.

// ResourceDecision is Gatekeeper's answer for one resource. MaxAge is set
// when the permission needs a second factor within that many seconds.
type ResourceDecision struct {
	Allow     bool   `json:"allow"`
	MatchedBy string `json:"matched_by"`
	MaxAge    int    `json:"max_age,omitempty"`
}

// ErrCheckUnavailable is Gatekeeper not answering a resource check.
var ErrCheckUnavailable = errors.New("gk: resource check unavailable")

const maxBatch = 200

// CanOn decides permission on resource ("campaign:42") for accessToken's subject.
func (s *SDK) CanOn(ctx context.Context, accessToken, permission, resource string) (ResourceDecision, error) {
	var d ResourceDecision
	err := s.authz(ctx, accessToken, "/v1/authz/check", map[string]string{"permission": permission, "resource": resource}, &d)
	return d, err
}

// CanOnEach decides permission on each resource, in order, 200 to a request.
func (s *SDK) CanOnEach(ctx context.Context, accessToken, permission string, resources []string) ([]ResourceDecision, error) {
	return s.canOnEach(ctx, accessToken, "", permission, resources)
}

func (s *SDK) canOnEach(ctx context.Context, accessToken, userID, permission string, resources []string) ([]ResourceDecision, error) {
	out := make([]ResourceDecision, 0, len(resources))
	for start := 0; start < len(resources); start += maxBatch {
		chunk := resources[start:min(start+maxBatch, len(resources))]
		checks := make([]map[string]string, len(chunk))
		for i, r := range chunk {
			checks[i] = map[string]string{"permission": permission, "resource": r}
		}
		var res struct {
			Results []ResourceDecision `json:"results"`
		}
		body := map[string]any{"checks": checks}
		if userID != "" {
			body["user_id"] = userID
		}
		if err := s.authz(ctx, accessToken, "/v1/authz/check-batch", body, &res); err != nil {
			return nil, err
		}
		if len(res.Results) != len(chunk) {
			return nil, fmt.Errorf("%w: %d answers for %d checks", ErrCheckUnavailable, len(res.Results), len(chunk))
		}
		out = append(out, res.Results...)
	}
	return out, nil
}

func (s *SDK) authz(ctx context.Context, token, path string, body, out any) error {
	b, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.cfg.Issuer+path, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := s.cfg.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrCheckUnavailable, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusForbidden {
		var p struct {
			Type string `json:"type"`
		}
		if json.NewDecoder(resp.Body).Decode(&p) == nil && strings.HasSuffix(p.Type, "user-not-served") {
			return ErrNotServed
		}
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: status %d", ErrCheckUnavailable, resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("%w: %v", ErrCheckUnavailable, err)
	}
	return nil
}

// RequirePermissionOn guards a route with a resource check; resource reads
// the object id ("campaign:42") from the request. Use it after Middleware.
// It answers 403 when denied, 401 with the RFC 9470 challenge when a fresher
// second factor would allow it, and 503 when Gatekeeper can't answer. A
// DPoP-bound token can't be forwarded without its holder's proof, so for one
// the check uses the client's credentials (CanOnFor, ADR-0119); without them it is 403.
func (s *SDK) RequirePermissionOn(permission string, resource func(*http.Request) string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p, verified := FromContext(r.Context())
			if !verified {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			var d ResourceDecision
			var err error
			if token, bearer := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer "); bearer && p.JKT == "" {
				d, err = s.CanOn(r.Context(), token, permission, resource(r))
			} else if s.cfg.ClientSecret != "" {
				d, err = s.CanOnFor(r.Context(), p.Sub, permission, resource(r))
			} else {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			if errors.Is(err, ErrNotServed) {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			switch {
			case err != nil:
				http.Error(w, "authorization unavailable", http.StatusServiceUnavailable)
			case d.Allow:
				next.ServeHTTP(w, r)
			case d.MaxAge > 0:
				w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer error="insufficient_user_authentication", max_age="%d", acr_values="mfa"`, d.MaxAge))
				http.Error(w, "step-up required", http.StatusUnauthorized)
			default:
				http.Error(w, "forbidden", http.StatusForbidden)
			}
		})
	}
}
