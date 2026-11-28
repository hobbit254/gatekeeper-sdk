package gk

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

// Second-person approvals (FR-Z21, ADR-0145): Gatekeeper signs a 2-minute
// approval of one action, bound to its permission, resource and amount, and
// spends it once. VerifyApproval checks one offline, for showing it;
// SpendApproval spends it, last, in the commit path of the action.

// Approval is a verified approval token.
type Approval struct {
	ID         string // the approval's id (jti)
	Approver   string // sub
	Requester  string // req
	ClientID   string // aud: the requester's client
	Permission string
	Resource   string
	Amount     *int64 // minor units; nil for a permission without a limit
	Currency   string
	OrgID      string
	Method     string // pin or mfa
	ExpiresAt  time.Time
}

// Approval errors.
var (
	// ErrApprovalClosed is an approval already spent, or expired (409).
	ErrApprovalClosed = errors.New("gk: approval already spent or expired")
	// ErrApprovalMismatch is an approval for another permission, resource,
	// amount, client or requester, or one Gatekeeper didn't sign (422).
	ErrApprovalMismatch = errors.New("gk: approval does not match the action")
)

// VerifyApproval checks raw offline for p's request: signed by the tenant's
// published key with typ approval+jwt, this issuer, unexpired, for p's
// client and requested by p. It doesn't spend it; only SpendApproval does.
func (s *SDK) VerifyApproval(ctx context.Context, raw string, p *Principal) (*Approval, error) {
	jws, err := jose.ParseSigned(raw, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil || len(jws.Signatures) != 1 {
		return nil, fmt.Errorf("%w: parse", ErrApprovalMismatch)
	}
	h := jws.Signatures[0].Protected
	if typ, _ := h.ExtraHeaders[jose.HeaderType].(string); !strings.EqualFold(typ, "approval+jwt") {
		return nil, fmt.Errorf("%w: typ", ErrApprovalMismatch)
	}
	key, err := s.key(ctx, h.KeyID)
	if err != nil {
		return nil, err
	}
	payload, err := jws.Verify(key)
	if err != nil {
		return nil, fmt.Errorf("%w: signature", ErrApprovalMismatch)
	}
	var c struct {
		Iss  string `json:"iss"`
		Aud  string `json:"aud"`
		JTI  string `json:"jti"`
		Sub  string `json:"sub"`
		Req  string `json:"req"`
		Perm string `json:"perm"`
		Res  string `json:"res"`
		Amt  *int64 `json:"amt"`
		Cur  string `json:"cur"`
		Org  string `json:"org"`
		Meth string `json:"method"`
		Exp  int64  `json:"exp"`
	}
	if err := json.Unmarshal(payload, &c); err != nil {
		return nil, fmt.Errorf("%w: claims", ErrApprovalMismatch)
	}
	switch {
	case c.Iss != s.cfg.Issuer:
		return nil, fmt.Errorf("%w: iss", ErrApprovalMismatch)
	case s.now().After(time.Unix(c.Exp, 0).Add(s.cfg.Leeway)):
		return nil, ErrApprovalClosed
	case p == nil || c.Aud != p.ClientID || c.Req != p.Sub:
		return nil, fmt.Errorf("%w: not this user's request", ErrApprovalMismatch)
	}
	return &Approval{ID: c.JTI, Approver: c.Sub, Requester: c.Req, ClientID: c.Aud, Permission: c.Perm, Resource: c.Res,
		Amount: c.Amt, Currency: c.Cur, OrgID: c.Org, Method: c.Meth, ExpiresAt: time.Unix(c.Exp, 0)}, nil
}

// SpendApproval spends raw once for permission on resource with amount (nil
// for none), with accessToken: the requester's own token, or a client
// credentials token of the approval's client. Call it last, so the action
// commits only when the spend succeeded.
func (s *SDK) SpendApproval(ctx context.Context, accessToken, raw, permission, resource string, amount *int64) (*Approval, error) {
	body := map[string]any{"token": raw, "permission": permission, "resource": resource}
	if amount != nil {
		body["amount"] = *amount
	}
	b, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.cfg.Issuer+"/v1/approvals/spend", bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err := s.cfg.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCheckUnavailable, err)
	}
	defer func() { _ = resp.Body.Close() }()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusConflict:
		return nil, ErrApprovalClosed
	case http.StatusUnprocessableEntity, http.StatusForbidden:
		return nil, ErrApprovalMismatch
	default:
		return nil, fmt.Errorf("%w: status %d", ErrCheckUnavailable, resp.StatusCode)
	}
	var out struct {
		ID         string `json:"approval_id"`
		Approver   string `json:"approver_id"`
		Requester  string `json:"requester_id"`
		ClientID   string `json:"client_id"`
		Permission string `json:"permission"`
		Resource   string `json:"resource"`
		Amount     *int64 `json:"amount"`
		Currency   string `json:"currency"`
		OrgID      string `json:"org_id"`
		Method     string `json:"method"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCheckUnavailable, err)
	}
	return &Approval{ID: out.ID, Approver: out.Approver, Requester: out.Requester, ClientID: out.ClientID, Permission: out.Permission,
		Resource: out.Resource, Amount: out.Amount, Currency: out.Currency, OrgID: out.OrgID, Method: out.Method}, nil
}
