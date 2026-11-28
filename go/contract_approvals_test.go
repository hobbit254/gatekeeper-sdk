package gk

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"slices"
	"testing"
)

// Contract vectors for approval tokens and support-session modes (ADR-0152).
type moreVectors struct {
	Approvals struct {
		Principal struct {
			Sub      string `json:"sub"`
			ClientID string `json:"client_id"`
		} `json:"principal"`
		Cases []struct {
			Name, Token, Expect string
			Approval            struct {
				ID, Approver, Requester, Permission, Resource, Currency, Method string
				Amount                                                          *int64
			} `json:"approval"`
		} `json:"cases"`
	} `json:"approvals"`
	SupportModes struct {
		RoleMap json.RawMessage `json:"role_map"`
		Cases   []struct {
			Name, Map, Token string
			ActorMode        string   `json:"actor_mode"`
			Permissions      []string `json:"permissions"`
		} `json:"cases"`
	} `json:"support_modes"`
}

func loadMoreVectors(t *testing.T) (vectors, moreVectors) {
	t.Helper()
	raw, err := os.ReadFile("../contract/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v vectors
	var m moreVectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	return v, m
}

func TestContractApprovals(t *testing.T) {
	v, m := loadMoreVectors(t)
	p := &Principal{Sub: m.Approvals.Principal.Sub, ClientID: m.Approvals.Principal.ClientID}
	for _, c := range m.Approvals.Cases {
		t.Run(c.Name, func(t *testing.T) {
			sdk := New(Config{Issuer: v.Issuer, Audience: v.Audience, ClientID: v.ClientID, HTTPClient: &http.Client{Transport: fixedServer{v}}})
			a, err := sdk.VerifyApproval(context.Background(), c.Token, p)
			got := "ok"
			switch {
			case errors.Is(err, ErrApprovalClosed):
				got = "closed"
			case errors.Is(err, ErrApprovalMismatch):
				got = "mismatch"
			case err != nil:
				t.Fatalf("unexpected error: %v", err)
			}
			if got != c.Expect {
				t.Fatalf("got %s, want %s (err %v)", got, c.Expect, err)
			}
			if got != "ok" {
				return
			}
			w := c.Approval
			if a.ID != w.ID || a.Approver != w.Approver || a.Requester != w.Requester || a.Permission != w.Permission ||
				a.Resource != w.Resource || a.Currency != w.Currency || a.Method != w.Method || (a.Amount == nil) != (w.Amount == nil) ||
				(a.Amount != nil && *a.Amount != *w.Amount) {
				t.Fatalf("read back %+v, want %+v", a, w)
			}
		})
	}
}

func TestContractSupportModes(t *testing.T) {
	v, m := loadMoreVectors(t)
	for _, c := range m.SupportModes.Cases {
		t.Run(c.Name, func(t *testing.T) {
			served := v
			if c.Map == "support" {
				served.RoleMap = m.SupportModes.RoleMap
			}
			sdk := New(Config{Issuer: v.Issuer, Audience: v.Audience, ClientID: v.ClientID, ClientSecret: v.ClientSecret,
				HTTPClient: &http.Client{Transport: fixedServer{served}}})
			p, err := sdk.Verify(context.Background(), c.Token)
			if err != nil {
				t.Fatal(err)
			}
			got := slices.Clone(p.Permissions)
			slices.Sort(got)
			want := slices.Clone(c.Permissions)
			slices.Sort(want)
			if p.ActorMode != c.ActorMode || !slices.Equal(got, want) {
				t.Fatalf("mode %q permissions %v, want %q %v", p.ActorMode, got, c.ActorMode, want)
			}
		})
	}
}
