// Command contractgen writes sdk/contract/vectors.json: a JWKS, a role map
// and signed tokens with the decision every SDK must reach (ADR-0038).
// Run from sdk/go: go run ./internal/contractgen > ../contract/vectors.json
package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"

	jose "github.com/go-jose/go-jose/v4"
)

const (
	issuer   = "https://auth.example.test/t/acme"
	audience = "notify-api"
	clientID = "notify-api"
	future   = 4102444800 // 2100-01-01
)

// stepUpCase checks RequireStepUp: fresh means amr has "mfa" and auth_time
// is within max_age seconds of now (ADR-0046).
type stepUpCase struct {
	Name   string `json:"name"`
	Token  string `json:"token"`
	MaxAge int    `json:"max_age"`
	Fresh  bool   `json:"fresh"`
}

// permStepUpCase checks RequirePermission with the role map's step_up
// windows (ADR-0097): expect is allow, deny (403) or step_up (401 with max_age).
type permStepUpCase struct {
	Name       string `json:"name"`
	Token      string `json:"token"`
	Permission string `json:"permission"`
	Expect     string `json:"expect"`
	MaxAge     int    `json:"max_age,omitempty"`
}

// amountCase checks CanAmount (ADR-0143): allow within the alone limit,
// approval_required above it, deny when the permission isn't held.
type amountCase struct {
	Name       string `json:"name"`
	Token      string `json:"token"`
	Permission string `json:"permission"`
	Amount     int64  `json:"amount"`
	Expect     string `json:"expect"`
}

type testCase struct {
	Name       string `json:"name"`
	Token      string `json:"token"`
	Permission string `json:"permission,omitempty"`
	// Expect is allow or deny (token valid), or reject (token invalid).
	Expect string `json:"expect"`
}

func main() {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pub := jose.JSONWebKey{Key: &key.PublicKey, KeyID: "contract-1", Algorithm: "ES256", Use: "sig"}

	claims := func(edit func(map[string]any)) map[string]any {
		c := map[string]any{"iss": issuer, "sub": "0192f3a1-7c2e-7d3a-9b1f-3a4c5d6e7f80", "aud": []string{audience},
			"exp": future, "iat": 1700000000, "client_id": "web", "tid": "0192f3a1-0000-7000-8000-000000000001",
			"roles": []string{"viewer"}, "rv": 3, "scope": "openid profile", "amr": []string{"pwd"}, "auth_time": 1700000000,
			"jti": "contract", "sid": "session-1"}
		if edit != nil {
			edit(c)
		}
		return c
	}
	sign := func(k *ecdsa.PrivateKey, kid, typ string, c map[string]any) string {
		opts := (&jose.SignerOptions{}).WithType(jose.ContentType(typ)).WithHeader("kid", kid)
		s, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: k}, opts)
		must(err)
		payload, _ := json.Marshal(c)
		jws, err := s.Sign(payload)
		must(err)
		out, err := jws.CompactSerialize()
		must(err)
		return out
	}
	good := func(edit func(map[string]any)) string { return sign(key, "contract-1", "at+jwt", claims(edit)) }
	b64 := func(v any) string { b, _ := json.Marshal(v); return base64.RawURLEncoding.EncodeToString(b) }

	viewer := good(nil)
	parts := strings.Split(viewer, ".")
	tampered := parts[0] + "." + b64(claims(func(c map[string]any) { c["roles"] = []string{"admin"} })) + "." + parts[2]
	pubJSON, _ := pub.MarshalJSON()
	hsHead := b64(map[string]any{"alg": "HS256", "typ": "at+jwt", "kid": "contract-1"})
	hsBody := b64(claims(nil))
	mac := hmac.New(sha256.New, pubJSON)
	mac.Write([]byte(hsHead + "." + hsBody))
	hs256 := hsHead + "." + hsBody + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	none := b64(map[string]any{"alg": "none", "typ": "at+jwt", "kid": "contract-1"}) + "." + hsBody + "."

	cases := []testCase{
		{"viewer may read", viewer, "subscriber:read", "allow"},
		{"viewer may not delete", viewer, "subscriber:delete", "deny"},
		{"admin may delete", good(func(c map[string]any) { c["roles"] = []string{"admin"} }), "subscriber:delete", "allow"},
		{"roles combine", good(func(c map[string]any) { c["roles"] = []string{"viewer", "billing"} }), "invoice:read", "allow"},
		{"unknown role grants nothing", good(func(c map[string]any) { c["roles"] = []string{"ghost"} }), "subscriber:read", "deny"},
		{"no wildcard matching in SDKs", viewer, "subscriber:*", "deny"},
		{"aud as a single string", good(func(c map[string]any) { c["aud"] = audience }), "subscriber:read", "allow"},
		{"wrong audience", good(func(c map[string]any) { c["aud"] = []string{"other-api"} }), "subscriber:read", "reject"},
		{"wrong issuer", good(func(c map[string]any) { c["iss"] = "https://auth.example.test/t/evil" }), "subscriber:read", "reject"},
		{"expired", good(func(c map[string]any) { c["exp"] = 946684800 }), "subscriber:read", "reject"},
		{"tampered payload", tampered, "subscriber:read", "reject"},
		{"signed by an unknown key", sign(other, "contract-1", "at+jwt", claims(nil)), "subscriber:read", "reject"},
		{"unknown kid", sign(other, "contract-9", "at+jwt", claims(nil)), "subscriber:read", "reject"},
		{"HS256 with the public key as secret", hs256, "subscriber:read", "reject"},
		{"alg none", none, "subscriber:read", "reject"},
		{"ID token is not an access token", sign(key, "contract-1", "JWT", claims(nil)), "subscriber:read", "reject"},
		{"garbage", "not.a.jwt", "subscriber:read", "reject"},
	}
	soon := int64(4102444000) // in 2100: always within any window
	stepUps := []stepUpCase{
		{"password + TOTP, recent", good(func(c map[string]any) { c["amr"] = []string{"pwd", "otp", "mfa"}; c["auth_time"] = soon }), 600, true},
		{"password + TOTP, long ago", good(func(c map[string]any) { c["amr"] = []string{"pwd", "otp", "mfa"} }), 600, false},
		{"password only, recent", good(func(c map[string]any) { c["auth_time"] = soon }), 600, false},
		{"SMS code is a single factor", good(func(c map[string]any) { c["amr"] = []string{"otp", "sms"}; c["auth_time"] = soon }), 600, false},
	}
	admin := func(edit func(map[string]any)) string {
		return good(func(c map[string]any) {
			c["roles"] = []string{"admin"}
			if edit != nil {
				edit(c)
			}
		})
	}
	permStepUps := []permStepUpCase{
		{"MFA within the permission's window", admin(func(c map[string]any) { c["amr"] = []string{"pwd", "otp", "mfa"}; c["auth_time"] = soon }), "subscriber:delete", "allow", 0},
		{"MFA long ago", admin(func(c map[string]any) { c["amr"] = []string{"pwd", "otp", "mfa"} }), "subscriber:delete", "step_up", 300},
		{"no second factor", admin(func(c map[string]any) { c["auth_time"] = soon }), "subscriber:delete", "step_up", 300},
		{"a permission without a window", admin(nil), "subscriber:read", "allow", 0},
		{"not granted", viewer, "subscriber:delete", "deny", 0},
		{"a machine token is never asked", admin(func(c map[string]any) { delete(c, "amr"); delete(c, "auth_time") }), "subscriber:delete", "allow", 0},
	}
	// Entitlements (ADR-0098): the plan and features ride in the token.
	entitlements := map[string]any{
		"token": good(func(c map[string]any) {
			c["entitlements"] = map[string]any{"plan": "pro", "features": []string{"bulk_sms", "reports"}}
		}),
		"plan": "pro", "features": []string{"bulk_sms", "reports"},
		"has": []string{"bulk_sms", "reports"}, "lacks": []string{"sso", "bulk"},
		"plain": viewer,
	}
	// Denylist cases (ADR-0048): the checker denies sid "session-denied" and jti "jti-denied".
	denyCases := []testCase{
		{"live session", viewer, "subscriber:read", "allow"},
		{"denied session", good(func(c map[string]any) { c["sid"] = "session-denied" }), "subscriber:read", "reject"},
		{"denied jti", good(func(c map[string]any) { c["jti"] = "jti-denied" }), "subscriber:read", "reject"},
	}
	// Impersonation (ADR-0058): act names the admin and when the window ends.
	impersonation := map[string]any{
		"token": good(func(c map[string]any) {
			c["act"] = map[string]any{"sub": "0192f3a1-aaaa-7000-8000-00000000000a", "ends_at": 4102444000}
		}),
		"actor":   "0192f3a1-aaaa-7000-8000-00000000000a",
		"ends_at": 4102444000,
		"plain":   viewer,
	}
	// API keys (ADR-0057, ADR-0059): POST {issuer}/oauth2/introspect with the
	// client's Basic credentials, form token=<key>; unknown keys are inactive.
	liveKey, deadKey := "gk_live_"+"0123456789abcdefghijABCDEFGHIJ01", "gk_live_"+"ZYXWVUTSRQponmlkjihgfedcba987654"
	apiKeys := map[string]any{
		"introspection": map[string]any{
			liveKey: map[string]any{"active": true, "token_type": "api_key", "sub": "0192f3a1-7c2e-7d3a-9b1f-3a4c5d6e7f80",
				"owner_type": "user", "scope": "subscriber:*", "exp": 4102444800, "permissions": []string{"subscriber:read"}},
			deadKey: map[string]any{"active": false},
		},
		"cases": []testCase{
			{"active key, granted permission", liveKey, "subscriber:read", "allow"},
			{"active key, permission outside it", liveKey, "subscriber:delete", "deny"},
			{"revoked key", deadKey, "subscriber:read", "reject"},
			{"unknown key", "gk_live_" + "00000000000000000000000000000000", "subscriber:read", "reject"},
		},
		"subject": "0192f3a1-7c2e-7d3a-9b1f-3a4c5d6e7f80",
	}
	// Organization roles (ADR-0142): a token in an organization carries org,
	// orv and org/<name> roles; the SDK fetches that organization's role map
	// ({role-map}?org=<slug>) and caches it by (org, rv, orv).
	inOrg := func(roles []string, org string, orv int) string {
		return good(func(c map[string]any) {
			c["roles"] = roles
			if org != "" {
				c["org"], c["orv"] = org, orv
			}
		})
	}
	tenantRoles := map[string][]string{"viewer": {"subscriber:read"}, "admin": {"subscriber:read", "subscriber:delete"}, "billing": {"invoice:read"},
		"cashier": {"invoice:read", "invoice:pay"}, "manager": {"invoice:pay"}, "payer": {"invoice:pay"}}
	// Amount limits (ADR-0143): invoice:pay carries one, in minor units; a
	// role giving it with no limit listed (payer) is unlimited.
	n := func(v int64) *int64 { return &v }
	type limit struct {
		Alone    *int64 `json:"alone,omitempty"`
		Approves *int64 `json:"approves,omitempty"`
	}
	tenantLimits := map[string]map[string]limit{"cashier": {"invoice:pay": {n(2000), n(0)}}, "manager": {"invoice:pay": {n(10000), nil}}}
	acmeLimits := map[string]map[string]limit{"cashier": {"invoice:pay": {n(5000), n(0)}}, "manager": tenantLimits["manager"]} // acme overrides cashier
	acmeRoles := map[string][]string{"org/till-lead": {"subscriber:read", "invoice:read"}}
	for k, v := range tenantRoles {
		acmeRoles[k] = v
	}
	orgRoles := map[string]any{
		"role_maps": map[string]any{
			"acme": map[string]any{"client_id": clientID, "rv": 3, "org": "acme", "orv": 2, "roles": acmeRoles, "step_up": map[string]int{"subscriber:delete": 300},
				"limited": []string{"invoice:pay"}, "limits": acmeLimits, "currency": "UGX"},
			"globex": map[string]any{"client_id": clientID, "rv": 3, "org": "globex", "orv": 1, "roles": tenantRoles, "step_up": map[string]int{"subscriber:delete": 300},
				"limited": []string{"invoice:pay"}, "limits": tenantLimits, "currency": "KES"},
		},
		"cases": []testCase{
			{"an org role resolves in its organization", inOrg([]string{"org/till-lead"}, "acme", 2), "invoice:read", "allow"},
			{"tenant roles still resolve in an organization", inOrg([]string{"viewer"}, "acme", 2), "subscriber:read", "allow"},
			{"tenant and org roles combine", inOrg([]string{"viewer", "org/till-lead"}, "acme", 2), "invoice:read", "allow"},
			{"an org role gives only what it holds", inOrg([]string{"org/till-lead"}, "acme", 2), "subscriber:delete", "deny"},
			{"an org role without its organization grants nothing", inOrg([]string{"org/till-lead"}, "", 0), "invoice:read", "deny"},
			{"another organization's role of that name grants nothing", inOrg([]string{"org/till-lead"}, "globex", 1), "invoice:read", "deny"},
		},
	}
	as := func(roles ...string) string { return inOrg(roles, "", 0) }
	amountLimits := map[string]any{
		"cases": []amountCase{
			{"within alone", as("cashier"), "invoice:pay", 1500, "allow"},
			{"exactly alone", as("cashier"), "invoice:pay", 2000, "allow"},
			{"above alone needs approval", as("cashier"), "invoice:pay", 2001, "approval_required"},
			{"the most generous role wins", as("cashier", "manager"), "invoice:pay", 9000, "allow"},
			{"a role with no limit set is unlimited", as("cashier", "payer"), "invoice:pay", 999999999, "allow"},
			{"not held", as("viewer"), "invoice:pay", 1, "deny"},
			{"a permission without a limit ignores the amount", as("cashier"), "invoice:read", 999999999, "allow"},
			{"an organization's override in it", inOrg([]string{"cashier"}, "acme", 2), "invoice:pay", 4000, "allow"},
			{"never another organization's", inOrg([]string{"cashier"}, "globex", 1), "invoice:pay", 4000, "approval_required"},
		},
		"currency": map[string]string{"tenant": "KES", "acme": "UGX"},
	}
	// DPoP (RFC 9449, ADR-0070): the token is bound to dkey; check the cases
	// in order with one replay cache, at time now, for a GET of url.
	dkey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	dother, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tp, err := (&jose.JSONWebKey{Key: &dkey.PublicKey}).Thumbprint(crypto.SHA256)
	must(err)
	jkt := base64.RawURLEncoding.EncodeToString(tp)
	bound := good(func(c map[string]any) { c["cnf"] = map[string]any{"jkt": jkt} })
	const now, target = 1700000000, "https://api.example.test/orders"
	ath := func(tok string) string {
		sum := sha256.Sum256([]byte(tok))
		return base64.RawURLEncoding.EncodeToString(sum[:])
	}
	proof := func(k *ecdsa.PrivateKey, typ, htm, htu string, iat int64, jti, ath string) string {
		opts := (&jose.SignerOptions{}).WithType(jose.ContentType(typ)).WithHeader("jwk", jose.JSONWebKey{Key: &k.PublicKey, Algorithm: "ES256"})
		sg, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: k}, opts)
		must(err)
		c := map[string]any{"htm": htm, "htu": htu, "iat": iat, "jti": jti}
		if ath != "" {
			c["ath"] = ath
		}
		payload, _ := json.Marshal(c)
		jws, err := sg.Sign(payload)
		must(err)
		out, err := jws.CompactSerialize()
		must(err)
		return out
	}
	valid := proof(dkey, "dpop+jwt", "GET", target, now, "jti-1", ath(bound))
	dpopCases := []map[string]any{
		{"name": "valid proof", "proof": valid, "expect": "allow"},
		{"name": "replayed proof", "proof": valid, "expect": "reject"},
		{"name": "another key", "proof": proof(dother, "dpop+jwt", "GET", target, now, "jti-2", ath(bound)), "expect": "reject"},
		{"name": "another method", "proof": proof(dkey, "dpop+jwt", "POST", target, now, "jti-3", ath(bound)), "expect": "reject"},
		{"name": "another URL", "proof": proof(dkey, "dpop+jwt", "GET", "https://api.example.test/admin", now, "jti-4", ath(bound)), "expect": "reject"},
		{"name": "another token's ath", "proof": proof(dkey, "dpop+jwt", "GET", target, now, "jti-5", ath(viewer)), "expect": "reject"},
		{"name": "no ath", "proof": proof(dkey, "dpop+jwt", "GET", target, now, "jti-6", ""), "expect": "reject"},
		{"name": "too old", "proof": proof(dkey, "dpop+jwt", "GET", target, now-300, "jti-7", ath(bound)), "expect": "reject"},
		{"name": "from the future", "proof": proof(dkey, "dpop+jwt", "GET", target, now+300, "jti-8", ath(bound)), "expect": "reject"},
		{"name": "not typ dpop+jwt", "proof": proof(dkey, "JWT", "GET", target, now, "jti-9", ath(bound)), "expect": "reject"},
		{"name": "no proof", "proof": "", "expect": "reject"},
		{"name": "a fresh valid proof", "proof": proof(dkey, "dpop+jwt", "GET", target, now+30, "jti-10", ath(bound)), "expect": "allow"},
	}
	dpop := map[string]any{
		"token": bound, "jkt": jkt, "now": now, "method": "GET",
		"url":   target + "?page=2", // the query is not part of htu
		"cases": dpopCases,
	}
	out := map[string]any{
		"description": "Shared SDK contract, test data only: the keys, tokens, API keys and secret here were made for these tests and protect nothing. Fetch JWKS from {issuer}/.well-known/jwks.json and the role map from " +
			"{issuer}/v1/clients/{client_id}/role-map (with ?org=<slug>, from org_roles.role_maps, 404 for any other slug); serve both from this file. Generated by go/internal/contractgen.",
		"issuer": issuer, "audience": audience, "client_id": clientID, "client_secret": "contract-secret",
		"jwks": jose.JSONWebKeySet{Keys: []jose.JSONWebKey{pub}},
		"role_map": map[string]any{"client_id": clientID, "rv": 3, "roles": map[string][]string{
			"viewer": {"subscriber:read"}, "admin": {"subscriber:read", "subscriber:delete"}, "billing": {"invoice:read"},
			"cashier": {"invoice:read", "invoice:pay"}, "manager": {"invoice:pay"}, "payer": {"invoice:pay"}},
			"step_up":  map[string]int{"subscriber:delete": 300}, // ADR-0097
			"limited":  []string{"invoice:pay"},                  // ADR-0143
			"limits":   tenantLimits,
			"currency": "KES"},
		"cases":              cases,
		"step_up":            stepUps,
		"permission_step_up": permStepUps,
		"denylist":           map[string]any{"sids": []string{"session-denied"}, "jtis": []string{"jti-denied"}, "cases": denyCases},
		"impersonation":      impersonation,
		"api_keys":           apiKeys,
		"dpop":               dpop,
		"entitlements":       entitlements,
		"org_roles":          orgRoles,
		"amount_limits":      amountLimits,
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	must(enc.Encode(out))
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
