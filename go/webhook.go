package gk

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"
)

// WebhookTolerance is how old a webhook's signature may be (INTEGRATION.md).
const WebhookTolerance = 5 * time.Minute

// ErrWebhookSignature is a webhook whose X-Gatekeeper-Signature doesn't verify.
var ErrWebhookSignature = errors.New("gatekeeper webhook: signature not valid")

// WebhookEvent is a delivered CloudEvent.
type WebhookEvent struct {
	ID      string          `json:"id"`
	Type    string          `json:"type"`
	Subject string          `json:"subject"`
	Time    time.Time       `json:"time"`
	Data    json.RawMessage `json:"data"`
}

// VerifyWebhook checks header (X-Gatekeeper-Signature: t=<unix>,v1=<hex>)
// over body with the webhook's whsec_ secret, refuses signatures older than
// WebhookTolerance, and decodes the event. Pass the raw body, not a re-encoding.
func VerifyWebhook(secret, header string, body []byte, now time.Time) (WebhookEvent, error) {
	var ev WebhookEvent
	var ts string
	var sigs [][]byte
	for _, p := range strings.Split(header, ",") {
		k, v, _ := strings.Cut(strings.TrimSpace(p), "=")
		switch k {
		case "t":
			ts = v
		case "v1":
			if b, err := hex.DecodeString(v); err == nil {
				sigs = append(sigs, b)
			}
		}
	}
	unix, err := strconv.ParseInt(ts, 10, 64)
	if err != nil || len(sigs) == 0 {
		return ev, ErrWebhookSignature
	}
	if age := now.Sub(time.Unix(unix, 0)); age > WebhookTolerance || age < -WebhookTolerance {
		return ev, ErrWebhookSignature
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(ts + "." + string(body)))
	want := mac.Sum(nil)
	ok := false
	for _, s := range sigs {
		ok = ok || hmac.Equal(s, want)
	}
	if !ok {
		return ev, ErrWebhookSignature
	}
	if err := json.Unmarshal(body, &ev); err != nil {
		return ev, ErrWebhookSignature
	}
	return ev, nil
}

// PushRequested is a sign-in waiting for the user's phone (ADR-0111): relay it
// to the user's devices through your push service so the app fetches it.
type PushRequested struct {
	UserID      string    `json:"user_id"`
	ChallengeID string    `json:"challenge_id"`
	ExpiresAt   time.Time `json:"expires_at"`
}

// PushRequested reads an mfa.push_requested event; ok is false for other types.
func (e WebhookEvent) PushRequested() (p PushRequested, ok bool) {
	if e.Type != "mfa.push_requested" || json.Unmarshal(e.Data, &p) != nil {
		return PushRequested{}, false
	}
	return p, p.UserID != "" && p.ChallengeID != ""
}
