package gk_test

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"
	"testing"
	"time"

	gk "github.com/hobbit254/gatekeeper-sdk/go"
)

// FR-A27 (ADR-0111): products verify the webhook and relay pending pushes.
func sign(secret string, at time.Time, body string) string {
	ts := strconv.FormatInt(at.Unix(), 10)
	m := hmac.New(sha256.New, []byte(secret))
	m.Write([]byte(ts + "." + body))
	return "t=" + ts + ",v1=" + hex.EncodeToString(m.Sum(nil))
}

func TestVerifyWebhookAndReadAPushRequest(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	body := `{"id":"e1","type":"mfa.push_requested","subject":"u1","time":"2027-01-15T08:00:00Z",` +
		`"data":{"user_id":"u1","challenge_id":"c1","expires_at":"2027-01-15T08:02:00Z"}}`
	ev, err := gk.VerifyWebhook("whsec_x", sign("whsec_x", now, body), []byte(body), now)
	if err != nil {
		t.Fatal(err)
	}
	p, ok := ev.PushRequested()
	if !ok || p.UserID != "u1" || p.ChallengeID != "c1" || p.ExpiresAt.IsZero() {
		t.Fatalf("push = %+v %v", p, ok)
	}
	for name, c := range map[string]struct {
		header, body string
		at           time.Time
	}{
		"wrong secret":  {sign("whsec_y", now, body), body, now},
		"edited body":   {sign("whsec_x", now, body), body + " ", now},
		"too old":       {sign("whsec_x", now.Add(-6*time.Minute), body), body, now},
		"no signature":  {"t=" + strconv.FormatInt(now.Unix(), 10), body, now},
		"empty header":  {"", body, now},
		"from the past": {sign("whsec_x", now, body), body, now.Add(6 * time.Minute)},
	} {
		if _, err := gk.VerifyWebhook("whsec_x", c.header, []byte(c.body), c.at); !errors.Is(err, gk.ErrWebhookSignature) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	if _, ok := (gk.WebhookEvent{Type: "user.created"}).PushRequested(); ok {
		t.Error("other types aren't pushes")
	}
}
