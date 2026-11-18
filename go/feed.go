package gk

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2" //nolint:depguard // retry jitter, not a secret
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// The revocation feed (FR-S17, ADR-0123): for APIs that can't reach
// Gatekeeper's Redis. A RevocationFeed is a Denylist: pass it to WithDenylist.

// ErrFeedStale is the feed not heard from within MaxStale (or never): tokens are refused.
var ErrFeedStale = errors.New("gk: the revocation feed is stale")

// FeedConfig configures a RevocationFeed. The client needs the revocations:read scope.
type FeedConfig struct {
	Issuer       string
	ClientID     string
	ClientSecret string
	// HTTPClient's Transport is used; its Timeout isn't (a stream stays open).
	HTTPClient *http.Client
	// MaxStale is how long without news before every token is refused (default 60 s, 10 s to 5 min).
	MaxStale time.Duration
}

// RevocationFeed keeps the tenant's denied sessions and tokens in memory.
type RevocationFeed struct {
	cfg    FeedConfig
	stream *http.Client
	mu     sync.Mutex
	denied map[string]time.Time // "sid:"+id or "jti:"+id -> until
	cursor string
	heard  time.Time
	token  string
	tokExp time.Time
}

// NewRevocationFeed returns a feed; call Run to start it.
func NewRevocationFeed(cfg FeedConfig) *RevocationFeed {
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = http.DefaultClient
	}
	switch {
	case cfg.MaxStale == 0:
		cfg.MaxStale = time.Minute
	case cfg.MaxStale < 10*time.Second:
		cfg.MaxStale = 10 * time.Second
	case cfg.MaxStale > 5*time.Minute:
		cfg.MaxStale = 5 * time.Minute
	}
	cfg.Issuer = strings.TrimRight(cfg.Issuer, "/")
	return &RevocationFeed{cfg: cfg, stream: &http.Client{Transport: cfg.HTTPClient.Transport}, denied: map[string]time.Time{}}
}

// Denied implements Denylist. It errs (so the token is refused) while the feed is stale.
func (f *RevocationFeed) Denied(_ context.Context, sid, jti string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	now := time.Now()
	if f.heard.IsZero() || now.Sub(f.heard) > f.cfg.MaxStale {
		return false, ErrFeedStale
	}
	for _, k := range []string{"sid:" + sid, "jti:" + jti} {
		if until, ok := f.denied[k]; ok && now.Before(until) && !strings.HasSuffix(k, ":") {
			return true, nil
		}
	}
	return false, nil
}

type revocation struct {
	Kind  string    `json:"kind"`
	Value string    `json:"value"`
	Until time.Time `json:"until"`
}

func (f *RevocationFeed) add(r revocation) {
	f.denied[r.Kind+":"+r.Value] = r.Until
}

// Run follows the feed until ctx ends: a snapshot, then the stream, reconnecting with backoff.
func (f *RevocationFeed) Run(ctx context.Context) {
	backoff := time.Second
	for ctx.Err() == nil {
		err := f.follow(ctx)
		if ctx.Err() != nil {
			return
		}
		if err == nil {
			backoff = time.Second // a clean close after the server's 10 minutes
			continue
		}
		wait := backoff/2 + rand.N(backoff/2+1) // #nosec G404 -- jitter, not a secret
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		backoff = min(backoff*2, 30*time.Second)
	}
}

func (f *RevocationFeed) follow(ctx context.Context) error {
	tok, err := f.accessToken(ctx)
	if err != nil {
		return err
	}
	f.mu.Lock()
	cursor := f.cursor
	f.mu.Unlock()
	if cursor == "" {
		if err := f.snapshot(ctx, tok); err != nil {
			return err
		}
	}
	return f.listen(ctx, tok)
}

func (f *RevocationFeed) snapshot(ctx context.Context, tok string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.cfg.Issuer+"/v1/revocations", nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := f.cfg.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		f.expireToken(resp.StatusCode)
		return fmt.Errorf("revocations snapshot: status %d", resp.StatusCode)
	}
	var snap struct {
		Items  []revocation `json:"items"`
		Cursor string       `json:"cursor"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&snap); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.denied = map[string]time.Time{}
	for _, r := range snap.Items {
		f.add(r)
	}
	f.cursor, f.heard = snap.Cursor, time.Now()
	return nil
}

func (f *RevocationFeed) listen(ctx context.Context, tok string) error {
	f.mu.Lock()
	cursor := f.cursor
	f.mu.Unlock()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.cfg.Issuer+"/v1/revocations/stream", nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("Last-Event-ID", cursor)
	resp, err := f.stream.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		f.expireToken(resp.StatusCode)
		return fmt.Errorf("revocations stream: status %d", resp.StatusCode)
	}
	sc := bufio.NewScanner(resp.Body)
	var id, event, data string
	for sc.Scan() {
		line := sc.Text()
		f.mu.Lock()
		f.heard = time.Now() // pings and events alike: the feed is alive
		f.mu.Unlock()
		switch {
		case line == "":
			if event == "reset" {
				f.mu.Lock()
				f.cursor = "" // the server no longer has our place: snapshot again
				f.mu.Unlock()
				return nil
			}
			var r revocation
			if data != "" && json.Unmarshal([]byte(data), &r) == nil {
				f.mu.Lock()
				f.add(r)
				if id != "" {
					f.cursor = id
				}
				f.mu.Unlock()
			}
			id, event, data = "", "", ""
		case strings.HasPrefix(line, "id: "):
			id = line[4:]
		case strings.HasPrefix(line, "event: "):
			event = line[7:]
		case strings.HasPrefix(line, "data: "):
			data = line[6:]
		}
	}
	return sc.Err()
}

func (f *RevocationFeed) expireToken(status int) {
	if status == http.StatusUnauthorized {
		f.mu.Lock()
		f.token = ""
		f.mu.Unlock()
	}
}

// accessToken is the client's revocations:read token, reused until a minute before it expires.
func (f *RevocationFeed) accessToken(ctx context.Context) (string, error) {
	f.mu.Lock()
	if f.token != "" && time.Now().Before(f.tokExp) {
		defer f.mu.Unlock()
		return f.token, nil
	}
	f.mu.Unlock()
	form := url.Values{"grant_type": {"client_credentials"}, "scope": {"revocations:read"}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, f.cfg.Issuer+"/oauth2/token", strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(url.QueryEscape(f.cfg.ClientID), url.QueryEscape(f.cfg.ClientSecret))
	resp, err := f.cfg.HTTPClient.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	var t struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if resp.StatusCode != http.StatusOK || json.NewDecoder(resp.Body).Decode(&t) != nil || t.AccessToken == "" {
		return "", fmt.Errorf("revocation feed: client credentials refused (status %d)", resp.StatusCode)
	}
	f.mu.Lock()
	f.token, f.tokExp = t.AccessToken, time.Now().Add(time.Duration(t.ExpiresIn)*time.Second-time.Minute)
	f.mu.Unlock()
	return t.AccessToken, nil
}
