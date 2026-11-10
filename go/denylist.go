package gk

import (
	"context"

	"github.com/redis/go-redis/v9"
)

// Denylist answers whether a token's session or jti was revoked before the
// token expired (FR-S7, ADR-0048).
type Denylist interface {
	Denied(ctx context.Context, sid, jti string) (bool, error)
}

// WithDenylist makes Verify refuse revoked tokens, one lookup per request.
// Errors refuse too (fail closed).
func (s *SDK) WithDenylist(d Denylist) *SDK {
	s.deny = d
	return s
}

// RedisDenylist reads Gatekeeper's denylist keys from the shared Redis:
// gk:deny:sid:<sid> and gk:deny:jti:<jti>.
func RedisDenylist(c *redis.Client) Denylist { return redisDenylist{c} }

type redisDenylist struct{ c *redis.Client }

func (r redisDenylist) Denied(ctx context.Context, sid, jti string) (bool, error) {
	var keys []string
	if sid != "" {
		keys = append(keys, "gk:deny:sid:"+sid)
	}
	if jti != "" {
		keys = append(keys, "gk:deny:jti:"+jti)
	}
	if len(keys) == 0 {
		return false, nil
	}
	n, err := r.c.Exists(ctx, keys...).Result()
	return n > 0, err
}
