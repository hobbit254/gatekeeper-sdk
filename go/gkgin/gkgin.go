// Package gkgin is the Gatekeeper SDK for gin (FR-S20, ADR-0153): token
// verification, permission guards, and a test that fails when a route has
// no guard. The guards wrap the route's handler, so the guard is what gin
// reports for the route:
//
//	r.Use(gkgin.Middleware(sdk))
//	r.GET("/orders", gkgin.RequirePermission("order:read", listOrders))
//	r.GET("/health", gkgin.Public(health))
//
// A guard set only on a group isn't seen by the test: wrap the handler.
package gkgin

import (
	"context"
	"net/http"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
	"unsafe"

	"github.com/gin-gonic/gin"

	gk "github.com/hobbit254/gatekeeper-sdk/go"
)

// marks records the guard each wrapper made by this package carries, by the
// wrapper's identity (its closure), so the test can read it back from the
// handler gin reports.
var marks sync.Map // uintptr -> gk.Guard

// funcID is a handler value's identity: its closure, which is distinct for
// every wrapper this package returns even when they share code.
func funcID(h gin.HandlerFunc) uintptr {
	return uintptr(*(*unsafe.Pointer)(unsafe.Pointer(&h))) // #nosec G103 -- reads a func value's closure pointer; never written
}

func marked(g gk.Guard, h gin.HandlerFunc) gin.HandlerFunc {
	marks.Store(funcID(h), g)
	return h
}

// GuardOf is the guard a handler from this package carries.
func GuardOf(h gin.HandlerFunc) (gk.Guard, bool) {
	if h == nil {
		return gk.Guard{}, false
	}
	g, ok := marks.Load(funcID(h))
	if !ok {
		return gk.Guard{}, false
	}
	return g.(gk.Guard), true
}

// Middleware verifies the access token as sdk.Middleware does and stores the
// Principal (gk.FromContext(c.Request.Context())); failures answer 401 and abort.
func Middleware(sdk *gk.SDK) gin.HandlerFunc {
	return adapt(sdk.Middleware(), nil)
}

// adapt runs a net/http guard; when it lets the request through, then runs
// (or, with none, the rest of the chain runs).
func adapt(guard func(http.Handler) http.Handler, then gin.HandlerFunc) gin.HandlerFunc {
	return func(c *gin.Context) {
		passed := false
		guard(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			passed, c.Request = true, r
		})).ServeHTTP(c.Writer, c.Request)
		switch {
		case !passed:
			c.Abort()
		case then != nil:
			then(c)
		default:
			c.Next()
		}
	}
}

// RequirePermission answers 403 unless the Principal holds permission (401
// with the step-up challenge when its window has passed), else runs h.
func RequirePermission(permission string, h gin.HandlerFunc) gin.HandlerFunc {
	return marked(gk.Guard{Kind: gk.GuardPermission, Permission: permission}, adapt(gk.RequirePermission(permission), h))
}

// RequirePermissionOn checks permission on the resource the request names
// with Gatekeeper, as sdk.RequirePermissionOn does, else runs h.
func RequirePermissionOn(sdk *gk.SDK, permission string, resource func(*gin.Context) string, h gin.HandlerFunc) gin.HandlerFunc {
	guard := sdk.RequirePermissionOn(permission, func(r *http.Request) string {
		c, _ := r.Context().Value(ginKey{}).(*gin.Context)
		return resource(c)
	})
	inner := adapt(guard, h)
	return marked(gk.Guard{Kind: gk.GuardResource, Permission: permission}, func(c *gin.Context) {
		c.Request = c.Request.WithContext(context.WithValue(c.Request.Context(), ginKey{}, c)) // per request: no shared state
		inner(c)
	})
}

type ginKey struct{}

// Public marks a route as deliberately open; it changes nothing at run time.
func Public(h gin.HandlerFunc) gin.HandlerFunc {
	return marked(gk.Guard{Kind: gk.GuardPublic}, func(c *gin.Context) { h(c) })
}

// SignedIn marks a route any valid token may call; 401 without the Principal.
func SignedIn(h gin.HandlerFunc) gin.HandlerFunc {
	return marked(gk.Guard{Kind: gk.GuardSignedIn}, adapt(gk.SignedIn(), h))
}

// Options tunes the check.
type Options struct {
	Permissions  []string // the manifest's keys; those no route guards are listed
	FailOnUnused bool
	Ignore       []string // "GET /health" or "/health"
}

// Report is what Check found.
type Report struct {
	Unguarded []string
	Unused    []string
}

// Check reports engine's routes with no guard, and the permissions no route uses.
func Check(engine *gin.Engine, opts Options) Report {
	var rep Report
	used := map[string]bool{}
	for _, r := range engine.Routes() {
		name := r.Method + " " + r.Path
		if slices.Contains(opts.Ignore, name) || slices.Contains(opts.Ignore, r.Path) {
			continue
		}
		g, ok := GuardOf(r.HandlerFunc)
		if !ok {
			rep.Unguarded = append(rep.Unguarded, name)
			continue
		}
		if g.Permission != "" {
			used[g.Permission] = true
		}
	}
	for _, p := range opts.Permissions {
		if !used[p] {
			rep.Unused = append(rep.Unused, p)
		}
	}
	sort.Strings(rep.Unguarded)
	sort.Strings(rep.Unused)
	return rep
}

// AssertEveryRouteGuarded fails t, listing them, when a route has no guard.
func AssertEveryRouteGuarded(t testing.TB, engine *gin.Engine, opts Options) {
	t.Helper()
	rep := Check(engine, opts)
	if len(rep.Unguarded) > 0 {
		t.Errorf("gkgin: %d route(s) with no Gatekeeper guard (wrap the handler in RequirePermission, RequirePermissionOn, Public or SignedIn):\n  %s",
			len(rep.Unguarded), strings.Join(rep.Unguarded, "\n  "))
	}
	if len(rep.Unused) > 0 {
		report := t.Logf
		if opts.FailOnUnused {
			report = t.Errorf
		}
		report("gkgin: permission(s) no route guards (fine if your code checks them): %s", strings.Join(rep.Unused, ", "))
	}
}
