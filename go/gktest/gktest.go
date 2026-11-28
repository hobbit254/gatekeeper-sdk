// Package gktest checks in your tests that every route has a Gatekeeper
// guard (FR-S20, ADR-0149): RequirePermission, RequirePermissionOn,
// RequireStepUp, or a deliberate Public or SignedIn. It reads the marks the
// guards leave and never calls a handler.
package gktest

import (
	"net/http"
	"slices"
	"sort"
	"strings"
	"testing"

	gk "github.com/hobbit254/gatekeeper-sdk/go"
)

// Route is one route to check. chi's chi.Walk gives these fields; a
// gktest.Mux records them as you register.
type Route struct {
	Method  string // "" when the pattern names none
	Pattern string
	Handler http.Handler
}

// Mux is an http.ServeMux that remembers what was registered, since a
// ServeMux can't list its routes. Use it where you build your router.
type Mux struct {
	*http.ServeMux
	routes []Route
}

// NewMux returns an empty recording mux.
func NewMux() *Mux { return &Mux{ServeMux: http.NewServeMux()} }

// Handle registers h for pattern ("GET /orders/{id}", as ServeMux takes it).
func (m *Mux) Handle(pattern string, h http.Handler) {
	m.ServeMux.Handle(pattern, h)
	method, path, ok := strings.Cut(pattern, " ")
	if !ok {
		method, path = "", pattern
	}
	m.routes = append(m.routes, Route{Method: method, Pattern: path, Handler: h})
}

// HandleFunc registers f for pattern.
func (m *Mux) HandleFunc(pattern string, f func(http.ResponseWriter, *http.Request)) {
	m.Handle(pattern, http.HandlerFunc(f))
}

// Routes is what was registered, in order.
func (m *Mux) Routes() []Route { return slices.Clone(m.routes) }

// Options tunes the check.
type Options struct {
	// Permissions are the manifest's keys; those no route guards are listed.
	Permissions []string
	// FailOnUnused fails the test when a permission is listed as unused.
	FailOnUnused bool
	// Ignore names routes to skip, as "METHOD /pattern" or "/pattern".
	Ignore []string
}

// Report is what Check found.
type Report struct {
	Unguarded []string // "METHOD /pattern"
	Unused    []string // permissions no route guards
}

// Check reports the routes with no guard, and the permissions no route uses.
func Check(routes []Route, opts Options) Report {
	var rep Report
	used := map[string]bool{}
	for _, r := range routes {
		name := strings.TrimSpace(r.Method + " " + r.Pattern)
		if slices.Contains(opts.Ignore, name) || slices.Contains(opts.Ignore, r.Pattern) {
			continue
		}
		g, ok := gk.GuardOf(r.Handler)
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
// Put the Gatekeeper guards outside other middleware, or make that
// middleware implement gk.Unwrapper, so the check can see them.
func AssertEveryRouteGuarded(t testing.TB, routes []Route, opts Options) {
	t.Helper()
	rep := Check(routes, opts)
	if len(rep.Unguarded) > 0 {
		t.Errorf("gktest: %d route(s) with no Gatekeeper guard (RequirePermission, RequirePermissionOn, RequireStepUp, Public or SignedIn):\n  %s",
			len(rep.Unguarded), strings.Join(rep.Unguarded, "\n  "))
	}
	if len(rep.Unused) > 0 {
		report := t.Logf
		if opts.FailOnUnused {
			report = t.Errorf
		}
		report("gktest: permission(s) no route guards (fine if your code checks them): %s", strings.Join(rep.Unused, ", "))
	}
}
