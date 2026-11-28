package gk

import "net/http"

// Route guard marks (FR-S20, ADR-0149): every guard this package returns
// says what it is, so gktest.AssertEveryRouteGuarded can find a route that
// has none without running it.

// Guard kinds.
const (
	GuardPermission = "permission" // RequirePermission
	GuardResource   = "resource"   // RequirePermissionOn
	GuardStepUp     = "step-up"    // RequireStepUp
	GuardPublic     = "public"     // Public: deliberately open
	GuardSignedIn   = "signed-in"  // SignedIn: any valid token
)

// Guard is what a route's guard requires.
type Guard struct {
	Kind       string
	Permission string // for permission and resource guards
}

// Marked is a handler that reports its guard.
type Marked interface {
	http.Handler
	GuardMark() Guard
}

// Unwrapper is a handler that wraps another; the test helpers follow it
// to find a guard further in. Your own middleware can implement it too.
type Unwrapper interface {
	http.Handler
	Unwrap() http.Handler
}

type marked struct {
	mark  Guard
	next  http.Handler
	serve http.HandlerFunc
}

func (m marked) ServeHTTP(w http.ResponseWriter, r *http.Request) { m.serve(w, r) }
func (m marked) GuardMark() Guard                                 { return m.mark }
func (m marked) Unwrap() http.Handler                             { return m.next }

func withMark(g Guard, next http.Handler, serve http.HandlerFunc) http.Handler {
	return marked{mark: g, next: next, serve: serve}
}

type wrapper struct {
	next  http.Handler
	serve http.HandlerFunc
}

func (w wrapper) ServeHTTP(rw http.ResponseWriter, r *http.Request) { w.serve(rw, r) }
func (w wrapper) Unwrap() http.Handler                              { return w.next }

// Public marks a route as deliberately open: it changes nothing at run time.
func Public() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return withMark(Guard{Kind: GuardPublic}, next, next.ServeHTTP)
	}
}

// SignedIn marks a route that any valid token may call, and answers 401
// when Middleware stored no Principal. Use it after Middleware.
func SignedIn() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return withMark(Guard{Kind: GuardSignedIn}, next, func(w http.ResponseWriter, r *http.Request) {
			if _, ok := FromContext(r.Context()); !ok {
				w.Header().Set("WWW-Authenticate", `Bearer`)
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// GuardOf follows h's Unwrap chain to the first guard mark.
func GuardOf(h http.Handler) (Guard, bool) {
	for i := 0; h != nil && i < 64; i++ { // a cycle can't hang a test
		if m, ok := h.(Marked); ok {
			return m.GuardMark(), true
		}
		u, ok := h.(Unwrapper)
		if !ok {
			return Guard{}, false
		}
		h = u.Unwrap()
	}
	return Guard{}, false
}
