package main

import (
	"testing"

	"github.com/hobbit254/gatekeeper-sdk/go/gktest"
)

// Every route has a guard: a forgotten one fails here, not in an audit.
func TestEveryRouteGuarded(t *testing.T) {
	mux := gktest.NewMux()
	register(mux)
	gktest.AssertEveryRouteGuarded(t, mux.Routes(), gktest.Options{Permissions: []string{"report:read"}, FailOnUnused: true})
}
