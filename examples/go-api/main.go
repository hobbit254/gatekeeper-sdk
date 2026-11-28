// Command go-api is an example API protected by Gatekeeper (FR-T9, ADR-0130),
// meant to be copied. GET /api/me answers any signed-in user; GET /api/reports
// needs the report:read permission. The browser app in ../browser-app calls it.
//
//	GK_ISSUER=https://auth.example.com/t/acme  the tenant's issuer
//	GK_AUDIENCE=shop-api                       this API's identifier (in the app client's API audiences)
//	GK_CLIENT_ID=shop-web                      the client whose roles and permissions apply
//	APP_ORIGIN=http://localhost:5173           the browser app allowed to call it (CORS)
//	PORT=8081
package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"time"

	gk "github.com/hobbit254/gatekeeper-sdk/go"
)

func main() {
	issuer, audience, client := os.Getenv("GK_ISSUER"), os.Getenv("GK_AUDIENCE"), os.Getenv("GK_CLIENT_ID")
	if issuer == "" || audience == "" || client == "" {
		log.Fatal("set GK_ISSUER, GK_AUDIENCE and GK_CLIENT_ID")
	}
	auth := gk.New(gk.Config{Issuer: issuer, Audience: audience, ClientID: client,
		ClientSecret: os.Getenv("GK_CLIENT_SECRET")}) // only for a confidential client
	srv := &http.Server{Addr: ":" + env("PORT", "8081"), Handler: cors(env("APP_ORIGIN", "http://localhost:5173"), routes(auth)),
		ReadHeaderTimeout: 5 * time.Second}
	log.Printf("listening on %s", srv.Addr)
	log.Fatal(srv.ListenAndServe())
}

func routes(auth *gk.SDK) http.Handler {
	mux := http.NewServeMux()
	register(mux)
	return auth.Middleware()(mux)
}

// register adds the routes, each with a guard; main_test.go checks none is missing.
func register(mux interface{ Handle(string, http.Handler) }) {
	mux.Handle("GET /api/me", gk.SignedIn()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, _ := gk.FromContext(r.Context())
		writeJSON(w, map[string]any{"sub": p.Sub, "roles": p.Roles, "permissions": p.Permissions})
	})))
	mux.Handle("GET /api/reports", gk.RequirePermission("report:read")(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{"reports": []string{"October sales"}})
	})))
}

// cors lets the browser app call the API with its bearer token.
func cors(origin string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Origin") == origin {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Headers", "Authorization")
			w.Header().Add("Vary", "Origin")
		}
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
