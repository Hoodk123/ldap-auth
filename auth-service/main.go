package main

import (
	"log"
	"net/http"
	"time"

	"github.com/Hoodk123/ldap-auth/api"
	"github.com/joho/godotenv"
	"github.com/prometheus/client_golang/prometheus/promhttp"
    "github.com/Hoodk123/ldap-auth/metrics"
)

func main() {
	_ = godotenv.Load("../.env")
	metrics.Register()  // register our custom metrics

	mux := http.NewServeMux()
	mux.HandleFunc("/auth/login", api.RateLimitMiddleware(api.LoginHandler))
	mux.Handle("/metrics", promhttp.Handler())  // Prometheus scrapes here
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if _, err := w.Write([]byte(`{"status":"ok"}`)); err != nil {
			log.Printf("health write error: %v", err)
		}
	})

	// Fix #1 — use http.Server with explicit timeouts
	// http.ListenAndServe has no timeouts — attackers can hold
	// connections open forever causing resource exhaustion
	server := &http.Server{
		Addr:         ":8080",
		Handler:      mux,
		ReadTimeout:  10 * time.Second, // max time to read request headers + body
		WriteTimeout: 10 * time.Second, // max time to write response
		IdleTimeout:  60 * time.Second, // max time for keep-alive connections
	}

	log.Println("Auth service starting on :8080")
	if err := server.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}