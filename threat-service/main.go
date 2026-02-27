package main

import (
	"log"
	"net/http"
	"time"

	"github.com/Hoodk123/ldap-auth/threat-service/db"
	"github.com/Hoodk123/ldap-auth/threat-service/threats"
	"github.com/joho/godotenv"
)

func main() {
	_ = godotenv.Load("../.env")

	database, err := db.Connect()
	if err != nil {
		log.Fatalf("database connection failed: %v", err)
	}
	defer database.Close()
	log.Println("connected to Supabase PostgreSQL")

	repo := threats.NewRepository(database)
	broker := threats.NewSSEBroker()
	handler := threats.NewHandler(repo, broker)

	mux := http.NewServeMux()

	mux.HandleFunc("/threats", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			handler.CreateThreat(w, r)
		case http.MethodGet:
			handler.ListThreats(w, r)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})

	mux.HandleFunc("/threats/", handler.UpdateStatus)
	mux.Handle("/threats/stream", http.HandlerFunc(broker.ServeSSE))

	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if _, err := w.Write([]byte(`{"status":"ok"}`)); err != nil {
			log.Printf("health write error: %v", err)
		}
	})

	server := &http.Server{
		Addr:         ":8082",
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	log.Println("threat-service starting on :8081")
	if err := server.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}