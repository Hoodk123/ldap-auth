package api

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"time"

	ldapclient "github.com/Hoodk123/ldap-auth/ldap"
	"github.com/Hoodk123/ldap-auth/metrics"
	"github.com/golang-jwt/jwt/v5"
)

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"` // #nosec G101
}

type LoginResponse struct {
	Token string `json:"token,omitempty"`
	Error string `json:"error,omitempty"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("writeJSON encode error: %v", err)
	}
}

func LoginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, LoginResponse{Error: "invalid request body"})
		return
	}

	if req.Username == "" || req.Password == "" {
		writeJSON(w, http.StatusBadRequest, LoginResponse{Error: "username and password required"})
		return
	}

	client := ldapclient.NewClient()
	ok, err := client.Authenticate(req.Username, req.Password)
	if err != nil {
		log.Printf("authentication error for user %s: %v", req.Username, err)
		// record system-level error — LDAP unreachable etc
		metrics.LoginAttempts.WithLabelValues("error").Inc()
		writeJSON(w, http.StatusInternalServerError, LoginResponse{Error: "authentication error"})
		return
	}

	if !ok {
		RecordFailedAttempt(r.RemoteAddr)
		metrics.LoginAttempts.WithLabelValues("failure").Inc()

		// emit threat for every failed login attempt
		go EmitThreat(r.RemoteAddr, req.Username,
			"FAILED_LOGIN", "MEDIUM",
			"Invalid credentials provided")

		writeJSON(w, http.StatusUnauthorized,
			LoginResponse{Error: "invalid credentials"})
		return
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": req.Username,
		"exp": time.Now().Add(time.Hour * 8).Unix(),
		"iat": time.Now().Unix(),
	})

	secret := os.Getenv("JWT_SECRET")
	tokenString, err := token.SignedString([]byte(secret))
	if err != nil {
		log.Printf("token signing error: %v", err)
		writeJSON(w, http.StatusInternalServerError, LoginResponse{Error: "token generation failed"})
		return
	}

	// record successful login
	metrics.LoginAttempts.WithLabelValues("success").Inc()
	writeJSON(w, http.StatusOK, LoginResponse{Token: tokenString})
}