package api

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	ldapclient "github.com/Hoodk123/ldap-auth/ldap"
)

// LoginRequest holds credentials from the client.
// Fix #2 — gosec flags "Password" field matching secret pattern.
// This is intentional — it is our API contract, not a leaked secret.
type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"` //nolint:gosec
}

type LoginResponse struct {
	Token string `json:"token,omitempty"`
	Error string `json:"error,omitempty"`
}

// writeJSON is a helper that handles the json.Encode error in one place
// Fix #3 — every Encode() call was silently ignoring errors
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
		writeJSON(w, http.StatusInternalServerError, LoginResponse{Error: "authentication error"})
		return
	}

	if !ok {
		RecordFailedAttempt(r.RemoteAddr)
		writeJSON(w, http.StatusUnauthorized, LoginResponse{Error: "invalid credentials"})
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

	writeJSON(w, http.StatusOK, LoginResponse{Token: tokenString})
}