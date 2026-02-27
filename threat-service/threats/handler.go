package threats

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"
)

type Handler struct {
	repo   *Repository
	broker *SSEBroker
}

func NewHandler(repo *Repository, broker *SSEBroker) *Handler {
	return &Handler{repo: repo, broker: broker}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("writeJSON error: %v", err)
	}
}

// POST /threats — auth-service calls this when it detects an attack
func (h *Handler) CreateThreat(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var t Threat
	if err := json.NewDecoder(r.Body).Decode(&t); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "invalid request body",
		})
		return
	}

	if t.SourceIP == "" || t.ThreatType == "" || t.Severity == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "source_ip, threat_type and severity are required",
		})
		return
	}

	saved, err := h.repo.Insert(t)
	if err != nil {
		log.Printf("failed to insert threat: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error": "failed to save threat",
		})
		return
	}

	// broadcast to all connected analysts instantly via SSE
	h.broker.Broadcast(saved)

	writeJSON(w, http.StatusCreated, saved)
}

// GET /threats — analysts fetch current open threats
func (h *Handler) ListThreats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	threats, err := h.repo.ListOpen()
	if err != nil {
		log.Printf("failed to list threats: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error": "failed to fetch threats",
		})
		return
	}

	if threats == nil {
		threats = []Threat{}
	}

	writeJSON(w, http.StatusOK, threats)
}

// PATCH /threats/{id}/status — analyst takes action on a threat
func (h *Handler) UpdateStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPatch {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// extract ID from path: /threats/uuid/status
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 4 {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "invalid path",
		})
		return
	}
	id := parts[2]

	var body struct {
		Status  string `json:"status"`
		Analyst string `json:"analyst"`
	}

	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "invalid request body",
		})
		return
	}

	if err := h.repo.UpdateStatus(id, body.Status, body.Analyst); err != nil {
		log.Printf("failed to update threat status: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error": "failed to update status",
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "updated"})
}