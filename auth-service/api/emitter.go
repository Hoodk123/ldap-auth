package api

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"time"
)

// EmitThreat sends a detected threat event to threat-service
// Called with go EmitThreat(...) so it never blocks the main request
func EmitThreat(sourceIP, username, threatType, severity, details string) {
	threatServiceURL := os.Getenv("THREAT_SERVICE_URL")
	if threatServiceURL == "" {
		// not configured — skip silently in development
		return
	}

	payload := map[string]string{
		"source_ip":   sourceIP,
		"username":    username,
		"threat_type": threatType,
		"severity":    severity,
		"details":     details,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		log.Printf("EmitThreat marshal error: %v", err)
		return
	}

	req, err := http.NewRequest(http.MethodPost,
		threatServiceURL+"/threats",
		bytes.NewBuffer(body),
	)
	if err != nil {
		log.Printf("EmitThreat request build error: %v", err)
		return
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Service-Key", os.Getenv("INTERNAL_SERVICE_KEY"))

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("EmitThreat failed to reach threat-service: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		log.Printf("EmitThreat unexpected status: %d", resp.StatusCode)
	}
}