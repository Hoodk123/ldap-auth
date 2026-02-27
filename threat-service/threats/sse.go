package threats

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
)

// SSEBroker manages all connected analyst browsers
// When a new threat arrives, it broadcasts to all of them instantly
type SSEBroker struct {
	clients map[chan string]bool
	mu      sync.RWMutex
}

func NewSSEBroker() *SSEBroker {
	return &SSEBroker{
		clients: make(map[chan string]bool),
	}
}

// Subscribe — analyst browser connects, gets a channel
func (b *SSEBroker) Subscribe() chan string {
	ch := make(chan string, 10)
	b.mu.Lock()
	b.clients[ch] = true
	b.mu.Unlock()
	return ch
}

// Unsubscribe — analyst closes browser tab
func (b *SSEBroker) Unsubscribe(ch chan string) {
	b.mu.Lock()
	delete(b.clients, ch)
	close(ch)
	b.mu.Unlock()
}

// Broadcast — sends new threat to ALL connected analysts instantly
func (b *SSEBroker) Broadcast(t Threat) {
	data, err := json.Marshal(t)
	if err != nil {
		log.Printf("SSE marshal error: %v", err)
		return
	}

	b.mu.RLock()
	defer b.mu.RUnlock()

	for ch := range b.clients {
		select {
		case ch <- string(data):
		default:
			// client too slow — skip, don't block
		}
	}
}

// ServeSSE — HTTP handler that keeps connection open and streams events
func (b *SSEBroker) ServeSSE(w http.ResponseWriter, r *http.Request) {
	// These headers tell browser: "keep this connection open, stream data"
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	ch := b.Subscribe()
	defer b.Unsubscribe(ch)

	log.Printf("analyst connected to SSE stream from %s", r.RemoteAddr)

	for {
		select {
		case msg, ok := <-ch:
			if !ok {
				return
			}
			// SSE format: "data: <payload>\n\n"
			fmt.Fprintf(w, "data: %s\n\n", msg)
			flusher.Flush()
		case <-r.Context().Done():
			// analyst closed the browser tab
			log.Printf("analyst disconnected from SSE stream")
			return
		}
	}
}