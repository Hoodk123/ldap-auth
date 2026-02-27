package api

import (
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/Hoodk123/ldap-auth/metrics"
)

type rateLimiter struct {
	attempts    map[string][]time.Time
	locked      map[string]time.Time
	mu          sync.Mutex
	maxAttempts int
	window      time.Duration
	lockout     time.Duration
}

func newRateLimiter() *rateLimiter {
	rl := &rateLimiter{
		attempts:    make(map[string][]time.Time),
		locked:      make(map[string]time.Time),
		maxAttempts: 5,
		window:      time.Minute,
		lockout:     15 * time.Minute,
	}
	go rl.cleanup()
	return rl
}

func (rl *rateLimiter) cleanup() {
	for {
		time.Sleep(5 * time.Minute)
		rl.mu.Lock()
		now := time.Now()
		for ip, t := range rl.locked {
			if now.After(t) {
				delete(rl.locked, ip)
				delete(rl.attempts, ip)
			}
		}
		rl.mu.Unlock()
	}
}

func (rl *rateLimiter) isAllowed(ip string) (bool, string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()

	if lockedUntil, exists := rl.locked[ip]; exists {
		if now.Before(lockedUntil) {
			remaining := time.Until(lockedUntil).Round(time.Second)
			return false, "Too many failed attempts. Try again in " + remaining.String()
		}
		delete(rl.locked, ip)
		delete(rl.attempts, ip)
	}

	windowStart := now.Add(-rl.window)
	var recent []time.Time
	for _, t := range rl.attempts[ip] {
		if t.After(windowStart) {
			recent = append(recent, t)
		}
	}
	rl.attempts[ip] = recent

	if len(recent) >= rl.maxAttempts {
		rl.locked[ip] = now.Add(rl.lockout)
		return false, "Account locked for 15 minutes due to too many attempts"
	}

	return true, ""
}

func (rl *rateLimiter) record(ip string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	rl.attempts[ip] = append(rl.attempts[ip], time.Now())
}

var limiter = newRateLimiter() //nolint:gosec

func RateLimitMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			ip = r.RemoteAddr
		}

		allowed, reason := limiter.isAllowed(ip)
		if !allowed {
			metrics.RateLimitedTotal.Inc()

			// emit threat asynchronously — don't block the response
			go EmitThreat(ip, "", "RATE_LIMITED", "HIGH",
				"IP blocked after too many failed attempts")

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusTooManyRequests)
			if _, err := w.Write([]byte(`{"error":"` + reason + `"}`)); err != nil {
				log.Printf("rate limit response write error: %v", err)
			}
			return
		}

		next(w, r)
	}
}

func RecordFailedAttempt(ip string) {
	host, _, err := net.SplitHostPort(ip)
	if err != nil {
		host = ip
	}
	limiter.record(host)
}