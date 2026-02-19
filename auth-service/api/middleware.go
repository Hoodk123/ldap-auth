package api

import (
	"net/http"
	"sync"
	"time"
)

type rateLimiter struct {
	attempts  map[string][]time.Time
	mu        sync.Mutex
	maxAttempts int
	window    time.Duration
	lockout   time.Duration
	locked    map[string]time.Time
}

func newRateLimiter() *rateLimiter {
	rl := &rateLimiter{
		attempts:    make(map[string][]time.Time),
		locked:      make(map[string]time.Time),
		maxAttempts: 5,               // 5 attempts
		window:      time.Minute,     // per minute
		lockout:     15 * time.Minute, // lockout for 15 min
	}
	// Background cleanup to prevent memory leak
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

	// Check if currently locked out
	if lockedUntil, exists := rl.locked[ip]; exists {
		if now.Before(lockedUntil) {
			remaining := time.Until(lockedUntil).Round(time.Second)
			return false, "Too many failed attempts. Try again in " + remaining.String()
		}
		delete(rl.locked, ip)
		delete(rl.attempts, ip)
	}

	// Filter attempts within the window
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

// Global limiter instance
var limiter = newRateLimiter()

func RateLimitMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := r.RemoteAddr

		allowed, reason := limiter.isAllowed(ip)
		if !allowed {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusTooManyRequests)
			w.Write([]byte(`{"error":"` + reason + `"}`))
			return
		}

		next(w, r)
	}
}

// Call this on failed login attempts only
func RecordFailedAttempt(ip string) {
	limiter.record(ip)
}