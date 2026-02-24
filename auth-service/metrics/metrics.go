package metrics

import "github.com/prometheus/client_golang/prometheus"

var (
	LoginAttempts = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ldap_auth_login_attempts_total",
			Help: "Total number of login attempts",
		},
		[]string{"status"}, // labels: "success", "failure", "error"
	)

	RateLimitedTotal = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "ldap_auth_rate_limited_total",
			Help: "Total number of requests blocked by rate limiter",
		},
	)

	RequestDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "ldap_auth_request_duration_seconds",
			Help:    "Login request duration in seconds",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"endpoint"},
	)
)

func Register() {
	prometheus.MustRegister(LoginAttempts)
	prometheus.MustRegister(RateLimitedTotal)
	prometheus.MustRegister(RequestDuration)
}