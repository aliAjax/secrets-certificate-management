package httpapi

import (
	"context"
	"net/http"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/example/secrets-cert-platform/internal/platform/metrics"
)

type responseRecorder struct {
	http.ResponseWriter
	status int
}

func (r *responseRecorder) WriteHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

func (r *responseRecorder) Write(data []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	return r.ResponseWriter.Write(data)
}

func (s *Server) withMiddleware(next http.Handler) http.Handler {
	return s.withRecovery(
		s.withRequestID(
			s.withLogging(
				s.withMetrics(
					s.withRateLimit(
						s.withAuth(next),
					),
				),
			),
		),
	)
}

func (s *Server) withRequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Request-ID")
		if id == "" {
			id = uuid.NewString()
		}
		ctx := context.WithValue(r.Context(), requestIDKey, id)
		w.Header().Set("X-Request-ID", id)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (s *Server) withLogging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &responseRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		s.logger.Info("http request",
			"request_id", requestIDFromContext(r.Context()),
			"method", r.Method,
			"path", r.URL.Path,
			"status", rec.status,
			"duration_ms", time.Since(start).Milliseconds(),
		)
	})
}

func (s *Server) withMetrics(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &responseRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		route := routeLabel(r.URL.Path)
		s.metrics.Requests.WithLabelValues(r.Method, route, http.StatusText(rec.status)).Inc()
		if rec.status >= 400 {
			s.metrics.Errors.WithLabelValues(route).Inc()
		}
		s.metrics.Duration.WithLabelValues(r.Method, route).Observe(time.Since(start).Seconds())
	})
}

func (s *Server) withRateLimit(next http.Handler) http.Handler {
	limiter := newSlidingWindowLimiter(s.config.Limits.RatePerSecond, s.config.Limits.RateBurst)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !limiter.Allow(rateLimitKeyFromRequest(r)) {
			writeError(w, http.StatusTooManyRequests, errTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) withRecovery(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if recovered := recover(); recovered != nil {
				s.logger.Error("panic in http handler", "error", recovered, "path", r.URL.Path)
				writeError(w, http.StatusInternalServerError, errInternal)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func routeLabel(path string) string {
	switch {
	case path == "/healthz":
		return "healthz"
	case path == "/readyz":
		return "readyz"
	case path == "/metrics":
		return "metrics"
	default:
		return "api"
	}
}

func clientIP(r *http.Request) string {
	if value := r.Header.Get("X-Forwarded-For"); value != "" {
		return value
	}
	return r.RemoteAddr
}

type slidingWindowLimiter struct {
	mu      sync.Mutex
	rate    int
	burst   int
	windows map[string]*windowState
}

type windowState struct {
	windowStart time.Time
	count       int
}

func newSlidingWindowLimiter(rate, burst int) *slidingWindowLimiter {
	if rate <= 0 {
		rate = 100
	}
	if burst <= 0 {
		burst = rate * 2
	}
	return &slidingWindowLimiter{rate: rate, burst: burst, windows: make(map[string]*windowState)}
}

func (l *slidingWindowLimiter) Allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	state, ok := l.windows[key]
	if !ok || now.Sub(state.windowStart) >= time.Second {
		state = &windowState{windowStart: now, count: 0}
		l.windows[key] = state
	}
	if state.count >= l.burst {
		return false
	}
	state.count++
	if len(l.windows) > 10000 {
		for k, v := range l.windows {
			if now.Sub(v.windowStart) > time.Minute {
				delete(l.windows, k)
			}
		}
	}
	return true
}

var _ = metrics.New
