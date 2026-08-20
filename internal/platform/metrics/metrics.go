package metrics

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type Metrics struct {
	Requests *prometheus.CounterVec
	Errors   *prometheus.CounterVec
	Duration *prometheus.HistogramVec
	DBOps    *prometheus.CounterVec
	Leases   prometheus.Gauge
}

func New() *Metrics {
	m := &Metrics{
		Requests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "scp_http_requests_total",
			Help: "HTTP requests handled by the platform.",
		}, []string{"method", "route", "status"}),
		Errors: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "scp_http_errors_total",
			Help: "HTTP handler errors.",
		}, []string{"route"}),
		Duration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "scp_http_request_duration_seconds",
			Help:    "HTTP request latency.",
			Buckets: prometheus.DefBuckets,
		}, []string{"method", "route"}),
		DBOps: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "scp_database_operations_total",
			Help: "Database operations by operation and result.",
		}, []string{"operation", "result"}),
		Leases: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "scp_active_leases",
			Help: "Current active dynamic secret leases.",
		}),
	}
	prometheus.MustRegister(m.Requests, m.Errors, m.Duration, m.DBOps, m.Leases)
	return m
}

func (m *Metrics) Handler() http.Handler {
	return promhttp.Handler()
}
