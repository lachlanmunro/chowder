package chowder

import (
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

const logger = "Log"

var (
	connCount = promauto.NewCounter(prometheus.CounterOpts{
		Name: "chowder_connections_made_ops_total",
		Help: "The total number of chowder connections made",
	})
	durations = promauto.NewHistogram(prometheus.HistogramOpts{
		Name: "chowder_duration_seconds",
		Help: "The breakdown of chowder durations in seconds",
	})
	statusCodes = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "chowder_status_codes",
		Help:    "The breakdown of chowder statuscodes returned",
		Buckets: []float64{199, 299, 399, 499},
	})
	_ http.ResponseWriter = &StatusWriter{}
)

// StatusWriter wraps a responsewriter to track the status and content length
// from https://www.reddit.com/r/golang/comments/7p35s4/how_do_i_get_the_response_status_for_my_middleware/
type StatusWriter struct {
	http.ResponseWriter
	status int
	length int
}

// WriteHeader changes the underlying ResponseWriter header status
func (w *StatusWriter) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

// Write writes to the changes the underlying ResponseWriter
func (w *StatusWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = 200
	}
	n, err := w.ResponseWriter.Write(b)
	w.length += n
	return n, err
}

// LogRequests logs all requests that pass through with loglevel dependant on status code
func LogRequests(handler http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		connCount.Inc()
		sw := &StatusWriter{ResponseWriter: w}
		handler.ServeHTTP(sw, r)
		statusCodes.Observe(float64(sw.status))
		d := time.Now().Sub(start)
		durations.Observe(d.Seconds())
		logLevelFromStatus(sw.status).
			Str("host", r.Host).
			Str("remote-address", r.RemoteAddr).
			Str("method", r.Method).
			Str("request-uri", r.RequestURI).
			Str("proto", r.Proto).
			Int("status", sw.status).
			Int("content-length", sw.length).
			Str("user-agent", r.Header.Get("User-Agent")).
			Dur("duration", d).
			Msg("request")
	}
}

func logLevelFromStatus(status int) *zerolog.Event {
	switch {
	case status < 200: // 100 -> 199
		return log.Debug()
	case status < 300: // 200 -> 299
		return log.Info()
	case status < 400: // 300 -> 399
		return log.Debug()
	case status < 500: // 400 -> 499
		return log.Warn()
	default:
		return log.Error()
	}
}
