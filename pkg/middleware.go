package chowder

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

const logKey key = 0

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

type key int

func getLog(ctx context.Context) *zerolog.Logger {
	l, ok := ctx.Value(logKey).(*zerolog.Logger)
	if !ok {
		newlog := log.With().Logger()
		l = &newlog
	}
	return l
}

func setLog(ctx context.Context, l *zerolog.Logger) context.Context {
	return context.WithValue(ctx, logKey, l)
}

func addLogFields(ctx context.Context, addFields func(zerolog.Context) zerolog.Context) {
	oldLog := getLog(ctx)
	newLog := addFields(oldLog.With()).Logger()
	*oldLog = newLog
}

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
func LogRequests(l zerolog.Logger, handler http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		connCount.Inc()
		l := l.With().
			Time("start", start).
			Str("host", r.Host).
			Str("remote-address", r.RemoteAddr).
			Str("method", r.Method).
			Str("request-uri", r.RequestURI).
			Str("proto", r.Proto).
			Str("user-agent", r.Header.Get("User-Agent")).
			Logger()
		sw := StatusWriter{ResponseWriter: w}
		defer func() {
			if r := recover(); r != nil {
				d := time.Since(start)
				durations.Observe(d.Seconds())
				logPanic(r, logLevelFromStatus(l, sw.status).
					Int("status", sw.status).
					Int("content-length", sw.length).
					Dur("duration", d)).
					Msg("response returned")
			}
		}()
		handler.ServeHTTP(&sw, r.WithContext(setLog(r.Context(), &l)))
		statusCodes.Observe(float64(sw.status))
		d := time.Since(start)
		durations.Observe(d.Seconds())
		logLevelFromStatus(l, sw.status).
			Int("status", sw.status).
			Int("content-length", sw.length).
			Dur("duration", d).
			Msg("response returned")
	}
}

func logPanic(p interface{}, e *zerolog.Event) *zerolog.Event {
	switch p := p.(type) {
	case error:
		return e.Err(p)
	case string:
		return e.Str("panic-logger", p)
	case fmt.Stringer:
		return e.Str("panic-logger", p.String())
	case fmt.GoStringer:
		return e.Str("panic-logger", p.GoString())
	default:
		return e.Interface("panic-logger", p)
	}
}

func logLevelFromStatus(l zerolog.Logger, status int) *zerolog.Event {
	switch {
	case status < 200: // 100 -> 199
		return l.Debug()
	case status < 300: // 200 -> 299
		return l.Info()
	case status < 400: // 300 -> 399
		return l.Debug()
	case status < 500: // 400 -> 499
		if status == 404 {
			return l.Info()
		}
		return l.Warn()
	default:
		return l.Error()
	}
}

// HeaderAuth enforces that users are authenticated by reading the Authorization header
func HeaderAuth(users map[string]string, handler http.Handler) http.HandlerFunc {
	if len(users) == 0 {
		log.Warn().Msg("no users supplied, authentication is disabled")
		return handler.ServeHTTP
	}
	return func(w http.ResponseWriter, r *http.Request) {
		t := r.Header.Get("Authorization")
		user, ok := users[t]
		if !ok {
			writeResponse(w, r, &Response{
				Error:   http.StatusText(http.StatusUnauthorized),
				Message: getAuthFailureMessage(t),
			}, http.StatusUnauthorized)
			return
		}
		addLogFields(r.Context(), func(l zerolog.Context) zerolog.Context {
			return l.Str("user", user)
		})
		handler.ServeHTTP(w, r)
	}
}

func getAuthFailureMessage(t string) string {
	if t == "" {
		return "no authorisation token supplied"
	}
	return fmt.Sprintf("token '%v' not recognised", t)
}
