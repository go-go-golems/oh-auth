package httptransport

import (
	"context"
	"net/http"
	"time"

	"github.com/go-go-golems/oh-auth/pkg/correlation"
)

// RequestObservation summarizes one OAuth HTTP request lifecycle. It never
// includes headers, bodies, query strings, or credentials.
type RequestObservation struct {
	RequestID string
	Method    string
	Path      string
	Status    int
	Duration  time.Duration
}

// RequestObserver receives request lifecycle observations. Implementations
// are trusted in-process sinks and must not block the request path.
type RequestObserver interface {
	ObserveRequest(context.Context, RequestObservation)
}

type recordingResponseWriter struct {
	http.ResponseWriter
	status int
}

func (w *recordingResponseWriter) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

// Correlation wraps an OAuth handler chain with request correlation: an
// inbound X-Request-ID is validated and propagated, otherwise a fresh
// identifier is minted. The identifier is exposed on the request context, the
// response header, and every request observation. Observers may be nil.
func Correlation(next http.Handler, observer RequestObserver) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestID, err := correlation.SanitizeInbound(r.Header.Get(correlation.Header))
		if err != nil {
			requestID = ""
		}
		w.Header().Set(correlation.Header, requestID)
		if requestID != "" {
			r = r.WithContext(correlation.WithID(r.Context(), requestID))
		}
		if observer == nil {
			next.ServeHTTP(w, r)
			return
		}
		start := time.Now()
		recorder := &recordingResponseWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(recorder, r)
		observer.ObserveRequest(r.Context(), RequestObservation{RequestID: requestID, Method: r.Method, Path: r.URL.Path, Status: recorder.status, Duration: time.Since(start)})
	})
}
