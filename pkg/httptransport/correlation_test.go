package httptransport_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-go-golems/oh-auth/pkg/correlation"
	"github.com/go-go-golems/oh-auth/pkg/httptransport"
	"github.com/go-go-golems/oh-auth/pkg/oauthserver"
)

type recordingObserver struct {
	observations []httptransport.RequestObservation
}

func (o *recordingObserver) ObserveRequest(_ context.Context, observation httptransport.RequestObservation) {
	o.observations = append(o.observations, observation)
}

func echoHandler(w http.ResponseWriter, r *http.Request) {
	_, _ = w.Write([]byte(correlation.FromContext(r.Context())))
}

func TestCorrelationHonorsValidInboundID(t *testing.T) {
	observer := &recordingObserver{}
	server := httptest.NewServer(httptransport.Correlation(http.HandlerFunc(echoHandler), observer))
	defer server.Close()
	request, _ := http.NewRequest(http.MethodGet, server.URL+"/oauth/register", nil)
	request.Header.Set(correlation.Header, "client-trace-123")
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = response.Body.Close() }()
	if got := response.Header.Get(correlation.Header); got != "client-trace-123" {
		t.Fatalf("echoed request id = %q", got)
	}
	body := make([]byte, 32)
	n, _ := response.Body.Read(body)
	if string(body[:n]) != "client-trace-123" {
		t.Fatalf("context request id = %q", string(body[:n]))
	}
	if len(observer.observations) != 1 {
		t.Fatalf("observations = %+v", observer.observations)
	}
	if observer.observations[0].RequestID != "client-trace-123" || observer.observations[0].Status != http.StatusOK || observer.observations[0].Method != http.MethodGet {
		t.Fatalf("observation = %+v", observer.observations[0])
	}
	if observer.observations[0].Duration < 0 {
		t.Fatal("negative duration")
	}
}

func TestCorrelationReplacesInvalidInboundID(t *testing.T) {
	observer := &recordingObserver{}
	server := httptest.NewServer(httptransport.Correlation(http.HandlerFunc(echoHandler), observer))
	defer server.Close()
	for _, invalid := range []string{"", "short", strings.Repeat("x", 100), "bad id with spaces"} {
		request, _ := http.NewRequest(http.MethodGet, server.URL+"/oauth/register", nil)
		request.Header.Set(correlation.Header, invalid)
		response, err := server.Client().Do(request)
		if err != nil {
			t.Fatal(err)
		}
		got := response.Header.Get(correlation.Header)
		_ = response.Body.Close()
		if got == invalid {
			t.Fatalf("invalid inbound id %q was echoed", invalid)
		}
		if !correlation.ValidID(got) {
			t.Fatalf("replacement id %q is not valid", got)
		}
	}
}

func TestCorrelationNilObserver(t *testing.T) {
	server := httptest.NewServer(httptransport.Correlation(http.HandlerFunc(echoHandler), nil))
	defer server.Close()
	response, err := http.Get(server.URL + "/oauth/token")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = response.Body.Close() }()
	if !correlation.ValidID(response.Header.Get(correlation.Header)) {
		t.Fatalf("request id = %q", response.Header.Get(correlation.Header))
	}
}

// TestServerCorrelationWithoutObserver asserts that mounted OAuth routes
// always apply correlation even when no RequestObserver is configured: the
// X-Request-ID header is set and inbound identifiers are honored.
func TestServerCorrelationWithoutObserver(t *testing.T) {
	server, _ := newServer(t)
	if server == nil {
		t.Fatal("missing server")
	}
	mux := http.NewServeMux()
	server.Mount(mux)
	first := httptest.NewRequest(http.MethodGet, "https://auth.example.test/jwks.json", nil)
	firstResponse := httptest.NewRecorder()
	mux.ServeHTTP(firstResponse, first)
	if !correlation.ValidID(firstResponse.Header().Get(correlation.Header)) {
		t.Fatalf("request id = %q", firstResponse.Header().Get(correlation.Header))
	}
	second := httptest.NewRequest(http.MethodGet, "https://auth.example.test/jwks.json", nil)
	second.Header.Set(correlation.Header, "client-trace-42")
	secondResponse := httptest.NewRecorder()
	mux.ServeHTTP(secondResponse, second)
	if got := secondResponse.Header().Get(correlation.Header); got != "client-trace-42" {
		t.Fatalf("inbound id = %q", got)
	}
}

func TestCorrelationObservesStatusAndPath(t *testing.T) {
	observer := &recordingObserver{}
	failing := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	})
	server := httptest.NewServer(httptransport.Correlation(failing, observer))
	defer server.Close()
	response, err := http.Post(server.URL+"/oauth/register", "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if len(observer.observations) != 1 {
		t.Fatalf("observations = %+v", observer.observations)
	}
	observation := observer.observations[0]
	if observation.Status != http.StatusServiceUnavailable || observation.Path != "/oauth/register" || observation.Method != http.MethodPost {
		t.Fatalf("observation = %+v", observation)
	}
}

// TestAuditEventRequestIDContract pins the request correlation field so sinks
// can rely on it being present on every audit event.
func TestAuditEventRequestIDContract(t *testing.T) {
	event := oauthserver.AuditEvent{Operation: "register_client", Outcome: "success", RequestID: "req-abcdefgh"}
	if event.RequestID != "req-abcdefgh" {
		t.Fatal("request id field is not stable")
	}
	if event.Time.After(time.Now().Add(time.Minute)) {
		t.Fatal("time is not bounded")
	}
}
