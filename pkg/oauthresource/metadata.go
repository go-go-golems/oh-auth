package oauthresource

import (
	"encoding/json"
	"net/http"

	"github.com/go-go-golems/oh-auth/pkg/oauthserver"
)

type Metadata struct {
	Resource             string   `json:"resource"`
	AuthorizationServers []string `json:"authorization_servers"`
	ScopesSupported      []string `json:"scopes_supported,omitempty"`
	ResourceName         string   `json:"resource_name,omitempty"`
}

func (m Metadata) Handler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(m)
}

func BearerChallenge(metadataURL string) string {
	return `Bearer error="invalid_token", resource_metadata="` + metadataURL + `"`
}

func Scopes(values oauthserver.ScopeSet) []string {
	result := make([]string, 0, len(values.Values()))
	for _, value := range values.Values() {
		result = append(result, string(value))
	}
	return result
}
