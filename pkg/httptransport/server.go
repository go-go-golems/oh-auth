// Package httptransport adapts oauthserver transitions to OAuth HTTP endpoints.
package httptransport

import (
	"context"
	"encoding/json"
	"errors"
	"html/template"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-go-golems/oh-auth/pkg/oauthresource"
	"github.com/go-go-golems/oh-auth/pkg/oauthserver"
)

type Config[A any] struct {
	Engine *oauthserver.Engine[A]
	Login  oauthserver.LoginStarter
}

type Server[A any] struct {
	engine          *oauthserver.Engine[A]
	issuer          string
	resources       oauthserver.ResourceRegistry
	tokens          oauthserver.TokenService[A]
	login           oauthserver.LoginStarter
	policy          oauthserver.HTTPPolicy
	consentTemplate *template.Template
}

func New[A any](config Config[A]) (*Server[A], error) {
	if config.Engine == nil {
		return nil, errors.New("HTTP transport configuration is incomplete")
	}
	return &Server[A]{engine: config.Engine, issuer: config.Engine.Issuer(), resources: config.Engine.Resources(), tokens: config.Engine.Tokens(), login: config.Login, policy: config.Engine.HTTPPolicy(), consentTemplate: template.Must(template.New("consent").Parse(consentPage))}, nil
}

func (s *Server[A]) Mount(mux *http.ServeMux) {
	mux.HandleFunc("/.well-known/oauth-authorization-server", s.metadata)
	mux.HandleFunc("/.well-known/openid-configuration", s.metadata)
	mux.HandleFunc("/jwks.json", s.jwks)
	mux.HandleFunc("/oauth/register", s.register)
	mux.HandleFunc("/oauth/authorize", s.authorize)
	mux.HandleFunc("/oauth/consent", s.consent)
	mux.HandleFunc("/oauth/token", s.token)
	mux.HandleFunc("/oauth/revoke", s.revoke)
}

type authorizationMetadata struct {
	Issuer                string   `json:"issuer"`
	AuthorizationEndpoint string   `json:"authorization_endpoint"`
	TokenEndpoint         string   `json:"token_endpoint"`
	RegistrationEndpoint  string   `json:"registration_endpoint"`
	RevocationEndpoint    string   `json:"revocation_endpoint"`
	JWKSURI               string   `json:"jwks_uri"`
	ResponseTypes         []string `json:"response_types_supported"`
	GrantTypes            []string `json:"grant_types_supported"`
	CodeChallengeMethods  []string `json:"code_challenge_methods_supported"`
	ScopesSupported       []string `json:"scopes_supported,omitempty"`
}

func (s *Server[A]) metadata(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.method(w, http.MethodGet)
		return
	}
	s.headers(w)
	resources, err := s.resources.ListResources(r.Context())
	if err != nil {
		s.writeOAuthError(w, serverOAuthError(oauthserver.ErrorTemporary, "metadata unavailable", 503, err))
		return
	}
	scopes := make([]string, 0)
	for _, resource := range resources {
		scopes = append(scopes, oauthresource.Scopes(resource.SupportedScopes)...)
	}
	s.writeJSON(w, http.StatusOK, authorizationMetadata{Issuer: s.issuer, AuthorizationEndpoint: s.absolute("/oauth/authorize"), TokenEndpoint: s.absolute("/oauth/token"), RegistrationEndpoint: s.absolute("/oauth/register"), RevocationEndpoint: s.absolute("/oauth/revoke"), JWKSURI: s.absolute("/jwks.json"), ResponseTypes: []string{"code"}, GrantTypes: []string{"authorization_code", "refresh_token"}, CodeChallengeMethods: []string{"S256"}, ScopesSupported: scopes})
}
func (s *Server[A]) jwks(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.method(w, http.MethodGet)
		return
	}
	s.headers(w)
	keys, err := s.tokens.JWKS(r.Context())
	if err != nil {
		s.writeOAuthError(w, serverOAuthError(oauthserver.ErrorTemporary, "key set unavailable", 503, err))
		return
	}
	s.writeJSON(w, http.StatusOK, keys)
}
func (s *Server[A]) register(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.method(w, http.MethodPost)
		return
	}
	s.headers(w)
	var request struct {
		ClientName              string   `json:"client_name"`
		RedirectURIs            []string `json:"redirect_uris"`
		Scope                   string   `json:"scope"`
		TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
		GrantTypes              []string `json:"grant_types"`
		ResponseTypes           []string `json:"response_types"`
	}
	if err := s.decodeJSON(w, r, &request); err != nil {
		s.writeOAuthError(w, invalid(oauthserver.ErrorInvalidClientMetadata, "client metadata is invalid", err))
		return
	}
	if request.TokenEndpointAuthMethod != "" && request.TokenEndpointAuthMethod != "none" {
		s.writeOAuthError(w, invalid(oauthserver.ErrorInvalidClientMetadata, "only public clients are supported", oauthserver.ErrInvalid))
		return
	}
	if !validMetadataList(request.GrantTypes, s.policy.MaxArrayLength, "authorization_code", "refresh_token") || !validMetadataList(request.ResponseTypes, s.policy.MaxArrayLength, "code") || len(request.RedirectURIs) > s.policy.MaxArrayLength {
		s.writeOAuthError(w, invalid(oauthserver.ErrorInvalidClientMetadata, "client metadata is invalid", oauthserver.ErrInvalid))
		return
	}
	result, err := s.engine.RegisterClient(r.Context(), oauthserver.RegisterClientInput{DisplayName: request.ClientName, RedirectURIs: request.RedirectURIs, RequestedScopes: strings.Fields(request.Scope)})
	if err != nil {
		s.writeOAuthError(w, err)
		return
	}
	s.writeJSON(w, http.StatusCreated, map[string]any{"client_id": result.Client.ID, "client_name": result.Client.DisplayName, "redirect_uris": result.Client.RedirectURIs, "token_endpoint_auth_method": "none", "grant_types": []string{"authorization_code", "refresh_token"}, "response_types": []string{"code"}, "scope": result.Client.AllowedScopes.String()})
}
func (s *Server[A]) authorize(w http.ResponseWriter, r *http.Request) {
	s.headers(w)
	if r.Method != http.MethodGet {
		s.method(w, http.MethodGet)
		return
	}
	query, err := s.authorizationQuery(r)
	if err != nil {
		s.writeOAuthError(w, invalid(oauthserver.ErrorInvalidRequest, "authorization request is invalid", err))
		return
	}
	result, err := s.engine.BeginAuthorization(r.Context(), oauthserver.BeginAuthorizationInput{ClientID: query.Get("client_id"), RedirectURI: query.Get("redirect_uri"), ResponseType: query.Get("response_type"), State: query.Get("state"), CodeChallenge: query.Get("code_challenge"), ChallengeMethod: query.Get("code_challenge_method"), Scopes: strings.Fields(query.Get("scope")), Resource: query.Get("resource")})
	if err != nil {
		if redirect, redirectErr := s.engine.ValidateRedirect(r.Context(), query.Get("client_id"), query.Get("redirect_uri")); redirectErr == nil && query.Get("state") != "" {
			s.redirectAuthorizationError(w, r, redirect, query.Get("state"), err)
			return
		}
		s.writeOAuthError(w, err)
		return
	}
	if s.login == nil {
		s.redirectLoginError(w, r, result.LoginContext, serverOAuthError(oauthserver.ErrorTemporary, "login is unavailable", 503, nil))
		return
	}
	destination, err := s.login.AuthorizationURL(r.Context(), result.LoginContext)
	if err != nil {
		s.redirectLoginError(w, r, result.LoginContext, serverOAuthError(oauthserver.ErrorTemporary, "login is unavailable", 503, err))
		return
	}
	http.Redirect(w, r, destination, http.StatusFound)
}

func (s *Server[A]) consent(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		s.consentGet(w, r)
		return
	}
	if r.Method == http.MethodPost {
		s.consentPost(w, r)
		return
	}
	s.headers(w)
	s.method(w, "GET, POST")
}

func (s *Server[A]) consentGet(w http.ResponseWriter, r *http.Request) {
	s.headers(w)
	if r.Method != http.MethodGet {
		s.method(w, http.MethodGet)
		return
	}
	view, err := s.engine.ConsentView(r.Context(), oauthserver.ConsentToken(r.URL.Query().Get("token")))
	if err != nil {
		s.writeOAuthError(w, err)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")
	if err := s.consentTemplate.Execute(w, view); err != nil {
		return
	}
}
func (s *Server[A]) consentPost(w http.ResponseWriter, r *http.Request) {
	s.headers(w)
	if r.Method != http.MethodPost {
		s.method(w, http.MethodPost)
		return
	}
	if err := s.parseForm(w, r, "scope"); err != nil {
		s.writeOAuthError(w, invalid(oauthserver.ErrorInvalidRequest, "consent form is invalid", err))
		return
	}
	if len(r.Form.Get("token")) > s.policy.MaxFieldBytes {
		s.writeOAuthError(w, invalid(oauthserver.ErrorInvalidRequest, "consent form is invalid", oauthserver.ErrInvalid))
		return
	}
	var decision oauthserver.ConsentDecision
	switch r.Form.Get("decision") {
	case "approve":
		decision = oauthserver.ConsentDecisionApprove
	case "deny":
		decision = oauthserver.ConsentDecisionDeny
	default:
		s.writeOAuthError(w, invalid(oauthserver.ErrorInvalidRequest, "consent decision is invalid", oauthserver.ErrInvalid))
		return
	}
	rawScopes := r.Form["scope"]
	selected := make([]oauthserver.Scope, len(rawScopes))
	for i, value := range rawScopes {
		selected[i] = oauthserver.Scope(value)
	}
	result, err := s.engine.DecideConsent(r.Context(), oauthserver.DecideConsentInput{Token: oauthserver.ConsentToken(r.Form.Get("token")), Decision: decision, SelectedScopes: selected})
	if err != nil {
		s.writeOAuthError(w, err)
		return
	}
	http.Redirect(w, r, result.RedirectURI, http.StatusFound)
}

func (s *Server[A]) token(w http.ResponseWriter, r *http.Request) {
	s.headers(w)
	if r.Method != http.MethodPost {
		s.method(w, http.MethodPost)
		return
	}
	if err := s.parseForm(w, r); err != nil {
		s.writeOAuthError(w, invalid(oauthserver.ErrorInvalidRequest, "token request is invalid", err))
		return
	}
	if r.Form.Get("grant_type") == "authorization_code" {
		result, err := s.engine.ExchangeCode(r.Context(), oauthserver.ExchangeCodeInput{Code: r.Form.Get("code"), ClientID: r.Form.Get("client_id"), RedirectURI: r.Form.Get("redirect_uri"), CodeVerifier: r.Form.Get("code_verifier")})
		if err != nil {
			s.writeOAuthError(w, err)
			return
		}
		s.writeToken(w, result)
		return
	}
	if r.Form.Get("grant_type") == "refresh_token" {
		result, err := s.engine.Refresh(r.Context(), oauthserver.RefreshInput{RefreshToken: r.Form.Get("refresh_token"), ClientID: r.Form.Get("client_id")})
		if err != nil {
			s.writeOAuthError(w, err)
			return
		}
		s.writeToken(w, result)
		return
	}
	s.writeOAuthError(w, serverOAuthError(oauthserver.ErrorUnsupportedGrant, "grant type is not supported", 400, oauthserver.ErrInvalid))
}
func (s *Server[A]) revoke(w http.ResponseWriter, r *http.Request) {
	s.headers(w)
	if r.Method != http.MethodPost {
		s.method(w, http.MethodPost)
		return
	}
	if err := s.parseForm(w, r); err != nil {
		s.writeOAuthError(w, invalid(oauthserver.ErrorInvalidRequest, "revocation request is invalid", err))
		return
	}
	if err := s.engine.Revoke(r.Context(), oauthserver.RevokeInput{Token: r.Form.Get("token"), ClientID: r.Form.Get("client_id")}); err != nil {
		s.writeOAuthError(w, serverOAuthError(oauthserver.ErrorTemporary, "revocation unavailable", 503, err))
		return
	}
	w.WriteHeader(http.StatusOK)
}

type CallbackAuthenticator[A any] interface {
	AuthenticateCallback(context.Context, *http.Request) (oauthserver.TransactionToken, oauthserver.Principal[A], error)
}

func (s *Server[A]) IdentityCallbackHandler(authenticator CallbackAuthenticator[A]) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.headers(w)
		transaction, principal, err := authenticator.AuthenticateCallback(r.Context(), r)
		if err != nil {
			s.writeOAuthError(w, serverOAuthError(oauthserver.ErrorAccessDenied, "login was not accepted", 400, err))
			return
		}
		result, err := s.engine.CompleteLogin(r.Context(), oauthserver.CompleteLoginInput[A]{Transaction: transaction, Principal: principal})
		if err != nil {
			s.writeOAuthError(w, err)
			return
		}
		http.Redirect(w, r, result.ConsentURL, http.StatusFound)
	})
}

func (s *Server[A]) authorizationQuery(r *http.Request) (url.Values, error) {
	if int64(len(r.URL.RawQuery)) > s.policy.MaxBodyBytes {
		return nil, errors.New("authorization query is too large")
	}
	query := r.URL.Query()
	for key, values := range query {
		if len(key) > s.policy.MaxFieldBytes || len(values) != 1 || len(values[0]) > s.policy.MaxFieldBytes {
			return nil, errors.New("authorization query is ambiguous or too large")
		}
	}
	return query, nil
}

func (s *Server[A]) parseForm(w http.ResponseWriter, r *http.Request, arrayFields ...string) error {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/x-www-form-urlencoded" {
		return errors.New("content type must be application/x-www-form-urlencoded")
	}
	if r.URL.RawQuery != "" {
		return errors.New("form endpoint does not accept query parameters")
	}
	r.Body = http.MaxBytesReader(w, r.Body, s.policy.MaxBodyBytes)
	if err := r.ParseForm(); err != nil {
		return err
	}
	r.Form = r.PostForm
	allowedArrays := make(map[string]struct{}, len(arrayFields))
	for _, field := range arrayFields {
		allowedArrays[field] = struct{}{}
	}
	for key, values := range r.PostForm {
		arrayField := hasKey(allowedArrays, key)
		if len(key) > s.policy.MaxFieldBytes || (arrayField && len(values) > s.policy.MaxArrayLength) || (!arrayField && len(values) != 1) {
			return errors.New("form limits or parameter cardinality exceeded")
		}
		for _, value := range values {
			if len(value) > s.policy.MaxFieldBytes {
				return errors.New("form field is too large")
			}
		}
	}
	return nil
}

func validMetadataList(values []string, maxLength int, allowed ...string) bool {
	if len(values) > maxLength {
		return false
	}
	allowedSet := make(map[string]struct{}, len(allowed))
	for _, value := range allowed {
		allowedSet[value] = struct{}{}
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if _, ok := allowedSet[value]; !ok {
			return false
		}
		if _, duplicate := seen[value]; duplicate {
			return false
		}
		seen[value] = struct{}{}
	}
	return true
}

func hasKey(values map[string]struct{}, key string) bool { _, ok := values[key]; return ok }

func (s *Server[A]) decodeJSON(w http.ResponseWriter, r *http.Request, destination any) error {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return errors.New("content type must be application/json")
	}
	r.Body = http.MaxBytesReader(w, r.Body, s.policy.MaxBodyBytes)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return errors.New("request must contain one JSON value")
	}
	return nil
}
func (s *Server[A]) writeToken(w http.ResponseWriter, result oauthserver.TokenResponse) {
	s.writeJSON(w, http.StatusOK, map[string]any{"access_token": result.AccessToken, "token_type": result.TokenType, "expires_in": int(result.ExpiresIn / time.Second), "refresh_token": result.RefreshToken, "scope": result.Scopes.String()})
}
func (s *Server[A]) writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
func (s *Server[A]) writeOAuthError(w http.ResponseWriter, err error) {
	var oauthErr *oauthserver.OAuthError
	if !errors.As(err, &oauthErr) {
		oauthErr = serverOAuthError(oauthserver.ErrorTemporary, "service is temporarily unavailable", 503, err)
	}
	s.writeJSON(w, oauthErr.HTTPStatus, map[string]string{"error": string(oauthErr.Code), "error_description": oauthErr.SafeDescription})
}
func (s *Server[A]) headers(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("X-Content-Type-Options", "nosniff")
}
func (s *Server[A]) method(w http.ResponseWriter, allowed string) {
	w.Header().Set("Allow", allowed)
	w.WriteHeader(http.StatusMethodNotAllowed)
}
func (s *Server[A]) redirectLoginError(w http.ResponseWriter, r *http.Request, login oauthserver.LoginContext, err error) {
	redirect, redirectErr := s.engine.ValidateRedirect(r.Context(), string(login.ClientID), string(login.RedirectURI))
	if redirectErr != nil {
		s.writeOAuthError(w, err)
		return
	}
	s.redirectAuthorizationError(w, r, redirect, login.State, err)
}

func (s *Server[A]) redirectAuthorizationError(w http.ResponseWriter, r *http.Request, redirect oauthserver.TrustedRedirect, state string, err error) {
	var oauthErr *oauthserver.OAuthError
	if !errors.As(err, &oauthErr) {
		oauthErr = serverOAuthError(oauthserver.ErrorTemporary, "authorization is temporarily unavailable", http.StatusServiceUnavailable, err)
	}
	destination, parseErr := url.Parse(string(redirect.URI()))
	if parseErr != nil {
		s.writeOAuthError(w, err)
		return
	}
	query := destination.Query()
	query.Set("error", string(oauthErr.Code))
	query.Set("error_description", oauthErr.SafeDescription)
	query.Set("state", state)
	destination.RawQuery = query.Encode()
	http.Redirect(w, r, destination.String(), http.StatusFound)
}

func (s *Server[A]) absolute(path string) string {
	return strings.TrimRight(s.issuer, "/") + path
}
func invalid(code oauthserver.ErrorCode, description string, cause error) error {
	return serverOAuthError(code, description, http.StatusBadRequest, cause)
}
func serverOAuthError(code oauthserver.ErrorCode, description string, status int, cause error) *oauthserver.OAuthError {
	return &oauthserver.OAuthError{Code: code, SafeDescription: description, HTTPStatus: status, Cause: cause}
}

const consentPage = `<!doctype html><html><head><meta charset="utf-8"><title>Authorize</title></head><body><main><h1>Authorize {{.ClientName}}</h1><p>{{.PrincipalName}} ({{.PrincipalEmail}})</p><p>{{.ResourceName}}</p><p>Destination: <code>{{.RedirectURI}}</code></p><p>Client trust: {{.ClientTrust}}</p><p>Access-token lifetime: {{.AccessTokenTTL}}</p><p>Authorization ends: {{.AuthorizationEnds}}</p><form method="post" action="/oauth/consent"><input type="hidden" name="token" value="{{.Token}}">{{range .Scopes}}<label><input type="checkbox" name="scope" value="{{.Scope}}" checked>{{.Scope}}</label>{{end}}<button name="decision" value="approve" type="submit">Approve</button><button name="decision" value="deny" type="submit">Deny</button></form></main></body></html>`
