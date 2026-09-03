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
	Engine   *oauthserver.Engine[A]
	Login    oauthserver.LoginStarter
	Observer RequestObserver
}

type Server[A any] struct {
	engine          *oauthserver.Engine[A]
	issuer          string
	resources       oauthserver.ResourceRegistry
	tokens          oauthserver.TokenService[A]
	login           oauthserver.LoginStarter
	policy          oauthserver.HTTPPolicy
	observer        RequestObserver
	consentTemplate *template.Template
}

func New[A any](config Config[A]) (*Server[A], error) {
	if config.Engine == nil {
		return nil, errors.New("HTTP transport configuration is incomplete")
	}
	return &Server[A]{engine: config.Engine, issuer: config.Engine.Issuer(), resources: config.Engine.Resources(), tokens: config.Engine.Tokens(), login: config.Login, policy: config.Engine.HTTPPolicy(), observer: config.Observer, consentTemplate: template.Must(template.New("consent").Parse(consentPage))}, nil
}

func (s *Server[A]) correlated(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		Correlation(handler, s.observer).ServeHTTP(w, r)
	}
}

func (s *Server[A]) Mount(mux *http.ServeMux) {
	mux.HandleFunc("/.well-known/oauth-authorization-server", s.correlated(s.metadata))
	mux.HandleFunc("/jwks.json", s.correlated(s.jwks))
	mux.HandleFunc("/oauth/register", s.correlated(s.register))
	mux.HandleFunc("/oauth/authorize", s.correlated(s.authorize))
	mux.HandleFunc("/oauth/consent", s.correlated(s.consent))
	mux.HandleFunc("/oauth/consent.css", s.correlated(s.consentCSS))
	mux.HandleFunc("/oauth/token", s.correlated(s.token))
	mux.HandleFunc("/oauth/revoke", s.correlated(s.revoke))
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
	TokenAuthMethods      []string `json:"token_endpoint_auth_methods_supported"`
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
	s.writeJSON(w, http.StatusOK, authorizationMetadata{Issuer: s.issuer, AuthorizationEndpoint: s.absolute("/oauth/authorize"), TokenEndpoint: s.absolute("/oauth/token"), RegistrationEndpoint: s.absolute("/oauth/register"), RevocationEndpoint: s.absolute("/oauth/revoke"), JWKSURI: s.absolute("/jwks.json"), ResponseTypes: []string{"code"}, GrantTypes: []string{"authorization_code", "refresh_token"}, CodeChallengeMethods: []string{"S256"}, TokenAuthMethods: []string{"none"}, ScopesSupported: scopes})
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
	if err := s.decodeRegistrationJSON(w, r, &request); err != nil {
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
	// form-action also governs redirects after form submission in browsers.
	// Consent may redirect only to the origin snapshotted from the validated,
	// registered redirect URI; never interpolate request input here.
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'self'; form-action 'self' "+view.RedirectOrigin+"; frame-ancestors 'none'; base-uri 'none'")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")
	if err := s.consentTemplate.Execute(w, view); err != nil {
		return
	}
}
func (s *Server[A]) consentCSS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.method(w, http.MethodGet)
		return
	}
	w.Header().Set("Content-Type", "text/css; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	_, _ = io.WriteString(w, consentStyles)
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

func (s *Server[A]) decodeRegistrationJSON(w http.ResponseWriter, r *http.Request, destination any) error {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return errors.New("content type must be application/json")
	}
	r.Body = http.MaxBytesReader(w, r.Body, s.policy.MaxBodyBytes)
	decoder := json.NewDecoder(r.Body)
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

const consentPage = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Authorize CoinVault</title><link rel="stylesheet" href="/oauth/consent.css"></head>
<body><main class="shell"><section class="card"><header class="brand"><span class="mark">CV</span><span><strong>CoinVault</strong><small>Secure connector authorization</small></span></header>
<div class="intro"><p class="eyebrow">Authorization request</p><h1>Connect {{.ClientName}}</h1><p class="lede">Review the access this connector is requesting from {{.ResourceName}}.</p></div>
<div class="identity"><span class="avatar">ID</span><span><strong>{{.PrincipalName}}</strong><small>{{.PrincipalEmail}}</small></span></div>
<form method="post" action="/oauth/consent"><input type="hidden" name="token" value="{{.Token}}"><fieldset><legend>Requested access</legend><div class="scopes">{{range .Scopes}}<label class="scope"><input type="checkbox" name="scope" value="{{.Scope}}" checked><span><strong>{{.Scope}}</strong><small>Grant this capability to the connector</small></span></label>{{end}}</div></fieldset>
<dl class="details"><div><dt>Destination</dt><dd>{{.RedirectOrigin}}</dd></div><div><dt>Client trust</dt><dd>{{.ClientTrust}}</dd></div><div><dt>Access token</dt><dd>{{.AccessTokenTTL}}</dd></div><div><dt>Authorization ends</dt><dd>{{.AuthorizationEnds}}</dd></div></dl>
<div class="actions"><button class="approve" name="decision" value="approve" type="submit">Approve connection</button><button class="deny" name="decision" value="deny" type="submit">Deny</button></div></form><footer>Only the selected scopes will be granted. You can revoke access later.</footer></section></main></body></html>`

const consentStyles = `:root{color-scheme:dark;--bg:#090a0c;--panel:#121418;--line:#2a2d33;--muted:#9a9fa9;--text:#f4f2eb;--gold:#d7aa45;--gold2:#f0cd72;--danger:#d36b67}*{box-sizing:border-box}body{margin:0;min-height:100vh;background:radial-gradient(circle at 50% -20%,#262019 0,#0d0e11 42%,var(--bg) 75%);color:var(--text);font:15px/1.5 Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}.shell{min-height:100vh;display:grid;place-items:center;padding:32px 16px}.card{width:min(620px,100%);background:linear-gradient(180deg,#17191e,var(--panel));border:1px solid #33363d;border-radius:18px;box-shadow:0 24px 80px #0009;overflow:hidden}.brand{display:flex;align-items:center;gap:12px;padding:20px 24px;border-bottom:1px solid var(--line)}.brand span:last-child,.identity span:last-child{display:flex;flex-direction:column}.brand small,.identity small{color:var(--muted)}.mark,.avatar{display:grid;place-items:center;flex:0 0 auto;width:42px;height:42px;border-radius:12px;background:linear-gradient(145deg,var(--gold2),#9b6b16);color:#171006;font-weight:900;letter-spacing:-.04em}.intro{padding:28px 28px 12px}.eyebrow{margin:0 0 5px;color:var(--gold2);font-size:12px;font-weight:750;letter-spacing:.13em;text-transform:uppercase}h1{margin:0;font-size:clamp(26px,5vw,36px);line-height:1.15;letter-spacing:-.035em}.lede{color:#c2c5cc;margin:12px 0 0}.identity{display:flex;align-items:center;gap:12px;margin:12px 28px 24px;padding:14px;border:1px solid var(--line);border-radius:12px;background:#0d0f12}.avatar{width:38px;height:38px;border-radius:50%;text-transform:uppercase}form{padding:0 28px 28px}fieldset{padding:0;border:0}legend{margin-bottom:10px;font-size:13px;font-weight:700;color:#d8d9dc}.scopes{display:grid;gap:8px}.scope{display:flex;align-items:flex-start;gap:12px;padding:13px 14px;border:1px solid var(--line);border-radius:10px;background:#0e1013;cursor:pointer}.scope:has(input:checked){border-color:#705a2b;background:#18150f}.scope input{margin-top:4px;accent-color:var(--gold)}.scope span{display:flex;min-width:0;flex-direction:column}.scope strong{overflow-wrap:anywhere;font-size:13px}.scope small{color:var(--muted)}.details{display:grid;gap:8px;margin:22px 0;padding-top:18px;border-top:1px solid var(--line)}.details div{display:flex;justify-content:space-between;gap:20px}.details dt{color:var(--muted)}.details dd{margin:0;max-width:65%;overflow-wrap:anywhere;text-align:right}.actions{display:flex;gap:10px}.actions button{border-radius:10px;padding:12px 18px;font:inherit;font-weight:750;cursor:pointer}.approve{flex:1;border:1px solid #e4bb5d;background:linear-gradient(180deg,var(--gold2),var(--gold));color:#1b1408}.approve:hover{filter:brightness(1.08)}.deny{border:1px solid #42464f;background:#1b1e23;color:#ddd}.deny:hover{border-color:var(--danger);color:#ffd5d2}footer{padding:15px 28px;border-top:1px solid var(--line);color:var(--muted);font-size:12px;text-align:center}@media(max-width:520px){.shell{padding:0}.card{min-height:100vh;border:0;border-radius:0}.intro,.identity,form{margin-left:18px;margin-right:18px;padding-left:0;padding-right:0}.details div{display:block}.details dd{max-width:none;text-align:left}.actions{flex-direction:column}.deny{order:-1}}`
