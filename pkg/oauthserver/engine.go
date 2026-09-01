package oauthserver

import (
	"context"
	"errors"
	"net/url"
	"time"
)

type Dependencies[A any] struct {
	Store       Store[A]
	Resources   ResourceRegistry
	Scopes      ScopePolicy[A]
	Revalidator PrincipalRevalidator[A]
	Tokens      TokenService[A]
	Secrets     SecretSource
	Clock       Clock
	Audit       AuditSink
}

type Engine[A any] struct {
	config Config
	deps   Dependencies[A]
}

func New[A any](config Config, deps Dependencies[A]) (*Engine[A], error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	if deps.Store == nil || deps.Resources == nil || deps.Scopes == nil || deps.Revalidator == nil || deps.Tokens == nil || deps.Secrets == nil || deps.Clock == nil {
		return nil, invalidValue("engine dependencies")
	}
	if deps.Tokens.TokenIssuer() != config.Issuer {
		return nil, invalidValue("token issuer")
	}
	if err := validateResourceRegistry(context.Background(), config.Resources, config.SupportedScopes, deps.Resources); err != nil {
		return nil, invalidValue("resource registry")
	}
	if deps.Audit == nil {
		deps.Audit = NopAudit{}
	}
	return &Engine[A]{config: config, deps: deps}, nil
}

func (e *Engine[A]) Issuer() string              { return e.config.Issuer }
func (e *Engine[A]) Resources() ResourceRegistry { return e.deps.Resources }
func (e *Engine[A]) Tokens() TokenService[A]     { return e.deps.Tokens }
func (e *Engine[A]) HTTPPolicy() HTTPPolicy      { return e.config.HTTP }
func (e *Engine[A]) now() time.Time              { return e.deps.Clock.Now().UTC() }

func (e *Engine[A]) RegisterClient(ctx context.Context, in RegisterClientInput) (RegisterClientResult, error) {
	if len(in.DisplayName) == 0 || len(in.DisplayName) > e.config.StatePolicy.Registration.MaxDisplayName || len(in.RedirectURIs) == 0 || len(in.RedirectURIs) > e.config.StatePolicy.Registration.MaxRedirectURIs {
		return RegisterClientResult{}, oauthError(ErrorInvalidClientMetadata, "client metadata is invalid", 400, ErrInvalid)
	}
	redirects := make([]RedirectURI, 0, len(in.RedirectURIs))
	seen := make(map[RedirectURI]struct{}, len(in.RedirectURIs))
	for _, raw := range in.RedirectURIs {
		redirect, err := NewRedirectURI(raw)
		if err != nil || !validRedirectURI(string(redirect), true) {
			return RegisterClientResult{}, oauthError(ErrorInvalidRedirectURI, "redirect URI is invalid", 400, err)
		}
		if len(redirect) > e.config.StatePolicy.Registration.MaxRedirectBytes {
			return RegisterClientResult{}, oauthError(ErrorInvalidRedirectURI, "redirect URI is too long", 400, ErrInvalid)
		}
		if _, exists := seen[redirect]; exists {
			return RegisterClientResult{}, oauthError(ErrorInvalidRedirectURI, "redirect URI is duplicated", 400, ErrInvalid)
		}
		seen[redirect] = struct{}{}
		redirects = append(redirects, redirect)
	}
	scopes, err := NewScopeSet(stringsToScopes(in.RequestedScopes)...)
	if err != nil || len(scopes.Values()) > e.config.StatePolicy.Registration.MaxScopeCount || !scopes.IsSubsetOf(e.config.SupportedScopes) {
		return RegisterClientResult{}, oauthError(ErrorInvalidScope, "requested scopes are invalid", 400, err)
	}
	id, err := e.deps.Secrets.NewTransactionToken()
	if err != nil {
		return RegisterClientResult{}, oauthError(ErrorTemporary, "could not create client", 503, err)
	}
	clientID, err := NewClientID(string(id))
	if err != nil {
		return RegisterClientResult{}, oauthError(ErrorTemporary, "could not create client", 503, err)
	}
	now := e.now()
	client := Client{ID: clientID, DisplayName: in.DisplayName, Trust: ClientTrustUnverified, RedirectURIs: redirects, AllowedScopes: scopes, CreatedAt: now, LastUsedAt: now}
	if err := e.deps.Store.RegisterClient(ctx, client, e.config.StatePolicy); err != nil {
		return RegisterClientResult{}, mapStoreError(err, ErrorInvalidClientMetadata)
	}
	e.audit(ctx, "register_client", "success", Principal[A]{}, client.ID, "", scopes, "")
	return RegisterClientResult{Client: client}, nil
}

type RegisterClientInput struct {
	DisplayName     string
	RedirectURIs    []string
	RequestedScopes []string
}

type RegisterClientResult struct{ Client Client }

type BeginAuthorizationInput struct {
	ClientID        string
	RedirectURI     string
	ResponseType    string
	State           string
	CodeChallenge   string
	ChallengeMethod string
	Scopes          []string
	Resource        string
}

func (e *Engine[A]) ValidateRedirect(ctx context.Context, clientIDRaw, redirectRaw string) (TrustedRedirect, error) {
	clientID, err := NewClientID(clientIDRaw)
	if err != nil {
		return TrustedRedirect{}, err
	}
	redirect, err := NewRedirectURI(redirectRaw)
	if err != nil || !validRedirectURI(string(redirect), true) {
		return TrustedRedirect{}, ErrBinding
	}
	client, err := e.deps.Store.GetClient(ctx, clientID)
	if err != nil {
		return TrustedRedirect{}, err
	}
	if !containsRedirect(client.RedirectURIs, redirect) {
		return TrustedRedirect{}, ErrBinding
	}
	return TrustedRedirect{uri: redirect}, nil
}

type BeginAuthorizationResult struct {
	Transaction  TransactionToken
	LoginContext LoginContext
}

func (e *Engine[A]) BeginAuthorization(ctx context.Context, in BeginAuthorizationInput) (BeginAuthorizationResult, error) {
	clientID, err := NewClientID(in.ClientID)
	if err != nil || in.ResponseType != "code" || in.State == "" || len(in.State) > e.config.HTTP.MaxFieldBytes {
		return BeginAuthorizationResult{}, invalidArgument("authorization request is invalid", err)
	}
	redirect, err := NewRedirectURI(in.RedirectURI)
	if err != nil || !validRedirectURI(string(redirect), true) {
		return BeginAuthorizationResult{}, oauthError(ErrorInvalidRedirectURI, "redirect URI is invalid", 400, err)
	}
	challenge, err := NewPKCEChallenge(in.CodeChallenge, in.ChallengeMethod)
	if err != nil {
		return BeginAuthorizationResult{}, invalidArgument("PKCE is required", err)
	}
	requested, err := NewScopeSet(stringsToScopes(in.Scopes)...)
	if err != nil {
		return BeginAuthorizationResult{}, oauthError(ErrorInvalidScope, "requested scopes are invalid", 400, err)
	}
	resourceID, err := NewResourceID(in.Resource)
	if err != nil {
		return BeginAuthorizationResult{}, oauthError(ErrorInvalidTarget, "resource is invalid", 400, err)
	}
	client, err := e.deps.Store.GetClient(ctx, clientID)
	if err != nil {
		return BeginAuthorizationResult{}, invalidArgument("client is invalid", err)
	}
	if !containsRedirect(client.RedirectURIs, redirect) {
		return BeginAuthorizationResult{}, oauthError(ErrorInvalidRedirectURI, "redirect URI is not registered", 400, ErrBinding)
	}
	resource, err := e.deps.Resources.LookupResource(ctx, resourceID)
	if err != nil {
		return BeginAuthorizationResult{}, oauthError(ErrorInvalidTarget, "resource is not supported", 400, err)
	}
	if !requested.IsSubsetOf(client.AllowedScopes) || !requested.IsSubsetOf(resource.SupportedScopes) || !requested.IsSubsetOf(e.config.SupportedScopes) {
		return BeginAuthorizationResult{}, oauthError(ErrorInvalidScope, "requested scopes are not allowed", 400, ErrInvalid)
	}
	if err := e.deps.Store.TouchClient(ctx, client.ID, e.now()); err != nil {
		return BeginAuthorizationResult{}, mapStoreError(err, ErrorInvalidRequest)
	}
	token, err := e.deps.Secrets.NewTransactionToken()
	if err != nil {
		return BeginAuthorizationResult{}, oauthError(ErrorTemporary, "could not start authorization", 503, err)
	}
	now := e.now()
	authorization := AuthorizationTransaction{Token: token, ClientID: clientID, RedirectURI: redirect, State: in.State, PKCEChallenge: challenge, RequestedScopes: requested, Resource: resourceID, ExpiresAt: now.Add(e.config.TransactionTTL)}
	if err := e.deps.Store.CreateAuthorization(ctx, authorization, e.config.StatePolicy); err != nil {
		return BeginAuthorizationResult{}, mapStoreError(err, ErrorInvalidRequest)
	}
	e.audit(ctx, "begin_authorization", "success", Principal[A]{}, clientID, resourceID, requested, "")
	return BeginAuthorizationResult{Transaction: token, LoginContext: LoginContext{Transaction: token, ClientID: clientID, RedirectURI: redirect, State: in.State}}, nil
}

type CompleteLoginInput[A any] struct {
	Transaction TransactionToken
	Principal   Principal[A]
}
type CompleteLoginResult struct {
	ConsentToken ConsentToken
	ConsentURL   string
}

func (e *Engine[A]) CompleteLogin(ctx context.Context, in CompleteLoginInput[A]) (CompleteLoginResult, error) {
	if _, err := NewSubject(string(in.Principal.Subject)); err != nil {
		return CompleteLoginResult{}, oauthError(ErrorAccessDenied, "authenticated principal is invalid", 400, err)
	}
	auth, err := e.deps.Store.GetAuthorization(ctx, DigestCredential(string(in.Transaction)))
	if err != nil {
		return CompleteLoginResult{}, invalidGrant(err)
	}
	if e.now().After(auth.ExpiresAt) {
		return CompleteLoginResult{}, invalidGrant(ErrExpired)
	}
	client, err := e.deps.Store.GetClient(ctx, auth.ClientID)
	if err != nil || !containsRedirect(client.RedirectURIs, auth.RedirectURI) {
		return CompleteLoginResult{}, invalidGrant(err)
	}
	resource, err := e.deps.Resources.LookupResource(ctx, auth.Resource)
	if err != nil {
		return CompleteLoginResult{}, invalidGrant(err)
	}
	available, err := e.deps.Scopes.AvailableScopes(ctx, in.Principal, resource)
	if err != nil {
		return CompleteLoginResult{}, oauthError(ErrorTemporary, "could not determine permissions", 503, err)
	}
	allowed := auth.RequestedScopes.Intersect(client.AllowedScopes).Intersect(resource.SupportedScopes).Intersect(available)
	consentToken, err := e.deps.Secrets.NewConsentToken()
	if err != nil {
		return CompleteLoginResult{}, oauthError(ErrorTemporary, "could not create consent", 503, err)
	}
	consent := ConsentSession[A]{Token: consentToken, Client: snapshotClient(client, auth.RedirectURI), State: auth.State, PKCEChallenge: auth.PKCEChallenge, Principal: in.Principal, AllowedScopes: allowed, Resource: auth.Resource, ExpiresAt: e.now().Add(e.config.ConsentTTL)}
	if err := e.deps.Store.CommitLogin(ctx, LoginCommit[A]{TransactionDigest: DigestCredential(string(in.Transaction)), Consent: consent}, e.config.StatePolicy); err != nil {
		return CompleteLoginResult{}, mapStoreError(err, ErrorInvalidGrant)
	}
	e.audit(ctx, "complete_login", "success", in.Principal, auth.ClientID, auth.Resource, allowed, "")
	return CompleteLoginResult{ConsentToken: consentToken, ConsentURL: "/oauth/consent?token=" + url.QueryEscape(string(consentToken))}, nil
}

func (e *Engine[A]) ConsentView(ctx context.Context, token ConsentToken) (ConsentView, error) {
	consent, err := e.deps.Store.GetConsent(ctx, DigestCredential(string(token)))
	if err != nil {
		return ConsentView{}, invalidGrant(err)
	}
	if e.now().After(consent.ExpiresAt) {
		return ConsentView{}, invalidGrant(ErrExpired)
	}
	resource, err := e.deps.Resources.LookupResource(ctx, consent.Resource)
	if err != nil {
		return ConsentView{}, invalidGrant(err)
	}
	scopes := make([]ConsentScope, 0, len(consent.AllowedScopes.Values()))
	for _, scope := range consent.AllowedScopes.Values() {
		scopes = append(scopes, ConsentScope{Scope: scope})
	}
	return ConsentView{Token: token, ResourceName: resource.DisplayName, PrincipalName: consent.Principal.DisplayName, PrincipalEmail: consent.Principal.Email, ClientName: consent.Client.DisplayName, ClientTrust: consent.Client.Trust, RedirectOrigin: consent.Client.RedirectOrigin, RedirectURI: string(consent.Client.RedirectURI), AccessTokenTTL: e.config.AccessTTL, AuthorizationEnds: consent.ExpiresAt.Add(e.config.RefreshTTL), Scopes: scopes}, nil
}

type ConsentDecision uint8

const (
	ConsentDecisionUnknown ConsentDecision = iota
	ConsentDecisionApprove
	ConsentDecisionDeny
)

type DecideConsentInput struct {
	Token          ConsentToken
	Decision       ConsentDecision
	SelectedScopes []Scope
}
type DecideConsentResult struct{ RedirectURI string }

func (e *Engine[A]) DecideConsent(ctx context.Context, in DecideConsentInput) (DecideConsentResult, error) {
	consent, err := e.deps.Store.GetConsent(ctx, DigestCredential(string(in.Token)))
	if err != nil {
		return DecideConsentResult{}, invalidGrant(err)
	}
	if e.now().After(consent.ExpiresAt) {
		return DecideConsentResult{}, invalidGrant(ErrExpired)
	}
	if in.Decision != ConsentDecisionApprove && in.Decision != ConsentDecisionDeny {
		return DecideConsentResult{}, invalidArgument("consent decision is invalid", ErrInvalid)
	}
	selected, err := NewScopeSet(in.SelectedScopes...)
	if err != nil {
		return DecideConsentResult{}, oauthError(ErrorInvalidScope, "selected scopes are invalid", 400, err)
	}
	if in.Decision == ConsentDecisionApprove && !selected.IsSubsetOf(consent.AllowedScopes) {
		return DecideConsentResult{}, oauthError(ErrorInvalidScope, "selected scopes are not allowed", 400, ErrInvalid)
	}
	var code *AuthorizationCodeRecord[A]
	var rawCode AuthorizationCode
	if in.Decision == ConsentDecisionApprove {
		rawCode, err = e.deps.Secrets.NewAuthorizationCode()
		if err != nil {
			return DecideConsentResult{}, oauthError(ErrorTemporary, "could not create authorization code", 503, err)
		}
		code = &AuthorizationCodeRecord[A]{Digest: DigestCredential(string(rawCode)), ClientID: consent.Client.ID, RedirectURI: consent.Client.RedirectURI, PKCEChallenge: consent.PKCEChallenge, Principal: consent.Principal, Scopes: selected, Resource: consent.Resource, State: consent.State, ExpiresAt: e.now().Add(e.config.CodeTTL)}
	}
	result, err := e.deps.Store.CommitConsent(ctx, ConsentCommit[A]{ConsentDigest: DigestCredential(string(in.Token)), Code: valueOrEmpty(code), Decision: in.Decision}, e.config.StatePolicy)
	if err != nil {
		return DecideConsentResult{}, mapStoreError(err, ErrorInvalidGrant)
	}
	redirect, err := redirectResult(consent.Client.RedirectURI, consent.State, in.Decision, string(rawCode))
	if err != nil {
		return DecideConsentResult{}, err
	}
	_ = result
	outcome := "denied"
	if in.Decision == ConsentDecisionApprove {
		outcome = "approved"
	}
	e.audit(ctx, "decide_consent", outcome, consent.Principal, consent.Client.ID, consent.Resource, selected, "")
	return DecideConsentResult{RedirectURI: redirect}, nil
}

func (e *Engine[A]) ExchangeCode(ctx context.Context, in ExchangeCodeInput) (TokenResponse, error) {
	clientID, err := NewClientID(in.ClientID)
	if err != nil || in.Code == "" {
		return TokenResponse{}, invalidGrant(err)
	}
	redirect, err := NewRedirectURI(in.RedirectURI)
	if err != nil {
		return TokenResponse{}, invalidGrant(err)
	}
	if err := ValidatePKCEVerifier(in.CodeVerifier); err != nil {
		return TokenResponse{}, invalidGrant(err)
	}
	code, err := e.deps.Store.GetCodeForExchange(ctx, CodeExchangeBinding{Digest: DigestCredential(in.Code), ClientID: clientID, RedirectURI: redirect, CodeVerifier: in.CodeVerifier})
	if err != nil {
		return TokenResponse{}, invalidGrant(err)
	}
	if e.now().After(code.ExpiresAt) || code.PKCEChallenge.Verify(in.CodeVerifier) != nil {
		return TokenResponse{}, invalidGrant(ErrBinding)
	}
	now := e.now()
	access, err := e.deps.Tokens.IssueAccessToken(ctx, AccessGrant[A]{Principal: code.Principal, ClientID: code.ClientID, Resource: code.Resource, Scopes: code.Scopes, IssuedAt: now, ExpiresAt: now.Add(e.config.AccessTTL)})
	if err != nil {
		return TokenResponse{}, oauthError(ErrorTemporary, "could not issue access token", 503, err)
	}
	refresh, err := e.deps.Secrets.NewRefreshToken()
	if err != nil {
		return TokenResponse{}, oauthError(ErrorTemporary, "could not issue refresh token", 503, err)
	}
	family, err := e.deps.Secrets.NewRefreshFamilyID()
	if err != nil {
		return TokenResponse{}, oauthError(ErrorTemporary, "could not issue refresh grant", 503, err)
	}
	grant := &RefreshGrant[A]{Digest: DigestCredential(string(refresh)), FamilyID: family, Generation: 0, ClientID: code.ClientID, Principal: code.Principal, Scopes: code.Scopes, Resource: code.Resource, ExpiresAt: now.Add(e.config.RefreshTTL)}
	if err := e.deps.Store.CommitCodeExchange(ctx, CodeExchangeCommit[A]{CodeDigest: code.Digest, Refresh: grant}, e.config.StatePolicy); err != nil {
		return TokenResponse{}, mapStoreError(err, ErrorInvalidGrant)
	}
	e.audit(ctx, "exchange_code", "success", code.Principal, code.ClientID, code.Resource, code.Scopes, "")
	return TokenResponse{AccessToken: access.Value, TokenType: access.TokenType, ExpiresIn: access.ExpiresAt.Sub(now), RefreshToken: string(refresh), Scopes: code.Scopes}, nil
}

type ExchangeCodeInput struct{ Code, ClientID, RedirectURI, CodeVerifier string }
type TokenResponse struct {
	AccessToken  string
	TokenType    string
	ExpiresIn    time.Duration
	RefreshToken string
	Scopes       ScopeSet
}

type RefreshInput struct{ RefreshToken, ClientID string }

func (e *Engine[A]) Refresh(ctx context.Context, in RefreshInput) (TokenResponse, error) {
	clientID, err := NewClientID(in.ClientID)
	if err != nil || in.RefreshToken == "" {
		return TokenResponse{}, invalidGrant(err)
	}
	grant, err := e.deps.Store.GetRefreshGrant(ctx, DigestCredential(in.RefreshToken))
	if err != nil {
		return TokenResponse{}, invalidGrant(err)
	}
	now := e.now()
	if !grant.RevokedAt.IsZero() || now.After(grant.ExpiresAt) || grant.ClientID != clientID {
		return TokenResponse{}, invalidGrant(ErrBinding)
	}
	revalidation, err := e.deps.Revalidator.Revalidate(ctx, grant.Principal.Subject)
	if err != nil {
		return TokenResponse{}, oauthError(ErrorTemporary, "identity could not be revalidated", 503, err)
	}
	switch revalidation.Status {
	case RevalidationUnknown:
		return TokenResponse{}, oauthError(ErrorTemporary, "identity could not be revalidated", 503, ErrInvalid)
	case RevalidationIneligible:
		if err := e.deps.Store.RevokeRefreshFamily(ctx, grant.FamilyID, now); err != nil {
			return TokenResponse{}, oauthError(ErrorTemporary, "identity revocation could not be persisted", 503, err)
		}
		e.audit(ctx, "refresh", "revoked", grant.Principal, grant.ClientID, grant.Resource, grant.Scopes, "principal_ineligible")
		return TokenResponse{}, invalidGrant(ErrRevoked)
	case RevalidationEligible:
		if revalidation.Principal.Subject == "" || revalidation.Principal.Subject != grant.Principal.Subject {
			return TokenResponse{}, oauthError(ErrorTemporary, "identity could not be revalidated", 503, ErrBinding)
		}
	default:
		return TokenResponse{}, oauthError(ErrorTemporary, "identity could not be revalidated", 503, ErrInvalid)
	}
	resource, err := e.deps.Resources.LookupResource(ctx, grant.Resource)
	if err != nil {
		return TokenResponse{}, invalidGrant(err)
	}
	available, err := e.deps.Scopes.AvailableScopes(ctx, revalidation.Principal, resource)
	if err != nil {
		return TokenResponse{}, oauthError(ErrorTemporary, "could not determine permissions", 503, err)
	}
	nextScopes := grant.Scopes.Intersect(available)
	access, err := e.deps.Tokens.IssueAccessToken(ctx, AccessGrant[A]{Principal: revalidation.Principal, ClientID: grant.ClientID, Resource: grant.Resource, Scopes: nextScopes, IssuedAt: now, ExpiresAt: now.Add(e.config.AccessTTL)})
	if err != nil {
		return TokenResponse{}, oauthError(ErrorTemporary, "could not issue access token", 503, err)
	}
	nextToken, err := e.deps.Secrets.NewRefreshToken()
	if err != nil {
		return TokenResponse{}, oauthError(ErrorTemporary, "could not issue refresh token", 503, err)
	}
	successor := RefreshGrant[A]{Digest: DigestCredential(string(nextToken)), FamilyID: grant.FamilyID, Generation: grant.Generation + 1, ClientID: grant.ClientID, Principal: revalidation.Principal, Scopes: nextScopes, Resource: grant.Resource, ExpiresAt: grant.ExpiresAt}
	if err := e.deps.Store.CommitRefreshRotation(ctx, RefreshRotation[A]{CurrentDigest: grant.Digest, FamilyID: grant.FamilyID, Generation: grant.Generation, Successor: successor}, e.config.StatePolicy); err != nil {
		return TokenResponse{}, mapStoreError(err, ErrorInvalidGrant)
	}
	e.audit(ctx, "refresh", "success", revalidation.Principal, grant.ClientID, grant.Resource, nextScopes, "")
	return TokenResponse{AccessToken: access.Value, TokenType: access.TokenType, ExpiresIn: access.ExpiresAt.Sub(now), RefreshToken: string(nextToken), Scopes: nextScopes}, nil
}

type RevokeInput struct{ Token, ClientID string }

func (e *Engine[A]) Revoke(ctx context.Context, in RevokeInput) error {
	clientID, err := NewClientID(in.ClientID)
	if err != nil || in.Token == "" {
		return nil
	}
	grant, err := e.deps.Store.GetRefreshGrant(ctx, DigestCredential(in.Token))
	if errors.Is(err, ErrNotFound) || (err == nil && grant.ClientID != clientID) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := e.deps.Store.RevokeRefreshFamily(ctx, grant.FamilyID, e.now()); err != nil {
		return err
	}
	e.audit(ctx, "revoke", "success", grant.Principal, grant.ClientID, grant.Resource, grant.Scopes, "")
	return nil
}

func containsRedirect(values []RedirectURI, target RedirectURI) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func snapshotClient(client Client, redirect RedirectURI) ConsentClientSnapshot {
	u, _ := url.Parse(string(redirect))
	return ConsentClientSnapshot{ID: client.ID, DisplayName: client.DisplayName, Trust: client.Trust, RedirectURI: redirect, RedirectOrigin: u.Scheme + "://" + u.Host}
}

func redirectResult(base RedirectURI, state string, decision ConsentDecision, rawCode string) (string, error) {
	u, err := url.Parse(string(base))
	if err != nil {
		return "", invalidArgument("redirect URI is invalid", err)
	}
	query := u.Query()
	query.Set("state", state)
	if decision == ConsentDecisionApprove {
		if rawCode == "" {
			return "", invalidArgument("authorization code is missing", ErrInvalid)
		}
		query.Set("code", rawCode)
	} else {
		query.Set("error", string(ErrorAccessDenied))
	}
	u.RawQuery = query.Encode()
	return u.String(), nil
}

func valueOrEmpty[A any](value *AuthorizationCodeRecord[A]) AuthorizationCodeRecord[A] {
	if value == nil {
		return AuthorizationCodeRecord[A]{}
	}
	return *value
}

func (e *Engine[A]) audit(ctx context.Context, operation, outcome string, principal Principal[A], client ClientID, resource ResourceID, scopes ScopeSet, reason string) {
	e.deps.Audit.Record(ctx, AuditEvent{Time: e.now(), Operation: operation, Outcome: outcome, Subject: principal.Subject, ClientID: client, Resource: resource, Scopes: scopes, ReasonCode: reason})
}

func mapStoreError(err error, code ErrorCode) *OAuthError {
	if errors.Is(err, ErrCapacity) {
		return oauthError(ErrorTemporary, "service capacity is temporarily unavailable", 503, err)
	}
	if errors.Is(err, ErrConflict) || errors.Is(err, ErrConsumed) || errors.Is(err, ErrExpired) || errors.Is(err, ErrRevoked) || errors.Is(err, ErrBinding) || errors.Is(err, ErrNotFound) {
		return oauthError(code, "the OAuth state is invalid", 400, err)
	}
	return oauthError(ErrorTemporary, "service is temporarily unavailable", 503, err)
}
