// Package jwttokens issues and verifies resource-bound JWT access tokens.
package jwttokens

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"sort"

	"github.com/go-go-golems/oh-auth/pkg/oauthserver"
	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

type Service[A any] struct {
	issuer       string
	tokenType    string
	activeKey    *rsa.PrivateKey
	verification map[string]*rsa.PublicKey
	activeKeyID  string
	claims       oauthserver.ClaimProvider[A]
	clock        oauthserver.Clock
}

type Config[A any] struct {
	Issuer       string
	TokenType    string
	ActiveKeyID  string
	ActiveKey    *rsa.PrivateKey
	Verification map[string]*rsa.PublicKey
	Claims       oauthserver.ClaimProvider[A]
	Clock        oauthserver.Clock
}

// Verifier validates access tokens in a resource-server process without
// requiring that process to hold an authorization-server signing key.
type Verifier struct {
	issuer       string
	tokenType    string
	verification map[string]*rsa.PublicKey
	clock        oauthserver.Clock
}

type VerificationConfig struct {
	Issuer    string
	TokenType string
	Keys      map[string]*rsa.PublicKey
	Clock     oauthserver.Clock
}

func NewVerifier(config VerificationConfig) (*Verifier, error) {
	if config.Issuer == "" || len(config.Keys) == 0 {
		return nil, errors.New("JWT verification configuration is incomplete")
	}
	if config.TokenType == "" {
		config.TokenType = "at+jwt"
	}
	verification := make(map[string]*rsa.PublicKey, len(config.Keys))
	for kid, key := range config.Keys {
		if kid == "" || key == nil || key.N == nil || key.N.BitLen() < 2048 || key.E < 3 {
			return nil, errors.New("JWT verification key is invalid")
		}
		verification[kid] = key
	}
	if config.Clock == nil {
		config.Clock = oauthserver.SystemClock{}
	}
	return &Verifier{issuer: config.Issuer, tokenType: config.TokenType, verification: verification, clock: config.Clock}, nil
}

func New[A any](config Config[A]) (*Service[A], error) {
	if config.Issuer == "" || config.ActiveKeyID == "" || config.ActiveKey == nil {
		return nil, errors.New("JWT configuration is incomplete")
	}
	if config.ActiveKey.N.BitLen() < 2048 || config.ActiveKey.Validate() != nil {
		return nil, errors.New("active JWT key must be a valid RSA key of at least 2048 bits")
	}
	if config.TokenType == "" {
		config.TokenType = "at+jwt"
	}
	verification := make(map[string]*rsa.PublicKey, len(config.Verification))
	for kid, key := range config.Verification {
		if kid == "" || key == nil || key.N == nil || key.N.BitLen() < 2048 || key.E < 3 {
			return nil, errors.New("JWT verification key is invalid")
		}
		verification[kid] = key
	}
	if existing, ok := verification[config.ActiveKeyID]; ok && (existing.N.Cmp(config.ActiveKey.N) != 0 || existing.E != config.ActiveKey.E) {
		return nil, errors.New("active JWT key ID conflicts with a different verification key")
	}
	verification[config.ActiveKeyID] = &config.ActiveKey.PublicKey
	if config.Clock == nil {
		config.Clock = oauthserver.SystemClock{}
	}
	return &Service[A]{issuer: config.Issuer, tokenType: config.TokenType, activeKey: config.ActiveKey, activeKeyID: config.ActiveKeyID, verification: verification, claims: config.Claims, clock: config.Clock}, nil
}

func (s *Service[A]) TokenIssuer() string { return s.issuer }

func (s *Service[A]) IssueAccessToken(ctx context.Context, grant oauthserver.AccessGrant[A]) (oauthserver.IssuedAccessToken, error) {
	if grant.Principal.Subject == "" || grant.ClientID == "" || grant.Resource == "" || grant.ExpiresAt.IsZero() || grant.IssuedAt.IsZero() {
		return oauthserver.IssuedAccessToken{}, errors.New("access grant is incomplete")
	}
	jti, err := newTokenID()
	if err != nil {
		return oauthserver.IssuedAccessToken{}, err
	}
	claims := jwt.Claims{Issuer: s.issuer, Subject: string(grant.Principal.Subject), Audience: jwt.Audience{string(grant.Resource)}, IssuedAt: jwt.NewNumericDate(grant.IssuedAt), NotBefore: jwt.NewNumericDate(grant.IssuedAt), Expiry: jwt.NewNumericDate(grant.ExpiresAt), ID: jti}
	extra := map[string]any{"client_id": string(grant.ClientID), "scope": grant.Scopes.String()}
	if s.claims != nil {
		provided, err := s.claims.ExtraClaims(ctx, grant.Principal)
		if err != nil {
			return oauthserver.IssuedAccessToken{}, err
		}
		for key, value := range provided {
			if isReservedClaim(key) {
				return oauthserver.IssuedAccessToken{}, fmt.Errorf("claim provider attempted reserved claim %q", key)
			}
			extra[key] = value
		}
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: s.activeKey}, (&jose.SignerOptions{}).WithType(jose.ContentType(s.tokenType)).WithHeader(jose.HeaderKey("kid"), s.activeKeyID))
	if err != nil {
		return oauthserver.IssuedAccessToken{}, err
	}
	serialized, err := jwt.Signed(signer).Claims(claims).Claims(extra).Serialize()
	if err != nil {
		return oauthserver.IssuedAccessToken{}, err
	}
	return oauthserver.IssuedAccessToken{Value: serialized, TokenType: "Bearer", ExpiresAt: grant.ExpiresAt}, nil
}

func (s *Service[A]) VerifyAccessToken(ctx context.Context, raw string, resource oauthserver.ResourceID) (oauthserver.VerifiedAccessToken, error) {
	return verifyAccessToken(ctx, s.issuer, s.tokenType, s.verification, s.clock, raw, resource)
}

func (v *Verifier) VerifyAccessToken(ctx context.Context, raw string, resource oauthserver.ResourceID) (oauthserver.VerifiedAccessToken, error) {
	return verifyAccessToken(ctx, v.issuer, v.tokenType, v.verification, v.clock, raw, resource)
}

func verifyAccessToken(_ context.Context, issuer, tokenType string, verification map[string]*rsa.PublicKey, clock oauthserver.Clock, raw string, resource oauthserver.ResourceID) (oauthserver.VerifiedAccessToken, error) {
	parsed, err := jwt.ParseSigned(raw, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		return oauthserver.VerifiedAccessToken{}, errors.New("access token is invalid")
	}
	if len(parsed.Headers) != 1 {
		return oauthserver.VerifiedAccessToken{}, errors.New("access token is invalid")
	}
	header := parsed.Headers[0]
	if header.Algorithm != string(jose.RS256) || header.KeyID == "" || header.JSONWebKey != nil || headerValue(header.ExtraHeaders, jose.HeaderType) != tokenType || hasUntrustedKeyHeader(header) {
		return oauthserver.VerifiedAccessToken{}, errors.New("access token header is invalid")
	}
	key, ok := verification[header.KeyID]
	if !ok {
		return oauthserver.VerifiedAccessToken{}, errors.New("access token key is unknown")
	}
	var claims jwt.Claims
	var all map[string]any
	if err := parsed.Claims(key, &claims, &all); err != nil {
		return oauthserver.VerifiedAccessToken{}, errors.New("access token signature is invalid")
	}
	now := clock.Now()
	if claims.Issuer != issuer || claims.Subject == "" || claims.ID == "" || claims.Expiry == nil || claims.IssuedAt == nil || len(claims.Audience) != 1 || claims.Audience[0] != string(resource) || claims.ValidateWithLeeway(jwt.Expected{Issuer: issuer, AnyAudience: []string{string(resource)}, Time: now}, 0) != nil {
		return oauthserver.VerifiedAccessToken{}, errors.New("access token claims are invalid")
	}
	clientRaw, ok := all["client_id"].(string)
	if !ok || clientRaw == "" {
		return oauthserver.VerifiedAccessToken{}, errors.New("access token client is missing")
	}
	clientID, err := oauthserver.NewClientID(clientRaw)
	if err != nil {
		return oauthserver.VerifiedAccessToken{}, errors.New("access token client is invalid")
	}
	scopeRaw, ok := all["scope"].(string)
	if !ok {
		return oauthserver.VerifiedAccessToken{}, errors.New("access token scope is missing")
	}
	scopes, err := oauthserver.ParseScopes(scopeRaw)
	if err != nil {
		return oauthserver.VerifiedAccessToken{}, errors.New("access token scope is invalid")
	}
	extra := make(map[string]any)
	for key, value := range all {
		if !isReservedClaim(key) {
			extra[key] = value
		}
	}
	subject, err := oauthserver.NewSubject(claims.Subject)
	if err != nil {
		return oauthserver.VerifiedAccessToken{}, errors.New("access token subject is invalid")
	}
	return oauthserver.VerifiedAccessToken{Subject: subject, ClientID: clientID, Issuer: claims.Issuer, Resource: resource, Scopes: scopes, IssuedAt: claims.IssuedAt.Time(), ExpiresAt: claims.Expiry.Time(), TokenID: claims.ID, ExtraClaims: extra}, nil
}

func (s *Service[A]) JWKS(context.Context) (oauthserver.JWKS, error) {
	keys := make([]string, 0, len(s.verification))
	for kid := range s.verification {
		keys = append(keys, kid)
	}
	sort.Strings(keys)
	result := oauthserver.JWKS{Keys: make([]map[string]any, 0, len(keys))}
	for _, kid := range keys {
		key := s.verification[kid]
		result.Keys = append(result.Keys, map[string]any{"kty": "RSA", "n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()), "kid": kid, "use": "sig", "alg": "RS256"})
	}
	return result, nil
}

func headerValue(headers map[jose.HeaderKey]interface{}, key jose.HeaderKey) string {
	value, ok := headers[key]
	if !ok {
		return ""
	}
	text, _ := value.(string)
	return text
}
func hasUntrustedKeyHeader(header jose.Header) bool {
	for key := range header.ExtraHeaders {
		if key == jose.HeaderKey("jku") || key == jose.HeaderKey("jwk") || key == jose.HeaderKey("x5u") || key == jose.HeaderKey("x5c") {
			return true
		}
	}
	return false
}
func isReservedClaim(key string) bool {
	switch key {
	case "iss", "sub", "aud", "iat", "nbf", "exp", "jti", "client_id", "scope":
		return true
	default:
		return false
	}
}
func newTokenID() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

var _ oauthserver.TokenService[struct{}] = (*Service[struct{}])(nil)
