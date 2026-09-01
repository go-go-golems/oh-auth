package memorytest

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/go-go-golems/oh-auth/pkg/oauthserver"
)

type Clock struct {
	mu      sync.Mutex
	Current time.Time
}

func NewClock(now time.Time) *Clock { return &Clock{Current: now} }
func (c *Clock) Now() time.Time     { c.mu.Lock(); defer c.mu.Unlock(); return c.Current }
func (c *Clock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.Current = c.Current.Add(d)
}

type Secrets struct {
	mu   sync.Mutex
	next uint64
}

func (s *Secrets) value(prefix string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.next++
	return fmt.Sprintf("%s-%040d", prefix, s.next)
}
func (s *Secrets) NewTransactionToken() (oauthserver.TransactionToken, error) {
	return oauthserver.NewTransactionToken(s.value("tx"))
}
func (s *Secrets) NewConsentToken() (oauthserver.ConsentToken, error) {
	return oauthserver.NewConsentToken(s.value("consent"))
}
func (s *Secrets) NewAuthorizationCode() (oauthserver.AuthorizationCode, error) {
	return oauthserver.NewAuthorizationCode(s.value("code"))
}
func (s *Secrets) NewRefreshToken() (oauthserver.RefreshToken, error) {
	return oauthserver.NewRefreshToken(s.value("refresh"))
}
func (s *Secrets) NewRefreshFamilyID() (oauthserver.RefreshFamilyID, error) {
	return oauthserver.NewRefreshFamilyID(s.value("family"))
}

type ScopePolicy[A any] struct{ Available oauthserver.ScopeSet }

func (p ScopePolicy[A]) AvailableScopes(context.Context, oauthserver.Principal[A], oauthserver.Resource) (oauthserver.ScopeSet, error) {
	return p.Available, nil
}

type Revalidator[A any] struct {
	Result oauthserver.Revalidation[A]
	Err    error
}

func (r Revalidator[A]) Revalidate(context.Context, oauthserver.Subject) (oauthserver.Revalidation[A], error) {
	return r.Result, r.Err
}

type TokenService[A any] struct {
	Issuer string
	Err    error
	next   uint64
}

func (t *TokenService[A]) TokenIssuer() string { return t.Issuer }
func (t *TokenService[A]) IssueAccessToken(_ context.Context, grant oauthserver.AccessGrant[A]) (oauthserver.IssuedAccessToken, error) {
	if t.Err != nil {
		return oauthserver.IssuedAccessToken{}, t.Err
	}
	t.next++
	return oauthserver.IssuedAccessToken{Value: fmt.Sprintf("access-%d", t.next), TokenType: "Bearer", ExpiresAt: grant.ExpiresAt}, nil
}
func (*TokenService[A]) VerifyAccessToken(context.Context, string, oauthserver.ResourceID) (oauthserver.VerifiedAccessToken, error) {
	return oauthserver.VerifiedAccessToken{}, oauthserver.ErrNotFound
}
func (t *TokenService[A]) JWKS(context.Context) (oauthserver.JWKS, error) {
	return oauthserver.JWKS{}, nil
}

var _ oauthserver.Clock = (*Clock)(nil)
var _ oauthserver.SecretSource = (*Secrets)(nil)
var _ oauthserver.ScopePolicy[struct{}] = ScopePolicy[struct{}]{}
var _ oauthserver.PrincipalRevalidator[struct{}] = Revalidator[struct{}]{}
var _ oauthserver.TokenService[struct{}] = (*TokenService[struct{}])(nil)
