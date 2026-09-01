package oauthresource

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/go-go-golems/oh-auth/pkg/oauthserver"
)

type Verifier interface {
	VerifyAccessToken(context.Context, string, oauthserver.ResourceID) (oauthserver.VerifiedAccessToken, error)
}

func BearerToken(r *http.Request) (string, error) {
	values := r.Header.Values("Authorization")
	if len(values) != 1 {
		return "", errors.New("bearer token is missing")
	}
	value := values[0]
	parts := strings.Fields(value)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || parts[1] == "" || strings.ContainsAny(parts[1], "\r\n") {
		return "", errors.New("bearer token is missing")
	}
	return parts[1], nil
}

func Authenticate(ctx context.Context, verifier Verifier, resource oauthserver.ResourceID, r *http.Request) (oauthserver.VerifiedAccessToken, error) {
	token, err := BearerToken(r)
	if err != nil {
		return oauthserver.VerifiedAccessToken{}, err
	}
	return verifier.VerifyAccessToken(ctx, token, resource)
}
