package oauthserver

import (
	"errors"
	"fmt"
)

var (
	ErrNotFound = errors.New("oauth record not found")
	ErrConsumed = errors.New("oauth credential consumed")
	ErrExpired  = errors.New("oauth credential expired")
	ErrRevoked  = errors.New("oauth grant revoked")
	ErrConflict = errors.New("oauth transition conflict")
	ErrCapacity = errors.New("oauth state capacity reached")
	ErrBinding  = errors.New("oauth credential binding mismatch")
	ErrInvalid  = errors.New("oauth value is invalid")
)

type ErrorCode string

const (
	ErrorInvalidRequest        ErrorCode = "invalid_request"
	ErrorInvalidClientMetadata ErrorCode = "invalid_client_metadata"
	ErrorInvalidRedirectURI    ErrorCode = "invalid_redirect_uri"
	ErrorInvalidScope          ErrorCode = "invalid_scope"
	ErrorInvalidTarget         ErrorCode = "invalid_target"
	ErrorAccessDenied          ErrorCode = "access_denied"
	ErrorInvalidGrant          ErrorCode = "invalid_grant"
	ErrorUnsupportedGrant      ErrorCode = "unsupported_grant_type"
	ErrorTemporary             ErrorCode = "temporarily_unavailable"
)

type OAuthError struct {
	Code            ErrorCode
	SafeDescription string
	HTTPStatus      int
	Cause           error
}

func (e *OAuthError) Error() string {
	if e.SafeDescription == "" {
		return string(e.Code)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.SafeDescription)
}

func (e *OAuthError) Unwrap() error { return e.Cause }

func oauthError(code ErrorCode, description string, status int, cause error) *OAuthError {
	return &OAuthError{Code: code, SafeDescription: description, HTTPStatus: status, Cause: cause}
}

func invalidArgument(description string, cause error) *OAuthError {
	return oauthError(ErrorInvalidRequest, description, 400, cause)
}

func invalidGrant(cause error) *OAuthError {
	return oauthError(ErrorInvalidGrant, "the grant is invalid", 400, cause)
}
