// Package correlation carries per-request correlation identifiers across
// OAuth engine and HTTP transport boundaries without logging-library
// dependencies. Identifiers are opaque, bounded, and contain no credentials.
package correlation

import (
	"context"
	"crypto/rand"
	"encoding/hex"
)

// Header is the canonical correlation header honored on ingress and set on
// every response.
const Header = "X-Request-ID"

const (
	// MinIDLength and MaxIDLength bound inbound identifiers so untrusted
	// values cannot bloat logs or headers.
	MinIDLength = 8
	MaxIDLength = 64
)

type requestIDKey struct{}

// NewID returns a fresh 128-bit random identifier. It fails closed when the
// system entropy source is unavailable.
func NewID() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

// WithID returns a context carrying the request identifier.
func WithID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, requestIDKey{}, id)
}

// FromContext returns the request identifier or an empty string.
func FromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	id, _ := ctx.Value(requestIDKey{}).(string)
	return id
}

// ValidID reports whether an inbound identifier is safe to propagate.
func ValidID(id string) bool {
	if len(id) < MinIDLength || len(id) > MaxIDLength {
		return false
	}
	for _, r := range id {
		switch {
		case r >= '0' && r <= '9':
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r == '-' || r == '_' || r == '.':
		default:
			return false
		}
	}
	return true
}

// SanitizeInbound returns the inbound identifier when valid, otherwise a
// fresh identifier. Invalid inbound identifiers are replaced, never echoed.
func SanitizeInbound(inbound string) (string, error) {
	if ValidID(inbound) {
		return inbound, nil
	}
	return NewID()
}
