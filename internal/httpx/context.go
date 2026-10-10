package httpx

import (
	"context"
	"uuid"
)

type contextKey string

const (
	cspNonceContextKey  contextKey = "csp-nonce"
	requestIDContextKey contextKey = "request-id"
)

func WithCSPNonce(ctx context.Context, nonce string) context.Context {
	return context.WithValue(ctx, cspNonceContextKey, nonce)
}

func CSPNonce(ctx context.Context) string {
	nonce, _ := ctx.Value(cspNonceContextKey).(string)
	return nonce
}

func WithRequestID(ctx context.Context, requestId uuid.UUID) context.Context {
	return context.WithValue(ctx, requestIDContextKey, requestId)
}

func RequestID(ctx context.Context) uuid.UUID {
	serverId, _ := ctx.Value(requestIDContextKey).(uuid.UUID)
	return serverId
}
