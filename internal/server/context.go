package server

import (
	"context"

	"github.com/endharassment/reporting-wizard/internal/model"
)

type contextKey int

const (
	ctxKeyUser contextKey = iota
	ctxKeyCSRFToken
	ctxKeyRequestID
)

func withUser(ctx context.Context, user *model.User) context.Context {
	return context.WithValue(ctx, ctxKeyUser, user)
}

// UserFromContext returns the authenticated user from the context, or nil.
func UserFromContext(ctx context.Context) *model.User {
	u, _ := ctx.Value(ctxKeyUser).(*model.User)
	return u
}

func withCSRFToken(ctx context.Context, token string) context.Context {
	return context.WithValue(ctx, ctxKeyCSRFToken, token)
}
