package httpx

import (
	"context"
	"net/http"

	"github.com/cloudwego/hertz/pkg/app"

	"github.com/bezhai/go_utils/authx"
)

func ServerAuthMiddleware(secret string) func(next app.HandlerFunc) app.HandlerFunc {
	return func(next app.HandlerFunc) app.HandlerFunc {
		return func(c context.Context, ctx *app.RequestContext) {
			salt := ctx.Request.Header.Get("X-Salt")
			if salt == "" {
				ctx.String(http.StatusForbidden, "missing salt")
				return
			}

			clientToken := ctx.Request.Header.Get("X-Token")
			if clientToken == "" {
				ctx.String(http.StatusForbidden, "missing token")
				return
			}

			bodyBytes, err := ctx.Body()
			if err != nil {
				ctx.String(http.StatusForbidden, "cannot read body")
				return
			}

			serverToken := authx.GenerateToken(salt, string(bodyBytes), secret)

			if serverToken != clientToken {
				ctx.String(http.StatusForbidden, "invalid token")
				return
			}

			next(c, ctx)
		}
	}
}
