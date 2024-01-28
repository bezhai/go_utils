package httpx

import (
	"context"
	"net/http"

	"github.com/cloudwego/hertz/pkg/app"

	"github.com/bezhai/go_utils/authx"
)

func ServerAuthMiddleware(secret string) app.HandlerFunc {
	return func(c context.Context, ctx *app.RequestContext) {

		if string(ctx.Request.Method()) == http.MethodGet {
			ctx.Next(c)
			return
		}

		salt := ctx.Request.Header.Get("X-Salt")
		if salt == "" {
			ctx.AbortWithMsg("missing salt", http.StatusForbidden)
			return
		}

		clientToken := ctx.Request.Header.Get("X-Token")
		if clientToken == "" {
			ctx.AbortWithMsg("missing token", http.StatusForbidden)
			return
		}

		bodyBytes, err := ctx.Body()
		if err != nil {
			ctx.AbortWithMsg("cannot read body", http.StatusForbidden)
			return
		}

		serverToken := authx.GenerateToken(salt, string(bodyBytes), secret)

		if serverToken != clientToken {
			ctx.AbortWithMsg("invalid token", http.StatusForbidden)
			return
		}
	}
}
