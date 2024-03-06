package httpx

import (
	"context"
	"net/http"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/app/client"
	"github.com/cloudwego/hertz/pkg/protocol"

	"github.com/bezhai/go_utils/authx"
)

func ServerSecretDecodeMiddleware(key string) app.HandlerFunc {
	return func(c context.Context, ctx *app.RequestContext) {
		if string(ctx.Request.Method()) == http.MethodGet {
			ctx.Next(c)
			return
		}

		salt := ctx.Request.Header.Get("X-Sec-Salt")
		if salt == "" {
			// 说明不是加密的
			return
		}

		bodyBytes, err := ctx.Body()
		if err != nil {
			ctx.AbortWithMsg("cannot read body", http.StatusForbidden)
			return
		}

		// 解密数据
		decryptedData, err := authx.Decrypt(string(bodyBytes), []byte(key), salt)
		if err != nil {
			ctx.AbortWithMsg("cannot decode body", http.StatusForbidden)
			return
		}

		ctx.Request.SetBody(decryptedData)
		return
	}
}

func ClientSecretEncodeMiddleware(key string, doEncode func(req *protocol.Request) bool) client.Middleware {
	return func(next client.Endpoint) client.Endpoint {
		return func(ctx context.Context, req *protocol.Request, resp *protocol.Response) error {
			if doEncode(req) {
				bodyBytes := req.Body()
				salt, err := authx.GenSalt(10)
				if err != nil {
					return err
				}
				encodeBody, err := authx.Encrypt(bodyBytes, []byte(key), salt)
				if err != nil {
					return err
				}
				req.SetBody(encodeBody)
				req.Header.Set("X-Sec-Salt", salt)
			}
			return nil
		}
	}
}
