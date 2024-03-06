package httpx

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/app/client"
	"github.com/cloudwego/hertz/pkg/app/server"
	"github.com/cloudwego/hertz/pkg/protocol"
)

func TestServerSecretDecodeMiddleware(t *testing.T) {
	t.Run("normal", func(t *testing.T) {

		type TestReq struct {
			Name string `json:"name"`
		}

		key := "123456789"
		h := server.Default()
		h.Use(ServerSecretDecodeMiddleware(key))
		h.POST("/test", func(c context.Context, ctx *app.RequestContext) {
			var err error
			var req TestReq

			err = ctx.BindAndValidate(&req)
			if err != nil {
				t.Log(err)
				ctx.AbortWithMsg(err.Error(), http.StatusBadRequest)
				return
			}

			fmt.Printf("%+v", req)

			ctx.JSON(http.StatusOK, req)
		})
		go h.Spin()

		time.Sleep(3 * time.Second)

		c, err := client.NewClient(
			client.WithDialTimeout(5*time.Second),
			client.WithClientReadTimeout(120*time.Second),
		)

		if err != nil {
			return
		}

		c.Use(ClientSecretEncodeMiddleware(key, func(req *protocol.Request) bool {
			return strings.Contains(string(req.Host()), "localhost")
		}))

		resp, err := SendRequest[*TestReq](context.Background(), c, "http://localhost:6789/test", PostFunc(&TestReq{Name: "1"}))
		if err == nil {
			t.Log(resp)
			return
		}
	})
}
