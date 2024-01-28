package httpx

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"reflect"

	json "github.com/bytedance/sonic"
	"github.com/cloudwego/hertz/pkg/app/client"
	"github.com/cloudwego/hertz/pkg/common/hlog"
	"github.com/cloudwego/hertz/pkg/protocol"
	"github.com/cloudwego/hertz/pkg/protocol/consts"

	"github.com/bezhai/go_utils/authx"
)

type RequestExtraFunc func(req *protocol.Request, resp *protocol.Response) error

func SendRequest[T any](ctx context.Context, c *client.Client, url string, extraFuncList ...RequestExtraFunc) (respBody T, err error) {

	isPointer := false
	if typeof := reflect.TypeOf(respBody); typeof.Kind() == reflect.Pointer {
		respBody = reflect.New(typeof.Elem()).Interface().(T)
		isPointer = true
	} else if typeof.Kind() == reflect.Slice {
		reflect.ValueOf(&respBody).Elem().Set(reflect.MakeSlice(typeof, 0, 0))
	}
	req := &protocol.Request{}
	resp := &protocol.Response{}
	for _, extraFunc := range extraFuncList {
		err = extraFunc(req, resp)
		if err != nil {
			return
		}
	}
	req.SetRequestURI(url)

	err = c.Do(ctx, req, resp)

	if err != nil {
		hlog.CtxWarnf(ctx, "http request return fail, error:%+v", err)
		return
	}

	if resp.StatusCode() != http.StatusOK {
		err = errors.New("resp code is not ok")
		hlog.CtxWarnf(ctx, "http request return fail, code: %d, msg: %s",
			resp.StatusCode(),
			string(resp.Body()))
		return
	}

	body := resp.Body()
	if len(body) > 0 {
		if _, ok1 := any(respBody).([]byte); ok1 {
			reflect.ValueOf(&respBody).Elem().Set(reflect.ValueOf(body))
		} else if _, ok2 := any(respBody).(struct{}); !ok2 {
			if isPointer {
				err = json.Unmarshal(body, respBody)
				if err != nil {
					return
				}
			} else {
				err = json.Unmarshal(body, &respBody)
				if err != nil {
					return
				}
			}
		}
	}

	return
}

func AddHeaderFunc(headers map[string]string) RequestExtraFunc {
	return func(req *protocol.Request, resp *protocol.Response) error {
		if headers != nil {
			req.SetHeaders(headers)
		}
		return nil
	}
}

func GetFunc(params map[string]string) RequestExtraFunc {

	urlEncode := func(params map[string]string) string {
		encode := url.Values{}
		for k, v := range params {
			encode.Add(k, v)
		}
		return encode.Encode()
	}

	return func(req *protocol.Request, resp *protocol.Response) error {
		req.SetMethod(consts.MethodGet)
		req.Header.SetContentTypeBytes([]byte("application/json"))
		if params != nil {
			req.SetQueryString(urlEncode(params))
		}
		return nil
	}
}

func PostFunc(body any) RequestExtraFunc {
	return func(req *protocol.Request, resp *protocol.Response) error {
		bodyBytes, err := json.Marshal(body)
		if err != nil {
			return err
		}
		req.SetMethod(consts.MethodPost)
		req.SetBody(bodyBytes)
		req.Header.SetContentTypeBytes([]byte("application/json"))
		return nil
	}
}

func PostFuncWithAuth(body any, secret string) RequestExtraFunc {
	return func(req *protocol.Request, resp *protocol.Response) error {
		bodyBytes, err := json.Marshal(body)
		if err != nil {
			return err
		}
		req.SetMethod(consts.MethodPost)
		req.SetBody(bodyBytes)
		req.Header.SetContentTypeBytes([]byte("application/json"))

		salt, err := authx.GenSalt(10)
		if err != nil {
			return err
		}
		token := authx.GenerateToken(salt, string(bodyBytes), secret)
		req.Header.Set("X-Salt", salt)
		req.Header.Set("X-Token", token)

		return nil
	}
}

func FormDataFunc(params []map[string]string, images []io.Reader) RequestExtraFunc {
	return func(req *protocol.Request, resp *protocol.Response) error {
		for _, param := range params {
			req.SetMultipartFormData(param)
		}

		for i, image := range images {
			req.SetFileReader("images", fmt.Sprintf("%d.jpg", i), image)
		}
		req.SetMethod(consts.MethodPost)
		req.Header.SetContentTypeBytes([]byte("multipart/form-data"))
		return nil
	}
}
