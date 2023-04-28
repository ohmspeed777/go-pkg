package middlewares

import (
	"bytes"
	"encoding/json"
	"fmt"
	"go-pkg/errorx"
	"go-pkg/logx"
	"io"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/pkg/errors"
	uuid "github.com/satori/go.uuid"
	"github.com/sirupsen/logrus"
)

var (
	SKIP_PATHS       = []string{"/build", "/health", "/metrics"}
	EXEC_TIMES_CACHE = make(map[string]time.Time)
)

const (
	REQUEST_INFO  = "request info"
	RESPONSE_INFO = "response info"
	ERROR_INFO    = "error info"
	JSON_TYPE     = "application/json"
)

func checkSkipPath(path string) bool {
	for _, v := range SKIP_PATHS {
		if v == path {
			return true
		}
	}
	return false
}

func LogRequestMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		if checkSkipPath(c.Path()) {
			return next(c)
		}

		logCTx := logx.GetLog().WithFields(logrus.Fields{
			"method":     c.Request().Method,
			"path":       c.Path(),
			"full_path":  c.Request().URL.String(),
			"ip":         c.RealIP(),
			"user_agent": c.Request().UserAgent(),
		})

		// ------------------ legacy ----------------------------
		reqBody := []byte{}
		if c.Request().Body != nil {
			reqBody, _ = ioutil.ReadAll(c.Request().Body)
		}

		// make prettier format
		if c.Request().Header.Get("Content-Type") == JSON_TYPE {
			bodyMap := map[string]interface{}{}
			_ = json.Unmarshal(reqBody, &bodyMap)
			logCTx = logCTx.WithField("body", bodyMap)
		} else {
			logCTx = logCTx.WithField("body", string(reqBody))
		}

		// return body to original body
		c.Request().Body = ioutil.NopCloser(bytes.NewBuffer(reqBody))

		// this id used for star to end lifecycle http
		traceID := uuid.NewV4().String()
		// this id used for only this request and response not include when redirect or other
		spanID := uuid.NewV4().String()

		// check if this request already set
		if c.Request().Header.Get("trace_id") != "" {
			traceID = c.Request().Header.Get("trace_id")
		}

		// set header
		c.Request().Header.Set("trace_id", traceID)
		c.Request().Header.Set("span_id", spanID)

		// keep start time
		EXEC_TIMES_CACHE[spanID] = time.Now()

		// log
		logCTx.WithFields(logrus.Fields{
			"trace_id":  traceID,
			"span_id":   spanID,
			"class":     "middleware",
			"ip":        c.RealIP(),
			"header":    c.Request().Header,
			"timestamp": time.Now(),
		}).Info(REQUEST_INFO)

		return next(c)
	}
}

func LogResponseMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		defer delete(EXEC_TIMES_CACHE, c.Request().Header.Get("span_id"))
		if checkSkipPath(c.Path()) {
			return next(c)
		}

		resBody := new(bytes.Buffer)
		bodyMap := map[string]interface{}{}

		// copy value to resBody
		// copy below way from echo body dump
		mw := io.MultiWriter(c.Response().Writer, resBody)
		writer := &bodyDumpResponseWriter{Writer: mw, ResponseWriter: c.Response().Writer}
		c.Response().Writer = writer

		if err := next(c); err != nil {
			c.Error(err)
		}

		json.Unmarshal(resBody.Bytes(), &bodyMap)
		logx.GetLog().WithFields(logrus.Fields{
			"class":      "middleware",
			"trace_id":   c.Request().Header.Get("trace_id"),
			"span_id":    c.Request().Header.Get("span_id"),
			"header":     c.Request().Header,
			"body":       bodyMap,
			"method":     c.Request().Method,
			"path":       c.Path(),
			"full_path":  c.Request().URL.String(),
			"timestamp":  time.Now(),
			"status":     c.Response().Status,
			"latency_ns": time.Since(EXEC_TIMES_CACHE[c.Request().Header.Get("span_id")]),
		}).Info(RESPONSE_INFO)

		return nil
	}
}

type (
	ErrorResponse struct {
		Msg         string `json:"message"`
		StackTracer string `json:"stack_tracer,omitempty"`
		Causer      string `json:"causer,omitempty"`
	}

	stackTracer interface {
		StackTrace() errors.StackTrace
	}
)

func CustomHTTPErrorHandler(e error, c echo.Context) {
	logCtx := logx.GetLog().WithFields(logrus.Fields{
		"class":      "middleware",
		"trace_id":   c.Request().Header.Get("trace_id"),
		"span_id":    c.Request().Header.Get("span_id"),
		"header":     c.Request().Header,
		"method":     c.Request().Method,
		"path":       c.Path(),
		"full_path":  c.Request().URL.String(),
		"timestamp":  time.Now(),
		"status":     c.Response().Status,
		"latency_ns": time.Since(EXEC_TIMES_CACHE[c.Request().Header.Get("span_id")]),
	})


	err, ok := e.(*errorx.Error)
	if ok {
		stackStr := strings.ReplaceAll(fmt.Sprintf("%+v", err.StackTracer), "\t", "\\n")
		res := &ErrorResponse{
			Msg:         err.Msg,
			StackTracer: stackStr,
			Causer:      fmt.Sprintf("%+v", err.Causer),
		}

		logCtx.WithField("error", err.Error()).Error(ERROR_INFO)

		c.JSON(int(err.StatusCode), res)
		return
	}
	
	logCtx.WithField("error", e.Error()).Error(ERROR_INFO)
	res := &ErrorResponse{
		Msg: "Something went wrong",
	}

	c.JSON(http.StatusInternalServerError, res)
}
