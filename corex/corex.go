package corex

import (
	"context"
	"errors"

	"github.com/labstack/echo/v4"
	"github.com/ohmspeed777/go-pkg/jwtx"
)

type ContextKey struct{}

type ContextValues struct {
	User    *jwtx.User
	TraceID string
	SpanID  string
}

func NewFromEchoContext(c echo.Context) context.Context {
	values := &ContextValues{
		TraceID: c.Request().Header.Get("trace_id"),
		SpanID:  c.Request().Header.Get("span_id"),
	}

	user, ok := c.Get("user").(*jwtx.User)
	if ok {
		values.User = user
	}

	return context.WithValue(c.Request().Context(), ContextKey{}, values)
}

func NewFromOutingContext(c context.Context) (*ContextValues, error) {
	values, ok := c.Value(ContextKey{}).(*ContextValues)
	if !ok {
		return nil, errors.New("can not parse context to ContextValues")
	}

	return values, nil
}
