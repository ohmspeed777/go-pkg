package corex

import (
	"context"
	"errors"

	"github.com/labstack/echo/v4"
)

type ContextKey struct{}

type ContextValues map[string]any

func NewFromEchoContext(c echo.Context) context.Context {
	values := ContextValues{
		"trace_id": c.Request().Header.Get("trace_id"),
		"span_id":  c.Request().Header.Get("span_id"),
	}
	return context.WithValue(c.Request().Context(), ContextKey{}, values)
}

func NewOutingEchoContext(c context.Context) (*ContextValues, error) {
	values, ok := c.Value(ContextKey{}).(ContextValues)
	if !ok {
		return nil, errors.New("can not parse context to ContextValues")
	}

	return &values, nil
}
