package errorx

import (
	"fmt"
	
	"github.com/pkg/errors"
)

type (
	StatusCode uint

	stackTracer interface {
		StackTrace() errors.StackTrace
	}

	Error struct {
		StatusCode  StatusCode
		Msg         string
		IsOveride   bool
		Causer      error
		StackTracer error
	}
)

func createError(status StatusCode, message string, causer ...error) error {
	err := &Error{
		StatusCode: status,
		Msg:        message,
		IsOveride:  true,
	}

	// I would to not required cause, So i use Array instead
	if len(causer) > 0 {
		refErr, ok := causer[0].(*Error)
		// if this error, it's overide before
		if ok {
			err.Causer = refErr.Causer
			err.IsOveride = refErr.IsOveride
			err.StackTracer = refErr.StackTracer
		} else {
			err.Causer = causer[0]
		}
	}

	// If it's tracked before, not need to create new tracking
	if _, ok := err.Causer.(stackTracer); ok {
		err.StackTracer = errors.WithStack(err.Causer)
		return err
	}

	if err.StackTracer != nil {
		return err
	}

	err.StackTracer = errors.WithStack(errors.New(message))
	return err
}

func New(status StatusCode, message string, causer ...error) error {
	err := createError(status, message, causer...)
	return err
}

func (e *Error) Error() string {
	return fmt.Sprintf("statusCode: %+v\n", e.StatusCode) + fmt.Sprintf("message: %+v\n", e.Msg) + fmt.Sprintf("stackTrack: %+v\n", e.StackTracer) + fmt.Sprintf("originError: %+v\n", e.Causer)
}
