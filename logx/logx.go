package logx

import (
	"github.com/labstack/echo/v4"
	"github.com/sirupsen/logrus"
)

const (
	TRACE = "trace_id"
	SPAN  = "span_id"
)

var logx *logrus.Logger

func Init(lvl string, caller bool) {
	l := logrus.New()
	l.SetReportCaller(caller)
	l.SetFormatter(&logrus.JSONFormatter{})
	level, err := logrus.ParseLevel(lvl)
	if err != nil {
		// other level number less than info will be show.
		level = logrus.InfoLevel
	}
	l.SetLevel(level)
	logx = l
}

func LoggerWithID(c echo.Context) logrus.FieldLogger {
	return logx.WithFields(logrus.Fields{
		TRACE: c.Request().Header.Get(TRACE),
		SPAN:  c.Request().Header.Get(SPAN),
	})
}

func GetLog() *logrus.Logger {
	return logx
}
