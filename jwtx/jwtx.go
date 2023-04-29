package jwtx

import (
	"crypto/rsa"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/dgrijalva/jwt-go"
	"github.com/labstack/echo/v4"
	"github.com/ohmspeed777/go-pkg/errorx"
)

type User struct {
	ID   string
	Role int
}

type JWT struct {
	priv *rsa.PrivateKey
}

func NewJWT(priv *rsa.PrivateKey) *JWT {
	return &JWT{
		priv: priv,
	}
}

func (j *JWT) RequiredAuth(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		user, err := j.MapClaims(c)
		if err != nil {
			return errorx.New(http.StatusUnauthorized, "unauthorized", err)
		}

		c.Set("user", user)
		return next(c)
	}
}

func (j *JWT) MapClaims(c echo.Context) (*User, error) {
	user := &User{}
	token, err := j.verifyToken(c)
	if err != nil {
		return nil, errors.New("verifyToken is not pass")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("claims is not jwt.MapClaims type")
	}

	user.ID = claims["id"].(string)
	user.Role = claims["role"].(int)

	return user, nil
}

func (j *JWT) NonRequiredAuth(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		user, err := j.MapClaims(c)
		if err == nil {
			c.Set("user", user)
		} else {
			c.Set("user", &User{})
		}

		return next(c)
	}
}

func (j *JWT) verifyToken(r echo.Context) (*jwt.Token, error) {
	tokenString := j.extractToken(r)
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return &j.priv.PublicKey, nil
	})
	if err != nil {
		return nil, err
	}
	return token, nil
}

func (j *JWT) extractToken(r echo.Context) string {
	bearToken := r.Request().Header.Get("Authorization")
	strArr := strings.Split(bearToken, " ")
	if len(strArr) == 2 {
		return strArr[1]
	}
	return ""
}
