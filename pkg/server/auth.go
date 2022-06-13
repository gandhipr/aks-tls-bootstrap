package server

import (
	"context"
	"fmt"

	"github.com/golang-jwt/jwt/v4"
	grpc_auth "github.com/grpc-ecosystem/go-grpc-middleware/auth"
	"github.com/sirupsen/logrus"
)

func AuthFunction(ctx context.Context) (context.Context, error) {
	fmt.Printf("ctx: %v\n", ctx)

	return nil, nil
}

func (s *TlsBootstrapServer) ValidateToken(ctx context.Context) (context.Context, error) {
	s.Log.Infof("validating token")
	tokenString, err := grpc_auth.AuthFromMD(ctx, "bearer")
	if err != nil {
		s.Log.Error(err)
		return nil, err
	}
	if tokenString == "" {
		err = fmt.Errorf("no token supplied")
		s.Log.Error(err)
		return nil, err
	}

	s.Log.WithField("token", tokenString).Debug("attempting to validate JWT")
	tokenClaims := &AzureADTokenClaims{}
	token, err := jwt.ParseWithClaims(tokenString, tokenClaims, jwks.Keyfunc)
	if err != nil {
		err = fmt.Errorf("failed to parse token: %v", err)
	}
	authLog := s.Log.WithFields(logrus.Fields{
		"oid": tokenClaims.Oid,
		"tid": tokenClaims.Tid,
	})

	err = token.Claims.Valid()
	if err != nil {
		err = fmt.Errorf("token claims are not valid: %v", err)
		authLog.Error(err)
		return nil, err
	}

	if tokenClaims.Tid != s.TenantId {
		err = fmt.Errorf("token tenant ID %s does not match expected tenant ID %s", tokenClaims.Tid, s.TenantId)
		authLog.Error(err)
		return nil, err
	}

	allowedId := false
	for _, id := range s.AllowedClientIds {
		if tokenClaims.Oid == id {
			allowedId = true
		}
	}
	if !allowedId {
		err = fmt.Errorf("principal ID %s is not in allowed ID list", tokenClaims.Oid)
		authLog.Error(err)
		return nil, err
	}

	newCtx := context.WithValue(ctx, "tokenInfo", token)
	authLog.Infof("validated token successfully")
	return newCtx, nil
}
