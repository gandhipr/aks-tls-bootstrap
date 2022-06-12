package server

import (
	"context"
	"fmt"

	"github.com/golang-jwt/jwt/v4"
	grpc_auth "github.com/grpc-ecosystem/go-grpc-middleware/auth"
	"github.com/sirupsen/logrus"
)

func ValidateToken(ctx context.Context) (context.Context, error) {
	log.Infof("validating token")
	tokenString, err := grpc_auth.AuthFromMD(ctx, "bearer")
	if err != nil {
		log.Error(err)
		return nil, err
	}
	if tokenString == "" {
		err = fmt.Errorf("no token supplied")
		log.Error(err)
		return nil, err
	}

	log.WithField("token", tokenString).Debug("attempting to validate JWT")
	tokenClaims := &AzureADTokenClaims{}
	token, err := jwt.ParseWithClaims(tokenString, tokenClaims, jwks.Keyfunc)
	if err != nil {
		err = fmt.Errorf("failed to parse token: %v", err)
	}
	authLog := log.WithFields(logrus.Fields{
		"oid": tokenClaims.Oid,
		"tid": tokenClaims.Tid,
	})
	authLog.Info("successfully validated token")

	err = token.Claims.Valid()
	if err != nil {
		err = fmt.Errorf("token claims are not valid: %v", err)
		authLog.Error(err)
		return nil, err
	}

	if tokenClaims.Tid != tenantId {
		err = fmt.Errorf("token tenant ID %s does not match expected tenant ID %s", tokenClaims.Tid, tenantId)
		authLog.Error(err)
		return nil, err
	}

	allowedId := false
	for _, id := range allowedIds {
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
