package server

import (
	"context"
	"fmt"
	"time"

	pb "github.com/phealy/aks-tls-bootstrap/pkg/proto"
	"github.com/sirupsen/logrus"
)

func (s *TlsBootstrapServer) GetToken(ctx context.Context, tokenRequest *pb.TokenRequest) (*pb.TokenResponse, error) {
	requestLog := log.WithFields(logrus.Fields{
		"nonce": tokenRequest.Nonce,
	})
	requestLog.Infof("received token request")

	attestedData, err := validateAttestedData(requestLog, tokenRequest.AttestedData, s.signerHostName)
	if err != nil {
		err = fmt.Errorf("failed to validate attested data: %v", err)
		requestLog.Error(err)
		return nil, err
	}
	requestLog.Infof("validated attested data")

	err = validateAttestedDataNonceExistsAndValid(attestedData)
	if err != nil {
		err = fmt.Errorf("failed to match token request nonce to valid existing nonce: %v", err)
		requestLog.Error(err)
		return nil, err
	}
	nonce := nonces[tokenRequest.Nonce]
	requestLog = requestLog.WithFields(logrus.Fields{
		"resourceId": nonce.ResourceId,
		"vmId":       attestedData.VmId,
	})

	err = validateVmId(requestLog, attestedData.VmId, nonces[tokenRequest.Nonce].ResourceId)
	if err != nil {
		err = fmt.Errorf("failed to validate VM ID: %v", err)
		requestLog.Error(err)
		return nil, err
	}

	response := &pb.TokenResponse{}
	response.Token = "dummyToken"

	delete(nonces, tokenRequest.Nonce)
	requestLog.Info("returning token and flushing nonce from cache")
	return response, nil
}

func validateAttestedDataNonceExistsAndValid(attestedData *AttestedData) error {
	nonce, exists := nonces[attestedData.Nonce]
	if !exists {
		return fmt.Errorf("nonce %s not found in cache", attestedData.Nonce)
	}

	if nonce.Expiration.Before(time.Now()) {
		return fmt.Errorf("nonce %s expired at %s", attestedData.Nonce, nonce.Expiration.String())
	}

	return nil
}
