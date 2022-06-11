package server

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/rand"
	"time"

	pb "github.com/phealy/aks-tls-bootstrap/pkg/proto"
)

func removeExpiredNonces() {
	interval := NONCE_EXPIRATION_CHECK_INTERVAL

	log.Infof("starting nonce expiration checker, interval %d second(s)", interval/time.Second)
	ticker := time.NewTicker(interval)

	for range ticker.C {
		for nonce := range nonces {
			if nonces[nonce].Expiration.Before(time.Now()) {
				log.Infof("removing expired nonce %s for %s", nonce, nonces[nonce].ResourceId)
				delete(nonces, nonce)
			}
		}
	}
}

func generateNonceString() (string, error) {
	rand.Seed(time.Now().Unix())
	bytes := make([]byte, 5)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", fmt.Errorf("failed to generate random token for nonce")
	}
	return hex.EncodeToString(bytes), nil
}

func (s *TlsBootstrapServer) GetNonce(ctx context.Context, nonceRequest *pb.NonceRequest) (*pb.NonceResponse, error) {
	requestLog := log.WithField("resourceId", nonceRequest.ResourceId)
	requestLog.Infof("received nonce request")

	var nonceStr string
	var err error
	attempts := 0
	for attempts < 100 {
		attempts++
		nonceStr, err = generateNonceString()
		if err != nil {
			return nil, err
		}
		_, exists := nonces[nonceStr]
		if !exists {
			break
		}
	}
	if attempts == 100 {
		err := fmt.Errorf("unable to generate a non-colliding nonce after 100 attempts")
		requestLog.Error(err)
		return nil, err
	}

	requestLog = requestLog.WithField("nonce", nonceStr)

	nonces[nonceStr] = &Nonce{
		Nonce:      nonceStr,
		ResourceId: nonceRequest.ResourceId,
		Expiration: time.Now().Add(NONCE_LIFETIME),
	}

	requestLog.Info("replying to nonce request")
	return &pb.NonceResponse{
		Nonce: nonceStr,
	}, nil
}
