package server

import (
	"github.com/sirupsen/logrus"
)

var (
	log    *logrus.Logger
	nonces map[string]*Nonce
)

func NewServer(mainLogger *logrus.Logger, passedSignerHostName *string) (*TlsBootstrapServer, error) {
	server := &TlsBootstrapServer{}
	log = mainLogger
	server.signerHostName = *passedSignerHostName

	nonces = make(map[string]*Nonce)
	go removeExpiredNonces()

	return server, nil
}
