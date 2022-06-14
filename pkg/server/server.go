package server

import (
	"crypto/tls"
	"fmt"
	"net/http"

	"github.com/MicahParks/keyfunc"
	"github.com/sirupsen/logrus"
)

var (
	jwks *keyfunc.JWKS
	log  *logrus.Logger

	allowedIds []string
)

func NewServer(s *TlsBootstrapServer) (*TlsBootstrapServer, error) {
	err := s.initializeClient()
	if err != nil {
		return nil, err
	}

	err = s.loadRootCertificates()
	if err != nil {
		return nil, err
	}

	err = s.loadIntermediateCertificates()
	if err != nil {
		return nil, err
	}

	s.tlsConfig = &tls.Config{
		RootCAs: s.rootCertPool,
	}
	s.httpClient = &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: s.tlsConfig,
		},
	}

	s.requests = make(map[string]*Request)

	s.Log.WithField("jwksUrl", s.JwksUrl).Info("fetching Azure AD JWKS keys")
	jwks, err = keyfunc.Get(s.JwksUrl, keyfunc.Options{
		Client:          s.httpClient,
		RefreshInterval: JWKS_REFRESH_INTERVAL,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to establish jwks keyfunc: %v", err)
	}
	s.Log.WithField("KIDs", jwks.KIDs()).Debug("loaded jwks")

	go s.removeExpiredNonces()

	return s, nil
}
