package server

import (
	"crypto/x509"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/MicahParks/keyfunc"
	"github.com/sirupsen/logrus"
)

var (
	jwks                 *keyfunc.JWKS
	log                  *logrus.Logger
	nonces               map[string]*Nonce
	allowedIds           []string
	intermediateCertPool *x509.CertPool = x509.NewCertPool()
	tenantId             string
)

func NewServer(mainLog *logrus.Logger, passedSignerHostName string, tenantIdArg string, allowedClientIdsString string, jwksUrl string, intermediateCertificateDirectory string) (*TlsBootstrapServer, error) {
	server := &TlsBootstrapServer{}
	log = mainLog
	server.signerHostName = passedSignerHostName
	allowedIds = strings.Split(allowedClientIdsString, ",")
	tenantId = tenantIdArg

	if intermediateCertificateDirectory != "" {
		err := loadIntermediateCertificates(intermediateCertificateDirectory)
		if err != nil {
			return nil, err
		}
	}

	log.WithField("jwksUrl", jwksUrl).Info("fetching Azure AD JWKS keys")
	var err error
	jwks, err = keyfunc.Get(jwksUrl, keyfunc.Options{
		RefreshInterval: 1 * time.Hour,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to establish jwks keyfunc: %v", err)
	}
	log.WithField("KIDs", jwks.KIDs()).Debug("loaded jwks")

	nonces = make(map[string]*Nonce)
	go removeExpiredNonces()

	return server, nil
}

func loadIntermediateCertificates(intermediateCertificateDirectoryArg string) error {
	intermediateCertificateDirectory, err := filepath.Abs(intermediateCertificateDirectoryArg)
	if err != nil {
		return fmt.Errorf("failed to resolve path %s to absolute path: %v", intermediateCertificateDirectoryArg, err)
	}

	directory, err := os.Open(intermediateCertificateDirectory)
	if err != nil {
		return fmt.Errorf("failed to open intermediate certificate directory %s: %v", intermediateCertificateDirectory, err)
	}

	files, err := directory.ReadDir(0)
	if err != nil {
		return fmt.Errorf("failed to read files in intermediate certificate directory %s: %v", intermediateCertificateDirectory, err)
	}

	loaded := 0
	for _, file := range files {
		data, err := os.ReadFile(path.Join(directory.Name(), file.Name()))
		if err != nil {
			return fmt.Errorf("failed to read intermediate certificate %s: %v", file.Name(), err)
		}
		ok := intermediateCertPool.AppendCertsFromPEM(data)
		if !ok {
			// it's not a PEM-format file, maybe it's a DER-format certificate?
			cert, err := x509.ParseCertificate(data)
			if err != nil {
				return fmt.Errorf("failed to parse certificate(s) from %s", path.Join(intermediateCertificateDirectory, file.Name()))
			}
			intermediateCertPool.AddCert(cert)
		}
		loaded++
	}

	log.WithField("intermediateCertificateDirectory", intermediateCertificateDirectory).Infof("loaded %d intermediate cert(s) to cache", loaded)

	return nil
}
