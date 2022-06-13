package server

import (
	"crypto/x509"
	"fmt"
	"os"
	"path"
	"path/filepath"
)

func (s *TlsBootstrapServer) loadRootCertificates() error {
	s.rootCertPool = x509.NewCertPool()
	if s.RootCertPath == "" {
		log.Info("loading root certificates from system root certificate pool")
		var err error
		s.rootCertPool, err = x509.SystemCertPool()
		if err != nil {
			return fmt.Errorf("no root certificates were supplied and loading the system certificate pool failed: %v", err)
		}
	} else {
		rootCertificateDirectory, err := filepath.Abs(s.RootCertPath)
		if err != nil {
			return fmt.Errorf("failed to resolve path %s to absolute path: %v", s.RootCertPath, err)
		}

		directory, err := os.Open(rootCertificateDirectory)
		if err != nil {
			return fmt.Errorf("failed to open root certificate directory %s: %v", rootCertificateDirectory, err)
		}

		files, err := directory.ReadDir(0)
		if err != nil {
			return fmt.Errorf("failed to read files in root certificate directory %s: %v", rootCertificateDirectory, err)
		}

		loaded := 0
		for _, file := range files {
			data, err := os.ReadFile(path.Join(directory.Name(), file.Name()))
			if err != nil {
				return fmt.Errorf("failed to read root certificate %s: %v", file.Name(), err)
			}
			ok := s.rootCertPool.AppendCertsFromPEM(data)
			if !ok {
				// it's not a PEM-format file, maybe it's a DER-format certificate?
				cert, err := x509.ParseCertificate(data)
				if err != nil {
					return fmt.Errorf("failed to parse certificate(s) from %s", path.Join(rootCertificateDirectory, file.Name()))
				}
				s.rootCertPool.AddCert(cert)
			}
			loaded++
		}

		s.Log.WithField("rootCertificateDirectory", rootCertificateDirectory).Infof("loaded %d root cert(s) to pool", loaded)
	}

	if len(s.rootCertPool.Subjects()) == 0 {
		return fmt.Errorf("no root certificates were found; attested data validation would be impossible.")
	}

	return nil
}

func (s *TlsBootstrapServer) loadIntermediateCertificates() error {
	s.intermediateCertPool = x509.NewCertPool()

	if s.IntermediateCertPath != "" {
		intermediateCertificateDirectory, err := filepath.Abs(s.IntermediateCertPath)
		if err != nil {
			return fmt.Errorf("failed to resolve path %s to absolute path: %v", s.IntermediateCertPath, err)
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
			ok := s.intermediateCertPool.AppendCertsFromPEM(data)
			if !ok {
				// it's not a PEM-format file, maybe it's a DER-format certificate?
				cert, err := x509.ParseCertificate(data)
				if err != nil {
					return fmt.Errorf("failed to parse certificate(s) from %s", path.Join(intermediateCertificateDirectory, file.Name()))
				}
				s.intermediateCertPool.AddCert(cert)
			}
			loaded++
		}

		s.Log.WithField("intermediateCertificateDirectory", intermediateCertificateDirectory).Infof("loaded %d intermediate cert(s) to cache", loaded)
	}

	return nil
}
