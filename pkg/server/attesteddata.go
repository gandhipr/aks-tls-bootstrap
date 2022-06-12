package server

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/sirupsen/logrus"
	"go.mozilla.org/pkcs7"
)

func validateAttestedData(log *logrus.Entry, signedAttestedData string, signerHostName string) (*AttestedData, error) {
	decodedSignature, err := base64.StdEncoding.DecodeString(signedAttestedData)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64 signature: %v", err)
	}

	p7, err := pkcs7.Parse(decodedSignature)
	if err != nil {
		return nil, fmt.Errorf("failed to parse pkcs7 signature block: %v", err)
	}

	pkcs7SignerCertificate := p7.GetOnlySigner()
	log.Infof("Signer: %s", pkcs7SignerCertificate.Subject)

	intermediateCertCached := false
	for _, cachedSubject := range intermediateCertPool.Subjects() {
		if bytes.Compare(cachedSubject, pkcs7SignerCertificate.RawIssuer) == 0 {
			log.Debug("intermediate certificate already cached")
			intermediateCertCached = true
		}
	}

	if !intermediateCertCached {
		intermediateCert, err := getIntermediateCertificate(log, pkcs7SignerCertificate.IssuingCertificateURL[0])
		if err != nil {
			return nil, fmt.Errorf("failed to retrieve intermediate certificate: %v", err)
		}
		intermediateCertPool.AddCert(intermediateCert)
	}

	_, err = pkcs7SignerCertificate.Verify(x509.VerifyOptions{
		DNSName:       signerHostName,
		Intermediates: intermediateCertPool,
		Roots:         nil,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to verify %s hostname: %v", signerHostName, err)
	}

	attestedData := &AttestedData{}
	err = json.Unmarshal(p7.Content, attestedData)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal attested data: %v", err)
	}

	return attestedData, nil
}

func getIntermediateCertificate(log *logrus.Entry, url string) (*x509.Certificate, error) {
	client := http.Client{}
	log.WithField("url", url).Infof("retrieving intermediate certificate")

	request, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize HTTP request: %v", err)
	}

	response, err := client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve IMDS attested data: %v", err)
	}

	defer response.Body.Close()
	responseBody, _ := ioutil.ReadAll(response.Body)

	certificate, err := x509.ParseCertificate(responseBody)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve intermediate certificate from %s: %v", url, err)
	}

	return certificate, nil
}
