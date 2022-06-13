package server

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/rand"
	"time"

	"github.com/sirupsen/logrus"
	coreV1 "k8s.io/api/core/v1"
	metaV1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

func (s *TlsBootstrapServer) createBootstrapToken(vmName string) (string, string, error) {
	rand.Seed(time.Now().Unix())

	bootstrapTokenBytes := make([]byte, 3)
	_, err := rand.Read(bootstrapTokenBytes)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate random token for bootstrap token")
	}
	bootstrapToken := hex.EncodeToString(bootstrapTokenBytes)

	bootstrapTokenSecretBytes := make([]byte, 8)
	_, err = rand.Read(bootstrapTokenSecretBytes)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate random token for bootstrap secret")
	}
	bootstrapTokenSecret := hex.EncodeToString(bootstrapTokenSecretBytes)

	return bootstrapToken, bootstrapTokenSecret, nil
}

func (s *TlsBootstrapServer) createBootstrapTokenSecret(vmName string) (string, error) {
	expirationDate := time.Now().UTC().Add(TOKEN_LIFETIME).Format(time.RFC3339)

	bootstrapToken, bootstrapTokenSecret, err := s.createBootstrapToken(vmName)
	if err != nil {
		return "", fmt.Errorf("failed to generate bootstrap token secret")
	}

	secret := *&coreV1.Secret{
		ObjectMeta: metaV1.ObjectMeta{
			Name: "bootstrap-token-" + bootstrapToken,
			Annotations: map[string]string{
				"kubernetes.azure.com/tls-bootstrap-hostname": vmName,
			},
		},
		Type: coreV1.SecretTypeBootstrapToken,
		StringData: map[string]string{
			"token-id":                       bootstrapToken,
			"token-secret":                   bootstrapTokenSecret,
			"usage-bootstrap-authentication": "true",
			"usage-bootstrap-signing":        "true",
			"expiration":                     expirationDate,
		},
	}
	s.Log.WithField("secret", secret).Debug("bootstrap secret generated")

	_, err = s.kubeSystemSecretsClient.Create(context.Background(), &secret, metaV1.CreateOptions{})
	if err != nil {
		return "", fmt.Errorf("failed to create secret in kube-system namespace: %v", err)
	}

	return bootstrapToken + "." + bootstrapTokenSecret, nil
}

func (s *TlsBootstrapServer) initializeClient() error {
	config, err := clientcmd.BuildConfigFromFlags(s.MasterUrl, s.KubeconfigPath)
	if err != nil {
		return fmt.Errorf("failed to initialize kubernetes client: %v", err)
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return fmt.Errorf("failed to create clientset: %v", err)
	}

	s.k8sClientSet = clientset

	serverVersion, err := s.k8sClientSet.ServerVersion()
	if err != nil {
		return fmt.Errorf("failed to create clientset: %v", err)
	}
	s.Log.WithFields(logrus.Fields{
		"apiServer":     config.Host,
		"serverVersion": serverVersion.String(),
	}).Info("connected to API server")

	s.kubeSystemSecretsClient = clientset.CoreV1().Secrets("kube-system")

	return nil
}
