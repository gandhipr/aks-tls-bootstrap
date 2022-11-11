package server

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/rand"
	"os"
	"time"

	"github.com/sirupsen/logrus"
	coreV1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metaV1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
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

func (s *TlsBootstrapServer) createBootstrapTokenSecret(vmName string) (string, string, error) {
	expirationDate := time.Now().UTC().Add(TOKEN_LIFETIME).Format(time.RFC3339)

	bootstrapToken, bootstrapTokenSecret, err := s.createBootstrapToken(vmName)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate bootstrap token secret")
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

	// TODO(ace): convert this to json patch not create/update retry
	_, err = s.kubeSystemSecretsClient.Create(context.Background(), &secret, metaV1.CreateOptions{})
	if err != nil && !errors.IsAlreadyExists(err) {
		return "", "", fmt.Errorf("failed to create secret in kube-system namespace: %v", err)
	}

	if errors.IsAlreadyExists(err) {
		s.Log.Info("secret existed, update.")
		_, err = s.kubeSystemSecretsClient.Update(context.Background(), &secret, metaV1.UpdateOptions{})
		if err != nil {
			return "", "", fmt.Errorf("failed to update secret in kube-system namespace: %v", err)
		}
	}

	return bootstrapToken + "." + bootstrapTokenSecret, expirationDate, nil
}

func (s *TlsBootstrapServer) initializeClient() error {
	kubeconfig, err := config.GetConfig()
	if err != nil {
		return fmt.Errorf("failed to initialize kubernetes client: %v", err)
	}

	clientset, err := kubernetes.NewForConfig(kubeconfig)
	if err != nil {
		return fmt.Errorf("failed to create clientset: %v", err)
	}

	kcSecret, err := clientset.CoreV1().Secrets(os.Getenv("POD_NS")).Get(context.Background(), "kubeconfig-file", metaV1.GetOptions{})
	if err != nil {
		return fmt.Errorf("getting kubeconfig secret: %s", err)
	}

	if kcSecret.Data == nil {
		return fmt.Errorf("kubeconfig secret is empty")
	}

	cfg, err := clientcmd.RESTConfigFromKubeConfig(kcSecret.Data["kubeconfig.yaml"])
	if err != nil {
		return fmt.Errorf("parsing overlay kubeconfig: %s", err)
	}

	overlay, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return fmt.Errorf("creating overlay kube client: %s", err)
	}

	s.k8sClientSet = overlay

	serverVersion, err := s.k8sClientSet.ServerVersion()
	if err != nil {
		return fmt.Errorf("failed to create clientset: %v", err)
	}
	s.Log.WithFields(logrus.Fields{
		"apiServer":     kubeconfig.Host,
		"serverVersion": serverVersion.String(),
	}).Info("connected to API server")

	s.kubeSystemSecretsClient = overlay.CoreV1().Secrets("kube-system")

	return nil
}
