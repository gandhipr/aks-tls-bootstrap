package client

import (
	"context"
	"encoding/json"
	"fmt"

	pb "github.com/phealy/aks-tls-bootstrap/pkg/proto"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func GetBootstrapToken(log *logrus.Logger, serverAddress string) (string, error) {
	conn, err := grpc.Dial(serverAddress, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return "", fmt.Errorf("failed to connect to %s: %v", serverAddress, err)
	}
	defer conn.Close()

	pbClient := pb.NewAKSBootstrapTokenRequestClient(conn)

	log.Info("retrieving IMDS instance data")
	instanceData, err := GetInstanceData()
	if err != nil {
		return "", fmt.Errorf("failed to retrieve instance metadata from IMDS: %v", err)
	}

	log.Infof("retrieving nonce from TLS bootstrap token server at %s", serverAddress)
	nonceRequest := pb.NonceRequest{
		ResourceId: instanceData.Compute.ResourceID,
	}
	nonce, err := pbClient.GetNonce(context.Background(), &nonceRequest)
	if err != nil {
		return "", fmt.Errorf("failed to retrieve a nonce: %v", err)
	}
	log.Infof("nonce reply is %s", nonce.Nonce)

	log.Info("retrieving IMDS attested data")
	attestedData, err := GetAttestedData(nonce.Nonce)
	if err != nil {
		return "", fmt.Errorf("failed to retrieve attested data from IMDS: %v", err)
	}

	log.Info("retrieving bootstrap token from TLS bootstrap token server")
	tokenRequest := pb.TokenRequest{
		ResourceId:   instanceData.Compute.ResourceID,
		Nonce:        nonce.Nonce,
		AttestedData: attestedData.Signature,
	}
	tokenReply, err := pbClient.GetToken(context.Background(), &tokenRequest)
	if err != nil {
		return "", fmt.Errorf("failed to retrieve a token: %v", err)
	}
	log.Info("received token reply")

	execCredential := &ExecCredential{}
	execCredential.APIVersion = "client.authentication.k8s.io/v1"
	execCredential.Kind = "ExecCredential"
	execCredential.Status.Token = tokenReply.Token

	execCredentialBytes, err := json.Marshal(execCredential)
	if err != nil {
		return "", fmt.Errorf("failed to marshal execCredential")
	}
	return string(execCredentialBytes), nil
}
