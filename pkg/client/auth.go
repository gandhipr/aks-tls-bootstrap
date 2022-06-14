package client

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/confidential"
	"github.com/sirupsen/logrus"
)

func GetAuthToken(log *logrus.Logger, clientId string) (string, error) {
	authMethod := ""
	azureConfig := &kubeletAzureJson{}

	if clientId != "" {
		authMethod = "msi"
	} else {
		azureJson, err := os.ReadFile("/etc/kubernetes/azure.json")
		if err != nil {
			log.WithError(err).Info("failed to parse /etc/kubernetes/azure.json")
		} else {
			err := json.Unmarshal(azureJson, azureConfig)
			if err != nil {
				log.WithError(err).Info("failed to unmarshal /etc/kubernetes/azure.json")
			} else {
				if azureConfig.ClientId == "msi" {
					authMethod = "msi"
					clientId = azureConfig.UserAssignedIdentityID
				} else {
					authMethod = "sp"
				}
			}
		}
	}

	if authMethod == "msi" {
		log.Info("retrieving IMDS access token")
		token, err := GetMSIToken(clientId)
		if err != nil {
			return "", err
		}

		return token.AccessToken, nil
	} else if authMethod == "sp" {
		credential, err := confidential.NewCredFromSecret(azureConfig.ClientSecret)
		if err != nil {
			return "", fmt.Errorf("failed to create secret from azure.json: %v", err)
		}

		client, err := confidential.New(azureConfig.ClientId, credential, confidential.WithAuthority("https://login.microsoftonline.com/"+azureConfig.TenantId))
		if err != nil {
			return "", fmt.Errorf("failed to create client from azure.json sp/secret: %v", err)
		}

		token, err := client.AcquireTokenByCredential(context.Background(), []string{"7319c514-987d-4e9b-ac3d-d38c4f427f4c/.default"})
		if err != nil {
			return "", fmt.Errorf("failed to acquire token via service principal: %v", err)
		}

		return token.AccessToken, nil
	}

	return "", fmt.Errorf("failed to find authentication via azure.json or msi")
}
