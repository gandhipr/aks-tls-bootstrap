package server

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/cloud"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources"
	"github.com/sirupsen/logrus"
)

func (s *TlsBootstrapServer) validateVmId(nonce string) error {
	var authMethod, clientID string
	azureConfig := &KubeletAzureJson{}
	azureJson, err := os.ReadFile("/etc/kubernetes/azure.json")
	if err != nil {
		log.WithError(err).Info("failed to parse /etc/kubernetes/azure.json")
		return err
	} else {
		err := json.Unmarshal(azureJson, azureConfig)
		if err != nil {
			log.WithError(err).Info("failed to unmarshal /etc/kubernetes/azure.json")
			return err
		} else {
			clientID = azureConfig.ClientId
			if azureConfig.ClientId == "msi" {
				authMethod = "msi"
				if azureConfig.UserAssignedIdentityID != "" {
					// user assigned managed identity
					// not necessary for system assigned.
					clientID = azureConfig.UserAssignedIdentityID
				}
			} else {
				authMethod = "sp"
			}
		}
	}

	s.Log.Debug("auth method", authMethod)
	s.Log.Debug("client id ", clientID)

	var credential azcore.TokenCredential
	if authMethod == "msi" {
		s.Log.Debug("creating msi credential")
		var c azcore.TokenCredential
		var err error
		if clientID == "msi" {
			c, err = azidentity.NewManagedIdentityCredential(nil)
		} else {
			c, err = azidentity.NewManagedIdentityCredential(&azidentity.ManagedIdentityCredentialOptions{
				ID: azidentity.ClientID(clientID),
			})
		}
		if err != nil {
			return fmt.Errorf("failed to get az identity")
		}
		credential = c
	} else {
		s.Log.Debug("creating sp credential")
		c, err := azidentity.NewClientSecretCredential(azureConfig.TenantId, clientID, azureConfig.ClientSecret, nil)
		if err != nil {
			return fmt.Errorf("failed to get az identity")
		}
		credential = c
	}

	s.Log.Debug("fetched az identity")

	resourceId, err := arm.ParseResourceID(s.requests[nonce].ResourceId)
	if err != nil {
		return fmt.Errorf("failed to parse resourceId: %s", err)
	}

	armResources, err := armresources.NewClient(resourceId.SubscriptionID, credential, &arm.ClientOptions{
		ClientOptions: azcore.ClientOptions{
			Cloud: cloud.AzurePublic,
		},
	})
	if err != nil {
		return fmt.Errorf("failed to get arm client: %s", err)
	}

	s.Log.WithField("resourceId", resourceId.String()).Debug("retrieving arm resource")
	resource, err := armResources.GetByID(context.Background(), s.requests[nonce].ResourceId, "2022-03-01", nil)
	if err != nil {
		return fmt.Errorf("failed to retrieve resource from ARM: %v", err)
	}
	s.Log.WithField("resource", resource).Debug("retrieved resource")

	properties := resource.Properties.(map[string]interface{})

	if s.requests[nonce].VmId != properties["vmId"].(string) {
		return fmt.Errorf("supplied VmId %s does not match VmId %s retrieved from ARM", s.requests[nonce].VmId, properties["vmId"].(string))
	}

	var vmName string
	_, hasOsProfile := properties["osProfile"]
	if hasOsProfile {
		osProfile := properties["osProfile"].(map[string]interface{})
		_, hasComputerName := osProfile["computerName"]
		if hasComputerName {
			vmName = osProfile["computerName"].(string)
		} else {
			vmName = *resource.Name
		}
	} else {
		vmName = *resource.Name
	}
	s.Log.WithFields(logrus.Fields{
		"vmIdFromClient": s.requests[nonce].VmId,
		"vmIdFromARM":    properties["vmId"].(string),
		"vmName":         vmName,
	}).Info("VmId from client matches VmId retrieved from ARM")

	s.requests[nonce].VmName = vmName

	return nil
}
