package server

import (
	"context"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/cloud"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources"
	"github.com/sirupsen/logrus"
)

func (s *TlsBootstrapServer) validateVmId(nonce string) error {
	credential, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return fmt.Errorf("failed to get az identity")
	}
	s.Log.Debug("fetched az identity")

	resourceId, err := arm.ParseResourceID(s.requests[nonce].ResourceId)
	if err != nil {
		return fmt.Errorf("failed to parse resourceId")
	}

	armResources, err := armresources.NewClient(resourceId.SubscriptionID, credential, &arm.ClientOptions{
		ClientOptions: azcore.ClientOptions{
			Cloud: cloud.AzurePublic,
		},
	})

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
