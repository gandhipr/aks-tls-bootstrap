package server

import (
	"context"
	"fmt"
	"reflect"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	_ "github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute"
	_ "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute"
	"github.com/sirupsen/logrus"
)

func (s *TlsBootstrapServer) validateVmId(vmId string, nonce string) error {
	credential, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return fmt.Errorf("failed to get az identity")
	}

	resourceId, err := arm.ParseResourceID(s.requests[nonce].ResourceId)
	if err != nil {
		return fmt.Errorf("failed to parse resourceId")
	}

	switch resourceId.ResourceType.Namespace + "/" + resourceId.ResourceType.Type {
	case "Microsoft.Compute/virtualMachines":
		client, err := armcompute.NewVirtualMachinesClient(resourceId.SubscriptionID, credential, nil)
		if err != nil {
			return fmt.Errorf("failed to create VirtualMachinesClient: %v", err)
		}

		vm, err := client.Get(context.Background(), resourceId.ResourceGroupName, resourceId.Name, nil)
		if err != nil {
			return fmt.Errorf("failed to retrieve virtual machine: %v", err)
		}

		if vmId != *vm.Properties.VMID {
			return fmt.Errorf("supplied VmId %s does not match VmId %s retrieved from ARM", vmId, *vm.Properties.VMID)
		}

		vmName := ""
		vmReflect := reflect.TypeOf(*vm.Properties)
		osProfile, ok := vmReflect.FieldByName("OSProfile")
		if ok {
			osProfileReflect := reflect.TypeOf(osProfile)
			_, ok := osProfileReflect.FieldByName("ComputerName")
			if ok {
				vmName = *vm.Properties.OSProfile.ComputerName
			} else {
				vmName = *vm.Name
			}
		}

		s.requests[nonce].VmName = vmName

		s.Log.WithFields(logrus.Fields{
			"vmId":   *vm.Properties.VMID,
			"vmName": vmName,
		}).Infof("supplied VmId %s matches VmId retrieved from ARM", vmId)
	case "Microsoft.Compute/virtualMachineScaleSets/virtualMachines":
		client, err := armcompute.NewVirtualMachineScaleSetVMsClient(resourceId.SubscriptionID, credential, nil)
		if err != nil {
			return fmt.Errorf("failed to create VirtualMachineScaleSetVMsClient: %v", err)
		}

		vm, err := client.Get(context.Background(), resourceId.ResourceGroupName, resourceId.Parent.Name, resourceId.Name, nil)
		if err != nil {
			return fmt.Errorf("failed to retrieve virtual machine scaleset instance: %v", err)
		}

		if vmId != *vm.Properties.VMID {
			return fmt.Errorf("supplied VmId %s does not match VmId %s retrieved from ARM", vmId, *vm.Properties.VMID)
		}

		vmName := ""
		vmReflect := reflect.TypeOf(*vm.Properties)
		osProfile, ok := vmReflect.FieldByName("OSProfile")
		if ok {
			osProfileReflect := reflect.TypeOf(osProfile)
			_, ok := osProfileReflect.FieldByName("ComputerName")
			if ok {
				vmName = *vm.Properties.OSProfile.ComputerName
			} else {
				vmName = *vm.Name
			}
		}

		s.requests[nonce].VmName = vmName

		s.Log.WithFields(logrus.Fields{
			"vmId":   *vm.Properties.VMID,
			"vmName": vmName,
		}).Infof("supplied VmId %s matches VmId retrieved from ARM", vmId)
	default:
		return fmt.Errorf("unknown resource type: %s/%s", resourceId.ResourceType.Namespace, resourceId.ResourceType.Type)
	}

	return nil
}
