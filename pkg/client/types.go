package client

type ExecCredential struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Status     struct {
		Token string `json:"token"`
	} `json:"status"`
}

type VmssInstanceData struct {
	Compute struct {
		AzEnvironment    string `json:"azEnvironment"`
		CustomData       string `json:"customData"`
		EvictionPolicy   string `json:"evictionPolicy"`
		ExtendedLocation struct {
			Name string `json:"name"`
			Type string `json:"type"`
		} `json:"extendedLocation"`
		IsHostCompatibilityLayerVM string `json:"isHostCompatibilityLayerVm"`
		LicenseType                string `json:"licenseType"`
		Location                   string `json:"location"`
		Name                       string `json:"name"`
		Offer                      string `json:"offer"`
		OsProfile                  struct {
			AdminUsername                 string `json:"adminUsername"`
			ComputerName                  string `json:"computerName"`
			DisablePasswordAuthentication string `json:"disablePasswordAuthentication"`
		} `json:"osProfile"`
		OsType           string `json:"osType"`
		PlacementGroupID string `json:"placementGroupId"`
		Plan             struct {
			Name      string `json:"name"`
			Product   string `json:"product"`
			Publisher string `json:"publisher"`
		} `json:"plan"`
		PlatformFaultDomain  string        `json:"platformFaultDomain"`
		PlatformUpdateDomain string        `json:"platformUpdateDomain"`
		Priority             string        `json:"priority"`
		Provider             string        `json:"provider"`
		PublicKeys           []interface{} `json:"publicKeys"`
		Publisher            string        `json:"publisher"`
		ResourceGroupName    string        `json:"resourceGroupName"`
		ResourceID           string        `json:"resourceId"`
		SecurityProfile      struct {
			SecureBootEnabled string `json:"secureBootEnabled"`
			VirtualTpmEnabled string `json:"virtualTpmEnabled"`
		} `json:"securityProfile"`
		Sku            string `json:"sku"`
		StorageProfile struct {
			DataDisks []struct {
				BytesPerSecondThrottle string `json:"bytesPerSecondThrottle"`
				Caching                string `json:"caching"`
				CreateOption           string `json:"createOption"`
				DiskCapacityBytes      string `json:"diskCapacityBytes"`
				DiskSizeGB             string `json:"diskSizeGB"`
				Image                  struct {
					URI string `json:"uri"`
				} `json:"image"`
				IsSharedDisk string `json:"isSharedDisk"`
				IsUltraDisk  string `json:"isUltraDisk"`
				Lun          string `json:"lun"`
				ManagedDisk  struct {
					ID                 string `json:"id"`
					StorageAccountType string `json:"storageAccountType"`
				} `json:"managedDisk"`
				Name                 string `json:"name"`
				OpsPerSecondThrottle string `json:"opsPerSecondThrottle"`
				Vhd                  struct {
					URI string `json:"uri"`
				} `json:"vhd"`
				WriteAcceleratorEnabled string `json:"writeAcceleratorEnabled"`
			} `json:"dataDisks"`
			ImageReference struct {
				ID        string `json:"id"`
				Offer     string `json:"offer"`
				Publisher string `json:"publisher"`
				Sku       string `json:"sku"`
				Version   string `json:"version"`
			} `json:"imageReference"`
			OsDisk struct {
				Caching          string `json:"caching"`
				CreateOption     string `json:"createOption"`
				DiffDiskSettings struct {
					Option string `json:"option"`
				} `json:"diffDiskSettings"`
				DiskSizeGB         string `json:"diskSizeGB"`
				EncryptionSettings struct {
					Enabled string `json:"enabled"`
				} `json:"encryptionSettings"`
				Image struct {
					URI string `json:"uri"`
				} `json:"image"`
				ManagedDisk struct {
					ID                 string `json:"id"`
					StorageAccountType string `json:"storageAccountType"`
				} `json:"managedDisk"`
				Name   string `json:"name"`
				OsType string `json:"osType"`
				Vhd    struct {
					URI string `json:"uri"`
				} `json:"vhd"`
				WriteAcceleratorEnabled string `json:"writeAcceleratorEnabled"`
			} `json:"osDisk"`
			ResourceDisk struct {
				Size string `json:"size"`
			} `json:"resourceDisk"`
		} `json:"storageProfile"`
		SubscriptionID string `json:"subscriptionId"`
		Tags           string `json:"tags"`
		TagsList       []struct {
			Name  string `json:"name"`
			Value string `json:"value"`
		} `json:"tagsList"`
		UserData               string `json:"userData"`
		Version                string `json:"version"`
		VirtualMachineScaleSet struct {
			ID string `json:"id"`
		} `json:"virtualMachineScaleSet"`
		VMID           string `json:"vmId"`
		VMScaleSetName string `json:"vmScaleSetName"`
		VMSize         string `json:"vmSize"`
		Zone           string `json:"zone"`
	} `json:"compute"`
	Network struct {
		Interface []struct {
			Ipv4 struct {
				IPAddress []struct {
					PrivateIPAddress string `json:"privateIpAddress"`
					PublicIPAddress  string `json:"publicIpAddress"`
				} `json:"ipAddress"`
				Subnet []struct {
					Address string `json:"address"`
					Prefix  string `json:"prefix"`
				} `json:"subnet"`
			} `json:"ipv4"`
			Ipv6 struct {
				IPAddress []struct {
					PrivateIPAddress string `json:"privateIpAddress"`
				} `json:"ipAddress"`
			} `json:"ipv6"`
			MacAddress string `json:"macAddress"`
		} `json:"interface"`
	} `json:"network"`
}

type VmssAttestedData struct {
	Encoding  string `json:"encoding"`
	Signature string `json:"signature"`
}
