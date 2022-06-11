package server

import (
	"time"

	pb "github.com/phealy/aks-tls-bootstrap/pkg/proto"
)

type Nonce struct {
	Nonce      string
	Expiration time.Time
	ResourceId string
}

type TlsBootstrapServer struct {
	signerHostName string
	pb.UnimplementedAKSBootstrapTokenRequestServer
}

type AttestedDataPlan struct {
	Name      string `json:"name,omitempty"`
	Product   string `json:"product,omitempty"`
	Publisher string `json:"publisher,omitempty"`
}

type AttestedDataTimeStamp struct {
	CreatedOn string `json:"createdOn"`
	ExpiresOn string `json:"expiresOn"`
}

type AttestedData struct {
	LicenseType    string                `json:"licenseType,omitempty"`
	Nonce          string                `json:",omitempty"`
	Plan           AttestedDataPlan      `json:",omitempty"`
	SubscriptionId string                `json:"subscriptionId"`
	Sku            string                `json:"sku,omitempty"`
	Timestamp      AttestedDataTimeStamp `json:"timestamp"`
	VmId           string                `json:"vmId"`
}
