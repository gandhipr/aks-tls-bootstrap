package server

import (
	"time"

	"github.com/MicahParks/keyfunc"
	"github.com/golang-jwt/jwt"
	pb "github.com/phealy/aks-tls-bootstrap/pkg/proto"
)

type AzureADTokenClaims struct {
	ClaimNames struct {
		Groups string `json:"groups"`
	} `json:"_claim_names"`
	ClaimSources struct {
		Src1 struct {
			Endpoint string `json:"endpoint"`
		} `json:"src1"`
	} `json:"_claim_sources"`
	Acr               string   `json:"acr"`
	Aio               string   `json:"aio"`
	Amr               []string `json:"amr"`
	AppId             string   `json:"appid"`
	AppIdAcr          string   `json:"appidacr"`
	Azp               string   `json:"azp"`
	Azpacr            string   `json:"azpacr"`
	Deviceid          string   `json:"deviceid"`
	FamilyName        string   `json:"family_name"`
	GivenName         string   `json:"given_name"`
	Groups            []string `json:"groups"`
	HasGroups         bool     `json:"hasgroups"`
	Idp               string   `json:"idp"`
	Ipaddr            string   `json:"ipaddr"`
	Name              string   `json:"name"`
	Oid               string   `json:"oid"`
	OnpremSid         string   `json:"onprem_sid"`
	PreferredUsername string   `json:"preferred_username"`
	Puid              string   `json:"puid"`
	Rh                string   `json:"rh"`
	Roles             []string `json:"roles"`
	Scp               string   `json:"scp"`
	Tid               string   `json:"tid"`
	UniqueName        string   `json:"unique_name"`
	Upn               string   `json:"upn"`
	Uti               string   `json:"uti"`
	Ver               string   `json:"ver"`
	Wids              []string `json:"wids"`
	XmsTcdt           int64    `json:"xms_tcdt"`
	jwt.StandardClaims
}

type Nonce struct {
	Nonce      string
	Expiration time.Time
	ResourceId string
}

type TlsBootstrapServer struct {
	signerHostName   string
	allowedClientIds []string
	jwksKeyfunc      *keyfunc.JWKS
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
