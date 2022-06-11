package client

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
)

func GetInstanceData() (*VmssInstanceData, error) {
	url := "http://169.254.169.254/metadata/instance"
	queryParameters := map[string]string{
		"api-version": "2021-05-01",
	}
	data := &VmssInstanceData{}

	err := getImdsData(url, queryParameters, data)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve IMDS instance data: %v", err)
	}

	return data, nil
}

func GetAttestedData(nonce string) (*VmssAttestedData, error) {
	url := "http://169.254.169.254/metadata/attested/document"
	queryParameters := map[string]string{
		"api-version": "2021-05-01",
		"nonce":       nonce,
	}

	data := &VmssAttestedData{}
	err := getImdsData(url, queryParameters, data)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve IMDS attested data: %v", err)
	}

	return data, nil
}

func getImdsData(url string, queryParameters map[string]string, responseObject interface{}) error {
	client := http.Client{Transport: &http.Transport{Proxy: nil}}

	request, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return fmt.Errorf("failed to initialize HTTP request: %v", err)
	}

	request.Header.Add("Metadata", "True")

	query := request.URL.Query()
	query.Add("format", "json")
	for key := range queryParameters {
		query.Add(key, queryParameters[key])
	}
	request.URL.RawQuery = query.Encode()

	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("failed to retrieve IMDS data: %v", err)
	}

	defer response.Body.Close()
	responseBody, _ := ioutil.ReadAll(response.Body)

	err = json.Unmarshal(responseBody, responseObject)
	if err != nil {
		return fmt.Errorf("failed to unmarshal IMDS data: %v", err)
	}

	return nil
}
