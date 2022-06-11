# aks-tls-bootstrap

A client/server POC to perform secure bootstrapping of AKS nodes. See [PRD](https://microsoft.sharepoint.com/:w:/t/azurecontainercompute/ERi0Wy2o1CROhwRzFAMk8NUByq_vGP4NhjJGdwgmqGJl5Q?e=T1mxZO) for details.

Implements the following options:

- Client is a client-go credential plugin that can be called from bootstrap-kubeconfig
- Server is a service that runs in the CCP and is proxied to via envoy, matching on an ALPN value

## To do

- [x] Nonce generation
- [x] IMDS/attested data querying
- [x] Attested data validation
- [x] VM ID validation
- [ ] move gRPC to HTTPS
- [ ] AAD auth to service (validate against a list of approved IDs somehow)
- [ ] Envoy/ALPN
- [ ] Cache intermediate certificates so we don't have to retrieve them every time
- [ ] Create bootstrap token secret
- [ ] Add webhooks to validate CSR requests and delete completed tokens
- [ ] Multi-cloud support (i.e. don't be hardcoded to public cloud
