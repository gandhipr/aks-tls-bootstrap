# aks-tls-bootstrap

A client/server POC to perform secure bootstrapping of AKS nodes. See [PRD](https://microsoft.sharepoint.com/:w:/t/azurecontainercompute/ERi0Wy2o1CROhwRzFAMk8NUByq_vGP4NhjJGdwgmqGJl5Q?e=T1mxZO) for details.

Implements the following options:

- Client is a client-go credential plugin that can be called from bootstrap-kubeconfig
- Server is a service that runs in the CCP and is proxied to via envoy, matching on an ALPN value

## To do

- [X] Nonce generation
- [X] IMDS/attested data querying
- [X] Attested data validation
- [X] VM ID validation
- [X] add TLS support
- [X] AAD auth to service (validate against a list of approved IDs somehow)
- [X] ALPN support on the client (used for Envoy routing)
- [X] Cache intermediate certificates so we don't have to retrieve them every time
- [X] Add option to allow root certificates to only be populated from a given directory (pinning) based on [this blog post](https://techcommunity.microsoft.com/t5/azure-governance-and-management/azure-instance-metadata-service-attested-data-tls-critical/ba-p/2888953)
- [X] Migrate functions to be on server struct struct and move variables there
- [X] Create bootstrap token secret
- [ ] Add webhook to validate CSR requests
- [ ] Multi-cloud support (i.e. don't be hardcoded to public cloud
- [ ] Make server image run as non-root user

## Items to consider

- How to decide if a machine is authorized or not (right now we just look at the identities; how will this work for BYON?)
  - Limit what subscription a machine can be in to join?
  - Some sort of nodepool association via RP?
  - kube-system secret (and -custom) listing allowed identities (this allows customers to create their own list?)
- How will ARM/K8s permissions be handled?
