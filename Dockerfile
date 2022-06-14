FROM mcr.microsoft.com/cbl-mariner/base/core:2.0
RUN tdnf install -y azure-cli && tdnf clean all
RUN tdnf install -y bind-utils ca-certificates iproute tcpdump && tdnf clean all
WORKDIR /opt/app/aks-tls-bootstrap
COPY bin/tls-bootstrap-server tls-bootstrap-server
COPY certs certs
CMD ["/opt/app/aks-tls-bootstrap/tls-bootstrap-server", "-root-cert-dir", "/opt/app/aks-tls-bootstrap/certs/roots", "-intermediate-cert-dir", "/opt/app/aks-tls-bootstrap/certs/intermediates"]