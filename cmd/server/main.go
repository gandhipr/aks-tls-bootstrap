package main

import (
	"flag"
	"fmt"
	"net"
	"strings"

	grpc_auth "github.com/grpc-ecosystem/go-grpc-middleware/auth"
	pb "github.com/phealy/aks-tls-bootstrap/pkg/proto"
	server "github.com/phealy/aks-tls-bootstrap/pkg/server"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

var (
	log                 = logrus.New()
	logFormat           = flag.String("log-format", "json", "Log format: json or text, default: json")
	hostname            = flag.String("hostname", "0.0.0.0", "The hostname to listen on.")
	port                = flag.Int("port", 9123, "The port to run the gRPC server on.")
	jwksUrl             = flag.String("jwks-url", "https://login.microsoftonline.com/common/discovery/v2.0/keys", "The JWKS endpoint for the Azure AD to use.")
	signerHostName      = flag.String("imds-signer-name", "metadata.azure.com", "The hostname that must be present in the signing certificate from IMDS.")
	tenantId            = flag.String("tenant-id", "", "Required tenant ID for authentication")
	allowedClientIds    = flag.String("allowed-client-ids", "", "A comma separated list of allowed client IDs for the service.")
	tlsCert             = flag.String("tls-cert", "", "TLS certificate path")
	tlsKey              = flag.String("tls-key", "", "TLS key path")
	rootCertDir         = flag.String("root-cert-dir", "", "A path to a directory containing root certificates. If not supplied, the system root certificate store will be used.")
	intermediateCertDir = flag.String("intermediate-cert-dir", "", "A path to a directory containing intermediate certificates to be loaded to the cache.")
	debug               = flag.Bool("debug", false, "enable debug logging (WILL LOG AUTHENTICATION DATA)")
)

func main() {
	flag.Parse()
	log.SetReportCaller(true)

	switch strings.ToLower(*logFormat) {
	case "text":
		log.SetFormatter(&logrus.TextFormatter{})
	default:
		log.SetFormatter(&logrus.JSONFormatter{})
	}

	if *debug {
		log.SetLevel(logrus.DebugLevel)
	}

	log.WithFields(logrus.Fields{
		"tls-cert": *tlsCert,
		"tls-key":  *tlsKey,
	}).Infof("fetching TLS certificate")
	tls, err := credentials.NewServerTLSFromFile(*tlsCert, *tlsKey)
	if err != nil {
		log.Fatalf("failed to initialize TLS certificate: %v", err)
	}

	grpcServer := grpc.NewServer(
		grpc.Creds(tls),
		grpc.StreamInterceptor(grpc_auth.StreamServerInterceptor(server.ValidateToken)),
		grpc.UnaryInterceptor(grpc_auth.UnaryServerInterceptor(server.ValidateToken)),
	)

	tlsBootstrapServer, err := server.NewServer(log, *signerHostName, *tenantId, *allowedClientIds, *jwksUrl, *rootCertDir, *intermediateCertDir)
	if err != nil {
		log.Fatalf("failed to initialize server: %v", err)
	}

	pb.RegisterAKSBootstrapTokenRequestServer(grpcServer, tlsBootstrapServer)

	listener, err := net.Listen("tcp", fmt.Sprintf("%s:%d", *hostname, *port))
	if err != nil {
		log.Fatalf("failed to listen on %s:%d: %v", *hostname, *port, err)
	}

	log.Infof("starting server on %s:%d", *hostname, *port)
	grpcServer.Serve(listener)
}
