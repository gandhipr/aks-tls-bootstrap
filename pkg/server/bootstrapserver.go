package server

import (
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"

	pb "github.com/Azure/aks-tls-bootstrap/pkg/proto"
	grpc_auth "github.com/grpc-ecosystem/go-grpc-middleware/auth"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

var (
	setupLog            = logrus.New()
	logFormat           = flag.String("log-format", "json", "Log format: json or text, default: json")
	hostname            = flag.String("hostname", "0.0.0.0", "The hostname to listen on.")
	port                = flag.Int("port", 9123, "The port to run the gRPC server on.")
	jwksUrl             = flag.String("jwks-url", "https://login.microsoftonline.com/common/discovery/v2.0/keys", "The JWKS endpoint for the Azure AD to use.")
	signerHostName      = flag.String("imds-signer-name", "metadata.azure.com", "The hostname that must be present in the signing certificate from IMDS.")
	allowedClientIds    = flag.String("allowed-client-ids", "", "A comma separated list of allowed client IDs for the service.")
	tlsCert             = flag.String("tls-cert", "", "TLS certificate path")
	tlsKey              = flag.String("tls-key", "", "TLS key path")
	rootCertDir         = flag.String("root-cert-dir", "", "A path to a directory containing root certificates. If not supplied, the system root certificate store will be used.")
	intermediateCertDir = flag.String("intermediate-cert-dir", "", "A path to a directory containing intermediate certificates to be loaded to the cache.")
	debug               = flag.Bool("debug", false, "enable debug logging (WILL LOG AUTHENTICATION DATA)")
)

func Run() error {
	flag.Parse()
	setupLog.SetReportCaller(true)
	setupLog.SetOutput(os.Stdout)

	switch strings.ToLower(*logFormat) {
	case "text":
		setupLog.SetFormatter(&logrus.TextFormatter{})
	default:
		setupLog.SetFormatter(&logrus.JSONFormatter{})
	}

	if *debug {
		setupLog.SetLevel(logrus.DebugLevel)
	}

	var tlsCreds grpc.ServerOption = nil
	if *tlsCert != "" {
		setupLog.WithFields(logrus.Fields{
			"tls-cert": *tlsCert,
			"tls-key":  *tlsKey,
		}).Infof("fetching TLS certificate")
		tls, err := credentials.NewServerTLSFromFile(*tlsCert, *tlsKey)
		if err != nil {
			setupLog.Fatalf("failed to initialize TLS certificate: %v", err)
		}

		tlsCreds = grpc.Creds(tls)
	}

	azureConfig := &KubeletAzureJson{}
	azureJson, err := os.ReadFile("/etc/kubernetes/azure.json")
	if err != nil {
		setupLog.Fatalf("failed to parse /etc/kubernetes/azure.json: %v", err)
		return err
	}

	if err := json.Unmarshal(azureJson, azureConfig); err != nil {
		setupLog.Fatalf("failed to unmarshal /etc/kubernetes/azure.json: %v", err)
		return err
	}

	s := &TlsBootstrapServer{
		Log:                  logrus.NewEntry(setupLog),
		AllowedClientIds:     strings.Split(*allowedClientIds, ","),
		IntermediateCertPath: *intermediateCertDir,
		JwksUrl:              *jwksUrl,
		RootCertPath:         *rootCertDir,
		SignerHostName:       *signerHostName,
		TenantId:             azureConfig.TenantId,
	}

	var grpcServer *grpc.Server
	if tlsCreds != nil {
		grpcServer = grpc.NewServer(
			tlsCreds,
			grpc.StreamInterceptor(grpc_auth.StreamServerInterceptor(s.ValidateToken)),
			grpc.UnaryInterceptor(grpc_auth.UnaryServerInterceptor(s.ValidateToken)),
		)
	} else {
		grpcServer = grpc.NewServer(
			grpc.StreamInterceptor(grpc_auth.StreamServerInterceptor(s.ValidateToken)),
			grpc.UnaryInterceptor(grpc_auth.UnaryServerInterceptor(s.ValidateToken)),
		)
	}

	tlsBootstrapServer, err := NewServer(s)
	if err != nil {
		setupLog.Fatalf("failed to initialize server: %v", err)
		return err
	}

	pb.RegisterAKSBootstrapTokenRequestServer(grpcServer, tlsBootstrapServer)

	listener, err := net.Listen("tcp", fmt.Sprintf("%s:%d", *hostname, *port))
	if err != nil {
		setupLog.Fatalf("failed to listen on %s:%d: %v", *hostname, *port, err)
		return err
	}

	setupLog.Infof("starting server on %s:%d", *hostname, *port)
	grpcServer.Serve(listener)

	return nil
}
