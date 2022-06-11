package main

import (
	"flag"
	"fmt"
	"net"

	pb "github.com/phealy/aks-tls-bootstrap/pkg/proto"
	server "github.com/phealy/aks-tls-bootstrap/pkg/server"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
)

var (
	log            = logrus.New()
	hostname       = flag.String("hostname", "localhost", "The hostname to listen on (localhost by default).")
	port           = flag.Int("port", 9123, "The port to run the gRPC server on.")
	signerHostName = flag.String("imds-signer-name", "metadata.azure.com", "The hostname that must be present in the signing certificate from IMDS.")
)

func main() {
	flag.Parse()
	log.SetReportCaller(true)
	log.SetFormatter(&logrus.JSONFormatter{})
	log.SetLevel(logrus.DebugLevel)

	listener, err := net.Listen("tcp", fmt.Sprintf("%s:%d", *hostname, *port))
	if err != nil {
		log.Fatalf("failed to listen on %s:%s: %v", *hostname, *port, err)
	}

	grpcServer := grpc.NewServer()
	tlsBootstrapServer, err := server.NewServer(log, signerHostName)
	if err != nil {
		log.Fatalf("failed to initialize server: %v", err)
	}

	pb.RegisterAKSBootstrapTokenRequestServer(grpcServer, tlsBootstrapServer)

	log.Infof("starting server on %s:%d", *hostname, *port)
	grpcServer.Serve(listener)
}
