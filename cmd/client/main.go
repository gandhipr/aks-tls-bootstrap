package main

import (
	"flag"
	"fmt"
	"strings"

	"github.com/phealy/aks-tls-bootstrap/pkg/client"
	"github.com/sirupsen/logrus"
)

var (
	log           = logrus.New()
	serverAddress = flag.String("server", "localhost:9123", "The hostname and port to connect to.")
	clientId      = flag.String("client-id", "", "The client ID for the assigned identity to use.")
	logFormat     = flag.String("log-format", "json", "Log format: json or text, default: json")
	tlsSkipVerify = flag.Bool("tls-skip-verify", false, "Skip TLS verification (dangerous, for testing only).")
	nextProto     = flag.String("next-proto", "", "ALPN Next Protocol value to send.")
	debug         = flag.Bool("debug", false, "enable debug logging (WILL LOG AUTHENTICATION DATA)")
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

	token, err := client.GetBootstrapToken(log, *serverAddress, *clientId, *tlsSkipVerify, *nextProto)
	if err != nil {
		log.Fatalf("Failed to retrieve bootstrap token: %v", err)
	}

	fmt.Println(token)
}
