package main

import (
	"flag"
	"fmt"

	"github.com/phealy/aks-tls-bootstrap/pkg/client"
	"github.com/sirupsen/logrus"
)

var (
	log           = logrus.New()
	serverAddress = flag.String("server", "localhost:9123", "The hostname and port to connect to.")
)

func main() {
	flag.Parse()
	log.SetReportCaller(true)
	log.SetFormatter(&logrus.TextFormatter{})

	token, err := client.GetBootstrapToken(log, *serverAddress)
	if err != nil {
		log.Fatalf("Failed to retrieve bootstrap token: %v", err)
	}

	fmt.Println(token)
}
