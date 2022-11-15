package starter

import (
	"github.com/Azure/aks-tls-bootstrap/pkg/server"
	"github.com/sirupsen/logrus"
	"os"
)

func Execute() {
	setupLog := logrus.New()
	setupLog.Infof("starting server")

	if err := server.Run(); err != nil {
		setupLog.Errorf("server exited with error, err: %v", err)
		os.Exit(1)
	}

	setupLog.Infof("server exited without error")
	os.Exit(0)
}
