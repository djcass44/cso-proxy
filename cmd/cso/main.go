package main

import (
	"github.com/gorilla/mux"
	"github.com/kelseyhightower/envconfig"
	log "github.com/sirupsen/logrus"
	"gitlab.com/autokubeops/serverless"
	"gitlab.com/av1o/cso-proxy/internal/adapter"
	"gitlab.com/av1o/cso-proxy/internal/api"
	"net/http"
)

type environment struct {
	Port int `envconfig:"PORT" default:"8080"`
}

func main() {
	var e environment
	if err := envconfig.Process("cso", &e); err != nil {
		log.WithError(err).Fatal("failed to read environment")
		return
	}

	router := mux.NewRouter().UseEncodedPath()
	router.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("OK"))
	}).Methods(http.MethodGet)

	// setup caps
	manifest := api.NewCapabilities(adapter.NewHarborAdapter(router))

	// app paths
	router.Handle("/.well-known/app-capabilities", manifest).
		Methods(http.MethodGet)

	serverless.NewBuilder(router).
		WithPort(e.Port).
		Run()
}
