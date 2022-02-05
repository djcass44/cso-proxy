/*
 *    Copyright 2022 Django Cass
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 *
 */

package main

import (
	"github.com/djcass44/cso-proxy/internal/adapter"
	"github.com/djcass44/cso-proxy/internal/api"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/kelseyhightower/envconfig"
	log "github.com/sirupsen/logrus"
	"gitlab.com/autokubeops/serverless"
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
	router.Use(handlers.ProxyHeaders)
	router.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("OK"))
	}).Methods(http.MethodGet)

	// setup caps
	dst := adapter.NewHarborAdapter()
	manifest := api.NewCapabilities(dst)
	middleware := api.NewMiddleware(dst)

	// app paths
	router.Handle("/.well-known/app-capabilities", manifest).
		Methods(http.MethodGet)
	router.PathPrefix("/cso/v1/repository/").
		Handler(middleware).
		Methods(http.MethodGet)

	serverless.NewBuilder(router).
		WithPort(e.Port).
		Run()
}
