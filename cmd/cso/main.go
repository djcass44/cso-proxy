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
	"context"
	"github.com/djcass44/cso-proxy/internal/adapter"
	"github.com/djcass44/cso-proxy/internal/api"
	"github.com/djcass44/go-utils/logging"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/kelseyhightower/envconfig"
	"gitlab.com/autokubeops/serverless"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"net/http"
)

type environment struct {
	Port     int `envconfig:"PORT" default:"8080"`
	LogLevel int `split_words:"true"`
}

func main() {
	var e environment
	envconfig.MustProcess("cso", &e)

	// configure logging
	zc := zap.NewProductionConfig()
	zc.Level = zap.NewAtomicLevelAt(zapcore.Level(e.LogLevel * -1))

	log, _ := logging.NewZap(context.TODO(), zc)

	router := mux.NewRouter().UseEncodedPath()
	router.Use(handlers.ProxyHeaders, logging.Middleware(log))
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
		WithLogger(log).
		Run()
}
