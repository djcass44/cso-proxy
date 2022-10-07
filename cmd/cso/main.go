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
	"github.com/djcass44/go-utils/otel"
	"github.com/djcass44/go-utils/otel/metrics"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/kelseyhightower/envconfig"
	"gitlab.com/autokubeops/serverless"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"net/http"
	"os"
)

type environment struct {
	Port     int `envconfig:"PORT" default:"8080"`
	LogLevel int `split_words:"true"`

	Otel struct {
		Enabled    bool    `split_words:"true"`
		SampleRate float64 `split_words:"true"`
	}
}

func main() {
	var e environment
	envconfig.MustProcess("cso", &e)

	// configure logging
	zc := zap.NewProductionConfig()
	zc.Level = zap.NewAtomicLevelAt(zapcore.Level(e.LogLevel * -1))

	log, ctx := logging.NewZap(context.TODO(), zc)

	// configure open telemetry
	if err := otel.Build(ctx, otel.Options{
		Enabled:     e.Otel.Enabled,
		ServiceName: "cso-proxy",
		Environment: "",
		SampleRate:  e.Otel.SampleRate,
	}); err != nil {
		log.Error(err, "failed to configure OpenTelemetry")
		os.Exit(1)
		return
	}

	// configure prometheus
	prom := metrics.MustNewDefault(ctx)

	router := mux.NewRouter().UseEncodedPath()
	router.Use(handlers.ProxyHeaders, logging.Middleware(log), otel.Middleware(), metrics.Middleware())
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
	router.Handle("/metrics", prom)

	serverless.NewBuilder(router).
		WithPort(e.Port).
		WithLogger(log).
		Run()
}
