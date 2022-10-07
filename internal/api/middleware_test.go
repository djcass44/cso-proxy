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

package api

import (
	"context"
	"fmt"
	"github.com/djcass44/cso-proxy/internal/adapter"
	"github.com/go-logr/logr"
	"github.com/go-logr/logr/testr"
	"github.com/quay/container-security-operator/secscan"
	"github.com/quay/container-security-operator/secscan/quay"
	"github.com/stretchr/testify/assert"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

type testAdapter struct{}

func (t testAdapter) Capabilities(*url.URL) *quay.AppCapabilities {
	return &quay.AppCapabilities{}
}

func (t testAdapter) ManifestSecurity(context.Context, string, string, adapter.Opts) (*secscan.Response, int, error) {
	return &secscan.Response{
		Status: "",
		Data:   secscan.Data{},
	}, http.StatusOK, nil
}

func TestMiddleware_ServeHTTP(t *testing.T) {
	ctx := logr.NewContext(context.TODO(), testr.NewWithOptions(t, testr.Options{Verbosity: 10}))
	var cases = []struct {
		path string
		code int
	}{
		{
			"/cso/v1/repository/registry.gitlab.com/av1o/base-images/alpine/manifest/sha256:f42e1d4f05bfd2911c7a205588348d06c7af7ec9bb46e2cb4846e733fb0399da/security",
			http.StatusOK,
		},
		{
			"/cso/v1/repository/bitnami/postgresql/manifest/foobar/security",
			http.StatusOK,
		},
		{
			"/cso/v1/repository/bitnami/postgresql/image/foobar/security",
			http.StatusNotFound,
		},
	}
	m := NewMiddleware(&testAdapter{})
	for _, tt := range cases {
		t.Run(tt.path, func(t *testing.T) {
			w := httptest.NewRecorder()
			m.ServeHTTP(w, httptest.NewRequest(http.MethodGet, fmt.Sprintf("https://example.org%s", tt.path), nil).WithContext(ctx))
			assert.EqualValues(t, tt.code, w.Code)
		})
	}
}
