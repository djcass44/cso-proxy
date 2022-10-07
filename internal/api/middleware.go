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
	"fmt"
	"github.com/djcass44/cso-proxy/internal/adapter"
	"github.com/djcass44/go-utils/utilities/httputils"
	"net/http"
	"regexp"
	"strings"
)

var ManifestRegex = regexp.MustCompile(`^/cso/v1/repository/([^/]+/){2,}manifest/([^/]+)/security$`)

type Middleware struct {
	dst adapter.Adapter
}

func NewMiddleware(dst adapter.Adapter) *Middleware {
	return &Middleware{
		dst: dst,
	}
}

func (m *Middleware) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !ManifestRegex.MatchString(r.URL.Path) {
		http.NotFound(w, r)
		return
	}
	features, vulnerabilities := r.URL.Query().Get("features") == "true", r.URL.Query().Get("vulnerabilities") == "true"
	path := strings.SplitN(strings.TrimPrefix(r.URL.Path, "/cso/v1/repository/"), "/manifest/", 2)[0]
	digest := ManifestRegex.FindStringSubmatch(r.URL.Path)[2]
	resp, code, err := m.dst.ManifestSecurity(r.Context(), path, digest, adapter.Opts{
		URI:             fmt.Sprintf("https://%s", r.Host),
		Features:        features,
		Vulnerabilities: vulnerabilities,
	})
	if err != nil {
		http.Error(w, err.Error(), code)
		return
	}
	httputils.ReturnJSON(r.Context(), w, code, resp)
}
