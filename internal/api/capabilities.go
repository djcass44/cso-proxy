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
	"github.com/djcass44/cso-proxy/internal/adapter"
	"github.com/djcass44/go-utils/utilities/httputils"
	"net/http"
)

type Capabilities struct {
	dst adapter.Adapter
}

func NewCapabilities(dst adapter.Adapter) *Capabilities {
	return &Capabilities{
		dst: dst,
	}
}

func (c *Capabilities) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	uri := r.URL
	uri.Host = r.Host
	// assume the scheme is HTTPS
	if uri.Scheme == "" {
		uri.Scheme = "https"
	}
	httputils.ReturnJSON(r.Context(), w, http.StatusOK, c.dst.Capabilities(uri))
}
