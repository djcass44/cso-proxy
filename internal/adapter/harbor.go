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

package adapter

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/djcass44/cso-proxy/internal/adapter/harbor"
	"github.com/djcass44/go-utils/pkg/httputils"
	"github.com/quay/container-security-operator/secscan"
	"github.com/quay/container-security-operator/secscan/quay"
	log "github.com/sirupsen/logrus"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Harbor struct{}

func NewHarborAdapter() *Harbor {
	h := new(Harbor)

	return h
}

func (*Harbor) Capabilities(uri *url.URL) *quay.AppCapabilities {
	appURL := fmt.Sprintf("%s://%s", uri.Scheme, uri.Host)
	return &quay.AppCapabilities{
		AppName: defaultAppName(uri),
		Capabilities: quay.Capabilities{
			ViewImage: struct {
				UrlTemplate string `json:"url-template"`
			}{
				UrlTemplate: fmt.Sprintf("%s/{namespace}/{reponame}:{tag}", appURL),
			},
			ManifestSecurity: struct {
				RestApiTemplate string `json:"rest-api-template"`
			}{
				RestApiTemplate: fmt.Sprintf("%s/cso/v1/repository/{namespace}/{reponame}/manifest/{digest}/security", appURL),
			},
			ImageSecurity: struct {
				RestApiTemplate string `json:"rest-api-template"`
			}{
				RestApiTemplate: "",
			},
		},
	}
}

func (h *Harbor) ManifestSecurity(ctx context.Context, path, digest string, opts Opts) (*secscan.Response, int, error) {
	bits := strings.SplitN(path, "/", 2)
	namespace, reponame := bits[0], bits[1]
	log.WithContext(ctx).WithFields(log.Fields{
		"namespace": namespace,
		"reponame":  reponame,
		"digest":    digest,
	}).Infof("fetching manifest information")
	reponame = url.PathEscape(reponame)
	return h.vulnerabilityInfo(ctx, opts.URI, namespace, reponame, digest, opts.Features, opts.Vulnerabilities)
}

func (*Harbor) vulnerabilityInfo(ctx context.Context, uri, namespace, repository, reference string, showFeatures, showVulnerabilities bool) (*secscan.Response, int, error) {
	target := fmt.Sprintf("%s/api/v2.0/projects/%s/repositories/%s/artifacts/%s/additions/vulnerabilities", uri, namespace, repository, reference)
	log.WithContext(ctx).Infof("targeting url: %s", target)
	// prep the request
	req, err := http.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		log.WithError(err).WithContext(ctx).Error("failed to prepare request")
		return nil, http.StatusInternalServerError, err
	}
	req.Header.Set("X-Accept-Vulnerabilities", "application/vnd.security.vulnerability.report; version=1.1")
	// execute the request
	start := time.Now()
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.WithError(err).WithContext(ctx).Error("failed to execute request")
		return nil, http.StatusInternalServerError, err
	}
	defer resp.Body.Close()
	log.WithContext(ctx).Infof("registry responded with status: %s in %s", resp.Status, time.Since(start))
	// handle errors
	if httputils.IsHTTPError(resp.StatusCode) {
		log.WithContext(ctx).Warningf("request failed with code: %d", resp.StatusCode)
		return nil, resp.StatusCode, fmt.Errorf("request failed: %s", resp.Status)
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.WithError(err).WithContext(ctx).Error("failed to read response body")
		return nil, resp.StatusCode, err
	}
	var report harbor.Response
	if err := json.Unmarshal(body, &report); err != nil {
		log.WithError(err).WithContext(ctx).Error("failed to unmarshal response")
		return nil, http.StatusInternalServerError, err
	}
	packages := map[string][]*secscan.Vulnerability{}
	for k, v := range report {
		log.WithContext(ctx).Infof("reading report: '%s'", k)
		for _, f := range v.Vulnerabilities {
			name := fmt.Sprintf("%s:%s", f.Package, f.Version)
			packages[name] = append(packages[name], &secscan.Vulnerability{
				Name:          f.ID,
				NamespaceName: "",
				Description:   f.Description,
				Link:          first(f.Links),
				Severity:      f.Severity,
				FixedBy:       f.FixVersion,
			})
		}
	}
	//goland:noinspection GoPreferNilSlice
	features := []*secscan.Feature{}
	for k, v := range packages {
		if !showFeatures {
			continue
		}
		name, version, _ := net.SplitHostPort(k)
		f := &secscan.Feature{
			Name:            name,
			NamespaceName:   "",
			VersionFormat:   "",
			Version:         version,
			Vulnerabilities: v,
			AddedBy:         "",
		}
		if !showVulnerabilities {
			f.Vulnerabilities = []*secscan.Vulnerability{}
		}
		features = append(features, f)
	}
	return &secscan.Response{
		Status: "scanned",
		Data: secscan.Data{
			Layer: secscan.Layer{
				Features: features,
			},
		},
	}, http.StatusOK, nil
}

func first(s []string) string {
	if len(s) == 0 {
		return ""
	}
	return s[0]
}
