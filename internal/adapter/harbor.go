package adapter

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/djcass44/go-utils/pkg/httputils"
	"github.com/gorilla/mux"
	"github.com/quay/container-security-operator/secscan"
	"github.com/quay/container-security-operator/secscan/quay"
	log "github.com/sirupsen/logrus"
	"gitlab.com/av1o/cso-proxy/internal/adapter/harbor"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"time"
)

type Harbor struct{}

func NewHarborAdapter(router *mux.Router) *Harbor {
	h := new(Harbor)

	router.HandleFunc("/cso/v1/repository/{namespace}/{reponame}/manifest/{digest}/security", h.ManifestSecurity).
		Methods(http.MethodGet)
	router.HandleFunc("/cso/v1/repository/{namespace}/{reponame}/image/{imageid}/security", h.ImageSecurity).
		Methods(http.MethodGet)

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
				RestApiTemplate: fmt.Sprintf("%s/cso/v1/repository/{namespace}/{reponame}/image/{imageid}/security", appURL),
			},
		},
	}
}

func (h *Harbor) ManifestSecurity(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	namespace, reponame, digest := vars["namespace"], vars["reponame"], vars["digest"]
	log.WithContext(r.Context()).WithFields(log.Fields{
		"namespace": namespace,
		"reponame":  reponame,
		"digest":    digest,
	}).Infof("fetching manifest information")
	uri := fmt.Sprintf("%s://%s", r.URL.Scheme, r.URL.Host)
	report, err := h.vulnerabilityInfo(r.Context(), uri, namespace, reponame, digest)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	httputils.ReturnJSON(w, http.StatusOK, report)
}

func (h *Harbor) ImageSecurity(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	namespace, reponame, imageid := vars["namespace"], vars["reponame"], vars["imageid"]
	log.WithContext(r.Context()).WithFields(log.Fields{
		"namespace": namespace,
		"reponame":  reponame,
		"imageid":   imageid,
	}).Infof("fetching image information")
	uri := fmt.Sprintf("%s://%s", r.URL.Scheme, r.URL.Host)
	report, err := h.vulnerabilityInfo(r.Context(), uri, namespace, reponame, imageid)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	httputils.ReturnJSON(w, http.StatusOK, report)
}

func (*Harbor) vulnerabilityInfo(ctx context.Context, uri, namespace, repository, reference string) (*secscan.Response, error) {
	target := fmt.Sprintf("%s/api/v2.0/projects/%s/repositories/%s/artifacts/%s/additions/vulnerabilities", uri, namespace, repository, reference)
	log.WithContext(ctx).Infof("targeting url: %s", target)
	// prep the request
	req, err := http.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		log.WithError(err).WithContext(ctx).Error("failed to prepare request")
		return nil, err
	}
	req.Header.Set("X-Accept-Vulnerabilities", "application/vnd.security.vulnerability.report; version=1.1")
	// execute the request
	start := time.Now()
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.WithError(err).WithContext(ctx).Error("failed to execute request")
		return nil, err
	}
	defer resp.Body.Close()
	log.WithContext(ctx).Infof("registry responded with status: %s in %s", resp.Status, time.Since(start))
	// handle errors
	if httputils.IsHTTPError(resp.StatusCode) {
		log.WithContext(ctx).Warningf("request failed with code: %d", resp.StatusCode)
		return nil, fmt.Errorf("request failed: %s", resp.Status)
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.WithError(err).WithContext(ctx).Error("failed to read response body")
		return nil, err
	}
	var report harbor.Response
	if err := json.Unmarshal(body, &report); err != nil {
		log.WithError(err).WithContext(ctx).Error("failed to unmarshal response")
		return nil, err
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
	var features []*secscan.Feature
	for k, v := range packages {
		name, version, _ := net.SplitHostPort(k)
		features = append(features, &secscan.Feature{
			Name:            name,
			NamespaceName:   "",
			VersionFormat:   "",
			Version:         version,
			Vulnerabilities: v,
			AddedBy:         "",
		})
	}
	return &secscan.Response{
		Status: "scanned",
		Data: secscan.Data{
			Layer: secscan.Layer{
				Features: features,
			},
		},
	}, nil
}

func first(s []string) string {
	if len(s) == 0 {
		return ""
	}
	return s[0]
}
