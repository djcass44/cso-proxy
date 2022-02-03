package adapter

import (
	"github.com/quay/container-security-operator/secscan/quay"
	"gitlab.com/av1o/cso-proxy/internal/adapter/harbor"
	"net/http"
	"net/url"
)

type Adapter interface {
	Capabilities(uri *url.URL) *quay.AppCapabilities
	ManifestSecurity(w http.ResponseWriter, r *http.Request)
	ImageSecurity(w http.ResponseWriter, r *http.Request)
}

type HarborScan map[string]harbor.Report
