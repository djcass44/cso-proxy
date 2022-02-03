package adapter

import (
	"github.com/quay/container-security-operator/secscan/quay"
	"net/url"
)

type Adapter interface {
	Capabilities(uri *url.URL) *quay.AppCapabilities
}
