package adapter

import (
	"fmt"
	"github.com/quay/container-security-operator/secscan/quay"
	"net/url"
)

type Registry struct{}

func NewRegistry() *Registry {
	return &Registry{}
}

func (r *Registry) Capabilities(uri *url.URL) *quay.AppCapabilities {
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
