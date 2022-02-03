package api

import (
	"github.com/djcass44/go-utils/pkg/httputils"
	"gitlab.com/av1o/cso-proxy/internal/adapter"
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
	httputils.ReturnJSON(w, http.StatusOK, c.dst.Capabilities(r.URL))
}
