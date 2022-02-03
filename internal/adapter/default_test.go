package adapter

import (
	"github.com/stretchr/testify/assert"
	"net/url"
	"testing"
)

func uri(s string) *url.URL {
	u, err := url.Parse(s)
	if err != nil {
		panic(err)
	}
	return u
}

func TestDefaultAppName(t *testing.T) {
	var cases = []struct {
		in  *url.URL
		out string
	}{
		{
			uri("https://quay.io"),
			"io.quay",
		},
		{
			uri("https://harbor.dcas.dev/docker.io"),
			"dev.dcas.harbor",
		},
	}
	for _, tt := range cases {
		t.Run(tt.out, func(t *testing.T) {
			assert.EqualValues(t, tt.out, defaultAppName(tt.in))
		})
	}
}
