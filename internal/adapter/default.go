package adapter

import (
	"net/url"
	"strings"
)

func defaultAppName(uri *url.URL) string {
	ss := strings.Split(uri.Hostname(), ".")
	// reverse the slice
	// https://stackoverflow.com/a/34816623
	last := len(ss) - 1
	for i := 0; i < len(ss)/2; i++ {
		ss[i], ss[last-i] = ss[last-i], ss[i]
	}
	return strings.Join(ss, ".")
}
