package handler

import (
	"net/http"
	"strings"
)

// PathProvider extracts path parameters from a request.
type PathProvider interface {
	Get(r *http.Request, key string) string
}

// DefaultPathProvider implements PathProvider with simple heuristics.
// It first checks the header "X-Path-<key>" (useful for tests), then
// falls back to returning the last path segment.
type DefaultPathProvider struct{}

func (d *DefaultPathProvider) Get(r *http.Request, key string) string {
	if r == nil {
		return ""
	}
	// Try Go 1.22 PathValue first
	if val := r.PathValue(key); val != "" {
		return val
	}
	// Header override for tests
	h := r.Header.Get("X-Path-" + key)
	if h != "" {
		return h
	}

	// Fallback: last non-empty path segment
	parts := strings.Split(r.URL.Path, "/")
	for i := len(parts) - 1; i >= 0; i-- {
		p := strings.TrimSpace(parts[i])
		if p != "" {
			return p
		}
	}
	return ""
}
