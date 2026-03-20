package scanner

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"mini-asm/internal/model"
)

func TestDNSScanner_Scan(t *testing.T) {
	s := NewDNSScanner()
	asset := &model.Asset{ID: "a1", Name: "localhost", Type: model.TypeDomain}

	records, err := s.Scan(asset)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(records) == 0 {
		t.Fatalf("expected at least one DNS record for localhost")
	}
}

func TestIPScanner_Scan_MockedAPI(t *testing.T) {
	// Mock ip-api.com JSON response
	mockResp := map[string]interface{}{
		"status":      "success",
		"country":     "Testland",
		"countryCode": "TL",
		"city":        "Testville",
		"region":      "TV",
		"lat":         1.23,
		"lon":         4.56,
		"isp":         "TestISP",
		"org":         "TestOrg",
		"as":          "AS64500 Test ASN",
		"reverse":     "host.test",
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(mockResp)
	}))
	defer srv.Close()

	// Create IPScanner and override client to redirect ip-api.com to our test server
	ips := &IPScanner{client: &http.Client{Timeout: 2 * time.Second}}

	// Custom DialContext to redirect ip-api.com:80 to test server address
	srvAddr := srv.Listener.Addr().String()
	ips.client.Transport = &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if strings.HasPrefix(addr, "ip-api.com:") || strings.HasPrefix(addr, "ip-api.com") {
				addr = srvAddr
			}
			var d net.Dialer
			return d.DialContext(ctx, network, addr)
		},
	}

	asset := &model.Asset{ID: "ip1", Name: "1.2.3.4", Type: model.TypeIP}
	res, err := ips.Scan(asset)
	if err != nil {
		t.Fatalf("IP scan failed: %v", err)
	}
	if len(res) == 0 {
		t.Fatalf("expected at least one IPResult")
	}
	if res[0].Geolocation.Country != "Testland" {
		t.Fatalf("unexpected country: %s", res[0].Geolocation.Country)
	}
	if res[0].ASN.Number == 0 {
		t.Fatalf("expected ASN number parsed")
	}
}

func TestWHOISScanner_Parse(t *testing.T) {
	s := NewWHOISScanner()
	raw := `Registrar: Example Registrar
Creation Date: 2020-01-02T03:04:05Z
Expiration Date: 2025-01-02T03:04:05Z
Name Server: ns1.example.com
Name Server: ns2.example.com
Email: admin@example.com
`

	rec := &model.WHOISRecord{}
	s.parseWHOIS(raw, rec)

	if rec.Registrar != "Example Registrar" {
		t.Fatalf("expected registrar parsed, got: %q", rec.Registrar)
	}
	if rec.NameServers == "" {
		t.Fatalf("expected name servers parsed")
	}
	if rec.Emails == "" {
		t.Fatalf("expected emails parsed")
	}
}
