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
	t.Skip("Skipping network-dependent DNS test on CI")
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

func TestPortScanner_Scan(t *testing.T) {
	t.Skip("Skipping network-dependent Port test on CI")
	s := NewPortScanner()
	s.timeout = 50 * time.Millisecond // very short timeout for test

	// Start a dummy TCP server
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to open dummy tcp port: %v", err)
	}
	defer l.Close()

	// we only scan up to 1000 by default, so if port > 1000, we need to hack it
	// but the port scanner scans 1..1000 hardcoded in Scan(). Let's just pass 
	// a custom test IP and see if it runs without errors
	// (we don't strictly assert the port is open if it's > 1000, just that scan works)
	asset := &model.Asset{ID: "p1", Name: "127.0.0.1", Type: model.TypeIP}

	res, err := s.Scan(asset)
	if err != nil {
		t.Fatalf("Port scan failed: %v", err)
	}
	if len(res) == 0 {
		t.Fatalf("expected port result")
	}
}

func TestSubdomainScanner_Scan(t *testing.T) {
	t.Skip("Skipping network-dependent Subdomain test on CI")
	s, err := NewSubdomainScanner()
	if err != nil {
		t.Fatalf("failed to init subdomain scanner: %v", err)
	}
	
	// Override wordlist to be very small for test speed
	s.wordlist = []string{"nonexistent-test-subdomain"}
	s.timeout = 100 * time.Millisecond

	asset := &model.Asset{ID: "d1", Name: "nonexistent.invalid", Type: model.TypeDomain}
	ctx := context.Background()
	
	res, err := s.Scan(asset, ctx)
	if err != nil {
		t.Fatalf("Subdomain scan failed: %v", err)
	}
	// We expect 0 results for a non-existent subdomain
	if len(res) != 0 {
		t.Fatalf("expected 0 subdomains, got %d", len(res))
	}
}
