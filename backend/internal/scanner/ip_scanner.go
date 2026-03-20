package scanner

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"mini-asm/internal/model"
)

// IPScanner performs geolocation and ASN lookup for IP addresses
type IPScanner struct {
	client *http.Client
}

// NewIPScanner creates a new IP scanner instance
func NewIPScanner() *IPScanner {
	return &IPScanner{
		client: &http.Client{Timeout: 8 * time.Second},
	}
}

// Type returns the scan type identifier
func (s *IPScanner) Type() model.ScanType {
	return model.ScanTypeIP
}

// Scan performs geolocation + ASN lookup for an IP asset
func (s *IPScanner) Scan(asset *model.Asset) ([]*model.IPResult, error) {
	if asset.Type != model.TypeIP {
		return nil, fmt.Errorf("IP scan only works on ip assets, got: %s", asset.Type)
	}

	ip := asset.Name
	// Use ip-api.com as the external provider
	url := fmt.Sprintf("http://ip-api.com/json/%s?fields=status,country,countryCode,city,region,lat,lon,isp,org,as,reverse", ip)

	resp, err := s.client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ip lookup failed: status %d", resp.StatusCode)
	}

	var out struct {
		Status      string  `json:"status"`
		Country     string  `json:"country"`
		CountryCode string  `json:"countryCode"`
		City        string  `json:"city"`
		Region      string  `json:"region"`
		Lat         float64 `json:"lat"`
		Lon         float64 `json:"lon"`
		ISP         string  `json:"isp"`
		Org         string  `json:"org"`
		AS          string  `json:"as"`
		Reverse     string  `json:"reverse"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("failed to decode ip-api response: %w", err)
	}

	if strings.ToLower(out.Status) != "success" {
		return nil, fmt.Errorf("ip-api returned non-success status")
	}

	// Parse AS field like "AS13335 Cloudflare, Inc." -> number and name
	asNumber := 0
	asName := ""
	asDesc := ""
	if out.AS != "" {
		parts := strings.SplitN(out.AS, " ", 2)
		if len(parts) >= 1 {
			p := strings.TrimPrefix(parts[0], "AS")
			var n int
			fmt.Sscanf(p, "%d", &n)
			asNumber = n
		}
		if len(parts) == 2 {
			asName = parts[1]
			asDesc = parts[1]
		}
	}

	res := &model.IPResult{
		IPAddress: ip,
	}
	res.Geolocation.Country = out.Country
	res.Geolocation.CountryCode = out.CountryCode
	res.Geolocation.City = out.City
	res.Geolocation.Region = out.Region
	res.Geolocation.Latitude = out.Lat
	res.Geolocation.Longitude = out.Lon
	res.Geolocation.ISP = out.ISP
	res.Geolocation.Org = out.Org
	res.ASN.Number = asNumber
	res.ASN.Name = asName
	res.ASN.Description = asDesc
	res.ReverseDNS = out.Reverse
	res.CreatedAt = time.Now()

	// Fill ID, AssetID and ScanJobID are set by caller
	return []*model.IPResult{res}, nil
}
