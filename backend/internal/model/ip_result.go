package model

import "time"

// IPResult represents geolocation and ASN information for an IP address
type IPResult struct {
	ID          string    `json:"id"`
	AssetID     string    `json:"asset_id"`
	ScanJobID   string    `json:"scan_job_id"`
	IPAddress   string    `json:"ip_address"`
	Geolocation GeoInfo   `json:"geolocation"`
	ASN         ASNInfo   `json:"asn"`
	ReverseDNS  string    `json:"reverse_dns"`
	CreatedAt   time.Time `json:"created_at"`
}

// GeoInfo contains basic geolocation details
type GeoInfo struct {
	Country     string  `json:"country"`
	CountryCode string  `json:"country_code"`
	City        string  `json:"city"`
	Region      string  `json:"region"`
	Latitude    float64 `json:"latitude"`
	Longitude   float64 `json:"longitude"`
	ISP         string  `json:"isp"`
	Org         string  `json:"org"`
}

// ASNInfo contains ASN number and descriptive fields
type ASNInfo struct {
	Number      int    `json:"number"`
	Name        string `json:"name"`
	Description string `json:"description"`
}
