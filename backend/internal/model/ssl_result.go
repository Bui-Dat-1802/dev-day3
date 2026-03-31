package model

import "time"

// SSLCertificate represents a parsed SSL/TLS certificate
type SSLCertificate struct {
	Subject         string    `json:"subject"`
	Issuer          string    `json:"issuer"`
	SerialNumber    string    `json:"serial_number"`
	ValidFrom       time.Time `json:"valid_from"`
	ValidUntil      time.Time `json:"valid_until"`
	DaysUntilExpiry int       `json:"days_until_expiry"`
	IsExpired       bool      `json:"is_expired"`
	IsSelfSigned    bool      `json:"is_self_signed"`
	SAN             []string  `json:"san"` // Subject Alternative Names
}

// SSLConnection represents TLS connection details
type SSLConnection struct {
	TLSVersion  string `json:"tls_version"`
	CipherSuite string `json:"cipher_suite"`
	KeyExchange string `json:"key_exchange"`
}

// SSLScanResult represents the result of an SSL/TLS scan
type SSLScanResult struct {
	ID          string         `json:"id"`
	AssetID     string         `json:"asset_id"`
	ScanJobID   string         `json:"scan_job_id"`
	Domain      string         `json:"domain"`
	Certificate SSLCertificate `json:"certificate"`
	Connection  SSLConnection  `json:"connection"`
	Grade       string         `json:"grade"`
	Issues      []string       `json:"issues"`
	CreatedAt   time.Time      `json:"created_at"`
}
