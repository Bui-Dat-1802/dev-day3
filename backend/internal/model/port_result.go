package model

import "time"

// OpenPort describes a single open port discovered on a host
type OpenPort struct {
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	State    string `json:"state"`
	Service  string `json:"service"`
	Version  string `json:"version"`
}

// PortScanResult represents aggregated port scan results for a host
type PortScanResult struct {
	ID             string     `json:"id"`
	AssetID        string     `json:"asset_id"`
	ScanJobID      string     `json:"scan_job_id"`
	IPAddress      string     `json:"ip_address"`
	OpenPorts      []OpenPort `json:"open_ports"`
	ClosedPorts    int        `json:"closed_ports"`
	TotalScanned   int        `json:"total_scanned"`
	ScanDurationMs int        `json:"scan_duration_ms"`
	CreatedAt      time.Time  `json:"created_at"`
}

// PortResult is the scanner-level result returned by scanner.PortScanner
type PortResult struct {
	IPAddress    string     `json:"ip_address"`
	OpenPorts    []OpenPort `json:"open_ports"`
	ClosedPorts  int        `json:"closed_ports"`
	TotalScanned int        `json:"total_scanned"`
	ScanDuration int64      `json:"scan_duration"` // milliseconds
	CreatedAt    time.Time  `json:"created_at"`
}
