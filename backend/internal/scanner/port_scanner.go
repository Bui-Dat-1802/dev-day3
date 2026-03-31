package scanner

import (
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"mini-asm/internal/model"
)

// PortScanner performs basic TCP port scanning with safety checks
type PortScanner struct {
	timeout     time.Duration
	concurrency int
}

// NewPortScanner creates a new PortScanner with sensible defaults
func NewPortScanner() *PortScanner {
	return &PortScanner{timeout: 400 * time.Millisecond, concurrency: 100}
}

// Type returns the scan type identifier
func (s *PortScanner) Type() model.ScanType { return model.ScanTypePort }

// isAllowedIP enforces safety: only allow localhost and private ranges
func (s *PortScanner) isAllowedIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	if ip.IsLoopback() {
		return true
	}

	// IPv4 private ranges
	if ipv4 := ip.To4(); ipv4 != nil {
		b := ipv4
		switch {
		case b[0] == 10:
			return true
		case b[0] == 172 && b[1] >= 16 && b[1] <= 31:
			return true
		case b[0] == 192 && b[1] == 168:
			return true
		}
	}

	return false
}

// bannerRead attempts to read a small banner from a connection
func (s *PortScanner) bannerRead(conn net.Conn) string {
	conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil {
		if err == io.EOF || strings.Contains(err.Error(), "timeout") {
			return ""
		}
		return ""
	}
	return strings.TrimSpace(string(buf[:n]))
}

// commonServices maps port to likely service name
var commonServices = map[int]string{
	22:   "ssh",
	80:   "http",
	443:  "https",
	21:   "ftp",
	25:   "smtp",
	110:  "pop3",
	143:  "imap",
	3306: "mysql",
	5432: "postgresql",
}

// Scan performs a limited port scan for the given IP asset
// Scans ports 1..1000 by default; safety restricted to private/local ranges
func (s *PortScanner) Scan(asset *model.Asset) ([]*model.PortResult, error) {
	if asset.Type != model.TypeIP {
		return nil, fmt.Errorf("port scan only works on ip assets, got: %s", asset.Type)
	}

	ip := asset.Name
	if !s.isAllowedIP(ip) {
		return nil, fmt.Errorf("port scan disallowed for IP: %s (only local/private ranges allowed)", ip)
	}

	start := time.Now()
	portsToScan := 1000
	sem := make(chan struct{}, s.concurrency)
	var mu sync.Mutex
	openPorts := []model.OpenPort{}
	var wg sync.WaitGroup

	for port := 1; port <= portsToScan; port++ {
		wg.Add(1)
		sem <- struct{}{}
		go func(p int) {
			defer wg.Done()
			defer func() { <-sem }()

			addr := fmt.Sprintf("%s:%d", ip, p)
			conn, err := net.DialTimeout("tcp", addr, s.timeout)
			if err != nil {
				return
			}
			// connected => open
			// attempt banner read for some services
			version := s.bannerRead(conn)
			conn.Close()

			service := ""
			if name, ok := commonServices[p]; ok {
				service = name
			}
			op := model.OpenPort{Port: p, Protocol: "tcp", State: "open", Service: service, Version: version}
			mu.Lock()
			openPorts = append(openPorts, op)
			mu.Unlock()
		}(port)
	}

	wg.Wait()
	duration := time.Since(start)

	result := &model.PortResult{
		IPAddress:    ip,
		OpenPorts:    openPorts,
		ClosedPorts:  portsToScan - len(openPorts),
		TotalScanned: portsToScan,
		ScanDuration: duration.Milliseconds(),
		CreatedAt:    time.Now(),
	}

	// Caller sets ID/AssetID/ScanJobID
	return []*model.PortResult{result}, nil
}
