package scanner

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"math/big"
	"net"
	"strings"
	"time"

	"mini-asm/internal/model"
)

// SSLScanner performs SSL/TLS certificate scanning on domains
//
// SCAN CATEGORY: 🔴 ACTIVE (directly connects to target)
type SSLScanner struct {
	timeout time.Duration
}

// NewSSLScanner creates a new SSL scanner instance
func NewSSLScanner() *SSLScanner {
	return &SSLScanner{
		timeout: 10 * time.Second,
	}
}

// Type returns the scan type identifier
func (s *SSLScanner) Type() model.ScanType {
	return model.ScanTypeSSL
}

// Scan performs an SSL/TLS scan on the given domain asset
func (s *SSLScanner) Scan(asset *model.Asset) (*model.SSLScanResult, error) {
	if asset.Type != model.TypeDomain {
		return nil, fmt.Errorf("SSL scan only works on domain assets, got: %s", asset.Type)
	}

	domain := asset.Name

	// Connect with TLS
	dialer := &net.Dialer{Timeout: s.timeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", domain+":443", &tls.Config{
		InsecureSkipVerify: true, // #nosec G402 -- we want to scan even self-signed certs
		ServerName:         domain,
	})
	if err != nil {
		return nil, fmt.Errorf("TLS connection failed to %s: %w", domain, err)
	}
	defer conn.Close() // #nosec G104

	// Extract connection state
	state := conn.ConnectionState()

	// Build TLS version string
	tlsVersion := tlsVersionString(state.Version)

	// Build cipher suite string
	cipherSuite := tls.CipherSuiteName(state.CipherSuite)

	// Get peer certificates
	certs := state.PeerCertificates
	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificates found for %s", domain)
	}

	// Use the leaf (first) certificate
	leaf := certs[0]
	now := time.Now()

	// Calculate days until expiry
	daysUntilExpiry := int(leaf.NotAfter.Sub(now).Hours() / 24)
	isExpired := now.After(leaf.NotAfter)

	// Check if self-signed (issuer == subject)
	isSelfSigned := leaf.Issuer.String() == leaf.Subject.String()

	// Build SAN list
	sanList := make([]string, 0, len(leaf.DNSNames))
	sanList = append(sanList, leaf.DNSNames...)
	for _, ip := range leaf.IPAddresses {
		sanList = append(sanList, ip.String())
	}

	// Format serial number as hex with colons
	serialHex := formatSerial(leaf.SerialNumber)

	// Determine grade based on findings
	issues := []string{}
	grade := gradeSSL(tlsVersion, leaf, isExpired, isSelfSigned, &issues)

	result := &model.SSLScanResult{
		Domain: domain,
		Certificate: model.SSLCertificate{
			Subject:         leaf.Subject.String(),
			Issuer:          leaf.Issuer.String(),
			SerialNumber:    serialHex,
			ValidFrom:       leaf.NotBefore,
			ValidUntil:      leaf.NotAfter,
			DaysUntilExpiry: daysUntilExpiry,
			IsExpired:       isExpired,
			IsSelfSigned:    isSelfSigned,
			SAN:             sanList,
		},
		Connection: model.SSLConnection{
			TLSVersion:  tlsVersion,
			CipherSuite: cipherSuite,
			KeyExchange: keyExchangeString(state),
		},
		Grade:  grade,
		Issues: issues,
	}

	return result, nil
}

// tlsVersionString converts TLS version constant to human-readable string
func tlsVersionString(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("Unknown (0x%04x)", version)
	}
}

// keyExchangeString returns the key exchange algorithm from the connection state
func keyExchangeString(state tls.ConnectionState) string {
	// TLS 1.3 always uses ephemeral key exchange
	if state.Version == tls.VersionTLS13 {
		// Try to infer from the cipher suite name
		suiteName := tls.CipherSuiteName(state.CipherSuite)
		if strings.Contains(suiteName, "CHACHA") {
			return "X25519"
		}
		return "X25519"
	}
	// For TLS 1.2 and below, return generic DHE/RSA
	suiteName := tls.CipherSuiteName(state.CipherSuite)
	if strings.Contains(suiteName, "ECDHE") {
		return "ECDHE"
	}
	if strings.Contains(suiteName, "DHE") {
		return "DHE"
	}
	return "RSA"
}

// formatSerial formats a big.Int serial number as a colon-separated hex string
func formatSerial(serial *big.Int) string {
	if serial == nil {
		return "N/A"
	}
	hex := fmt.Sprintf("%x", serial)
	// Pad to even length
	if len(hex)%2 != 0 {
		hex = "0" + hex
	}
	// Insert colons every 2 characters
	parts := []string{}
	for i := 0; i < len(hex); i += 2 {
		parts = append(parts, hex[i:i+2])
	}
	return strings.Join(parts, ":")
}

// gradeSSL assigns an SSL grade (A/B/C/F) based on findings
func gradeSSL(tlsVersion string, cert *x509.Certificate, isExpired, isSelfSigned bool, issues *[]string) string {
	score := 100

	// Expired certificate is an immediate F
	if isExpired {
		*issues = append(*issues, "Certificate is expired")
		return "F"
	}

	// Self-signed certificate
	if isSelfSigned {
		*issues = append(*issues, "Self-signed certificate")
		score -= 20
	}

	// Expiring soon (within 14 days)
	daysLeft := int(time.Until(cert.NotAfter).Hours() / 24)
	if daysLeft < 14 {
		*issues = append(*issues, fmt.Sprintf("Certificate expires in %d days", daysLeft))
		score -= 10
	}

	// Old TLS versions
	switch tlsVersion {
	case "TLS 1.0":
		*issues = append(*issues, "TLS 1.0 is deprecated and insecure")
		score -= 40
	case "TLS 1.1":
		*issues = append(*issues, "TLS 1.1 is deprecated")
		score -= 20
	}

	// No SANs
	if len(cert.DNSNames) == 0 {
		*issues = append(*issues, "No Subject Alternative Names (SAN) found")
		score -= 10
	}

	if score >= 90 {
		return "A"
	} else if score >= 70 {
		return "B"
	} else if score >= 50 {
		return "C"
	}
	return "F"
}
