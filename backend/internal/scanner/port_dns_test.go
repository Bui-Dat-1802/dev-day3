package scanner

import (
	"testing"

	"mini-asm/internal/model"
)

func TestPortScanner_IsAllowedIP(t *testing.T) {
	s := NewPortScanner()
	cases := []struct {
		ip   string
		want bool
	}{
		{"127.0.0.1", true},
		{"10.0.0.5", true},
		{"172.16.0.1", true},
		{"192.168.1.1", true},
		{"8.8.8.8", false},
		{"invalid", false},
	}

	for _, c := range cases {
		if got := s.isAllowedIP(c.ip); got != c.want {
			t.Fatalf("isAllowedIP(%s) = %v; want %v", c.ip, got, c.want)
		}
	}
}

func TestDNSScanner_ExtractIPs(t *testing.T) {
	ds := NewDNSScanner()
	records := []*model.DNSRecord{
		{RecordType: "A", Value: "1.2.3.4"},
		{RecordType: "AAAA", Value: "::1"},
		{RecordType: "TXT", Value: "hello"},
		{RecordType: "A", Value: "1.2.3.4"}, // duplicate
	}

	ips := ds.ExtractIPs(records)
	if len(ips) != 2 { // 1.2.3.4 and ::1
		t.Fatalf("expected 2 unique IPs, got %d: %#v", len(ips), ips)
	}
}
