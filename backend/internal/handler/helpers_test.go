package handler

import (
	"net/http"
	"net/url"
	"testing"

	"mini-asm/internal/model"
)

func TestParseIntParam_Defaults(t *testing.T) {
	req := &http.Request{URL: &url.URL{RawQuery: ""}}
	if got := parseIntParam(req, "page", 3); got != 3 {
		t.Fatalf("expected default 3, got %d", got)
	}
}

func TestParseIntParam_Valid(t *testing.T) {
	req := &http.Request{URL: &url.URL{RawQuery: "page=2"}}
	if got := parseIntParam(req, "page", 1); got != 2 {
		t.Fatalf("expected 2, got %d", got)
	}
}

func TestPaginateResults_DNSRecords(t *testing.T) {
	records := []*model.DNSRecord{
		{RecordType: "A", Name: "a1", Value: "1.1.1.1"},
		{RecordType: "A", Name: "a2", Value: "2.2.2.2"},
		{RecordType: "A", Name: "a3", Value: "3.3.3.3"},
	}

	res := paginateResults(records, 1, 2)
	data, ok := res.Data.([]*model.DNSRecord)
	if !ok {
		t.Fatalf("expected slice of DNSRecord, got %T", res.Data)
	}
	if len(data) != 2 {
		t.Fatalf("expected 2 items, got %d", len(data))
	}
	if res.Total != 3 {
		t.Fatalf("expected total 3, got %d", res.Total)
	}
}

func TestMapErrorToStatus_NotFound(t *testing.T) {
	if code := mapErrorToStatus(model.ErrNotFound); code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", code)
	}
}
