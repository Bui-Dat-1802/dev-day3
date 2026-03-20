package handler

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"mini-asm/internal/model"
)

// MockScanService minimal implementation for handler tests
type MockScanService struct {
	StartFunc      func(assetID string, scanType model.ScanType) (*model.ScanJob, error)
	GetResultsFunc func(jobID string) (interface{}, error)
	GetJobFunc     func(jobID string) (*model.ScanJob, error)
}

func (m *MockScanService) DemoSyncVsAsync(assetID string) error                  { return nil }
func (m *MockScanService) ListScanJobs(assetID string) ([]*model.ScanJob, error) { return nil, nil }
func (m *MockScanService) GetAssetSubdomains(assetID string) ([]*model.Subdomain, error) {
	return nil, nil
}
func (m *MockScanService) GetAssetDNSRecords(assetID string) ([]*model.DNSRecord, error) {
	return nil, nil
}
func (m *MockScanService) GetAssetWHOIS(assetID string) (*model.WHOISRecord, error) { return nil, nil }
func (m *MockScanService) GetAssetAllScanResults(assetID string) (map[string]interface{}, error) {
	return nil, nil
}

func (m *MockScanService) StartScan(assetID string, scanType model.ScanType) (*model.ScanJob, error) {
	if m.StartFunc != nil {
		return m.StartFunc(assetID, scanType)
	}
	return &model.ScanJob{ID: "job1", AssetID: assetID, ScanType: scanType}, nil
}
func (m *MockScanService) GetScanResults(jobID string) (interface{}, error) {
	if m.GetResultsFunc != nil {
		return m.GetResultsFunc(jobID)
	}
	return nil, nil
}
func (m *MockScanService) GetScanJob(jobID string) (*model.ScanJob, error) {
	if m.GetJobFunc != nil {
		return m.GetJobFunc(jobID)
	}
	return &model.ScanJob{ID: jobID}, nil
}

func TestStartScanHandler_Success(t *testing.T) {
	mock := &MockScanService{
		StartFunc: func(assetID string, scanType model.ScanType) (*model.ScanJob, error) {
			return &model.ScanJob{ID: "job-123", AssetID: assetID, ScanType: scanType}, nil
		},
	}

	h := NewScanHandler(mock)

	body := map[string]string{"scan_type": string(model.ScanTypeIP)}
	b, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/assets/a1/scan", bytes.NewReader(b))
	req.Header.Set("X-Path-id", "a1")
	w := httptest.NewRecorder()

	h.StartScan(w, req)

	if w.Code != http.StatusAccepted {
		t.Fatalf("expected 202 Accepted, got %d: %s", w.Code, w.Body.String())
	}

	var job model.ScanJob
	if err := json.NewDecoder(w.Body).Decode(&job); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if job.ID != "job-123" {
		t.Fatalf("unexpected job id: %s", job.ID)
	}
}

func TestGetScanResultsHandler_Success(t *testing.T) {
	mock := &MockScanService{
		GetResultsFunc: func(jobID string) (interface{}, error) {
			return []*model.IPResult{{IPAddress: "1.2.3.4"}}, nil
		},
	}
	h := NewScanHandler(mock)

	req := httptest.NewRequest(http.MethodGet, "/scan-jobs/job-1/results", nil)
	req.Header.Set("X-Path-id", "job-1")
	w := httptest.NewRecorder()

	h.GetScanResults(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", w.Code, w.Body.String())
	}

	var results []model.IPResult
	if err := json.NewDecoder(w.Body).Decode(&results); err != nil {
		t.Fatalf("failed to decode results: %v", err)
	}
	if len(results) != 1 || results[0].IPAddress != "1.2.3.4" {
		t.Fatalf("unexpected results: %#v", results)
	}
}
