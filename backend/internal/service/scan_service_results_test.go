package service

import (
	"testing"
	"time"

	"mini-asm/internal/model"
	"mini-asm/internal/storage"
)

// MockScanStorage implements storage.ScanStorage for tests
type MockScanStorage struct {
	jobs        map[string]*model.ScanJob
	ipResults   map[string][]*model.IPResult
	portResults map[string][]*model.PortScanResult
}

func NewMockScanStorage() *MockScanStorage {
	return &MockScanStorage{
		jobs:        make(map[string]*model.ScanJob),
		ipResults:   make(map[string][]*model.IPResult),
		portResults: make(map[string][]*model.PortScanResult),
	}
}

func (m *MockScanStorage) CreateScanJob(job *model.ScanJob) error {
	m.jobs[job.ID] = job
	return nil
}
func (m *MockScanStorage) GetScanJob(id string) (*model.ScanJob, error) { return m.jobs[id], nil }
func (m *MockScanStorage) UpdateScanJob(job *model.ScanJob) error       { m.jobs[job.ID] = job; return nil }
func (m *MockScanStorage) ListScanJobsByAsset(assetID string) ([]*model.ScanJob, error) {
	return nil, nil
}

func (m *MockScanStorage) CreateSubdomain(subdomain *model.Subdomain) error { return nil }
func (m *MockScanStorage) GetSubdomainsByAsset(assetID string) ([]*model.Subdomain, error) {
	return nil, nil
}
func (m *MockScanStorage) GetSubdomainsByScan(scanJobID string) ([]*model.Subdomain, error) {
	return nil, nil
}

func (m *MockScanStorage) CreateDNSRecord(record *model.DNSRecord) error { return nil }
func (m *MockScanStorage) GetDNSRecordsByAsset(assetID string) ([]*model.DNSRecord, error) {
	return nil, nil
}
func (m *MockScanStorage) GetDNSRecordsByScan(scanJobID string) ([]*model.DNSRecord, error) {
	return nil, nil
}

func (m *MockScanStorage) CreateWHOISRecord(record *model.WHOISRecord) error { return nil }
func (m *MockScanStorage) GetWHOISRecordByAsset(assetID string) (*model.WHOISRecord, error) {
	return nil, nil
}
func (m *MockScanStorage) GetWHOISRecordsByScan(scanJobID string) ([]*model.WHOISRecord, error) {
	return nil, nil
}

func (m *MockScanStorage) CreateIPResult(result *model.IPResult) error {
	m.ipResults[result.ScanJobID] = append(m.ipResults[result.ScanJobID], result)
	return nil
}
func (m *MockScanStorage) GetIPResultsByAsset(assetID string) ([]*model.IPResult, error) {
	return nil, nil
}
func (m *MockScanStorage) GetIPResultsByScan(scanJobID string) ([]*model.IPResult, error) {
	return m.ipResults[scanJobID], nil
}

func (m *MockScanStorage) CreatePortScanResult(result *model.PortScanResult) error {
	m.portResults[result.ScanJobID] = append(m.portResults[result.ScanJobID], result)
	return nil
}
func (m *MockScanStorage) GetPortScanResultsByAsset(assetID string) ([]*model.PortScanResult, error) {
	return nil, nil
}
func (m *MockScanStorage) GetPortScanResultsByScan(scanJobID string) ([]*model.PortScanResult, error) {
	return m.portResults[scanJobID], nil
}

// Ensure MockScanStorage implements storage.ScanStorage
var _ storage.ScanStorage = (*MockScanStorage)(nil)

func TestGetScanResults_IP(t *testing.T) {
	mock := NewMockScanStorage()
	job := &model.ScanJob{ID: "job-ip-1", ScanType: model.ScanTypeIP}
	mock.jobs[job.ID] = job

	// Prepare IP result
	ipr := &model.IPResult{
		ID:        "r1",
		IPAddress: "1.2.3.4",
		CreatedAt: time.Now(),
		ScanJobID: job.ID,
	}
	mock.ipResults[job.ID] = []*model.IPResult{ipr}

	s := &ScanService{scanStorage: mock}

	res, err := s.GetScanResults(job.ID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got, ok := res.([]*model.IPResult)
	if !ok {
		t.Fatalf("expected []*model.IPResult, got %T", res)
	}
	if len(got) != 1 || got[0].IPAddress != "1.2.3.4" {
		t.Fatalf("unexpected results: %#v", got)
	}
}

func TestGetScanResults_Port(t *testing.T) {
	mock := NewMockScanStorage()
	job := &model.ScanJob{ID: "job-port-1", ScanType: model.ScanTypePort}
	mock.jobs[job.ID] = job

	pr := &model.PortScanResult{
		ID:        "p1",
		IPAddress: "127.0.0.1",
		ScanJobID: job.ID,
		CreatedAt: time.Now(),
		OpenPorts: []model.OpenPort{{Port: 22, Protocol: "tcp", State: "open", Service: "ssh"}},
	}
	mock.portResults[job.ID] = []*model.PortScanResult{pr}

	s := &ScanService{scanStorage: mock}

	res, err := s.GetScanResults(job.ID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got, ok := res.([]*model.PortScanResult)
	if !ok {
		t.Fatalf("expected []*model.PortScanResult, got %T", res)
	}
	if len(got) != 1 || got[0].IPAddress != "127.0.0.1" {
		t.Fatalf("unexpected results: %#v", got)
	}
}
