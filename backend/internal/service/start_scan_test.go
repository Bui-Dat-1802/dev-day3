package service

import (
	"errors"
	"testing"
	"time"

	"mini-asm/internal/model"
	"mini-asm/internal/storage"
)

// -- Mocks ------------------------------------------------------------------
type mockStore struct {
	assets map[string]*model.Asset
}

func (m *mockStore) Create(a *model.Asset) error { return nil }
func (m *mockStore) GetAll(params storage.QueryParams) (*storage.PaginatedResult, error) {
	return &storage.PaginatedResult{}, nil
}
func (m *mockStore) GetByID(id string) (*model.Asset, error) {
	if a, ok := m.assets[id]; ok {
		return a, nil
	}
	return nil, errors.New("not found")
}
func (m *mockStore) Update(id string, a *model.Asset) error          { return nil }
func (m *mockStore) Delete(id string) error                          { return nil }
func (m *mockStore) Count(params storage.QueryParams) (int64, error) { return 0, nil }

type mockScanStore struct {
	createdJobs []*model.ScanJob
	updatedJobs []*model.ScanJob
	ipResults   []*model.IPResult
	portResults []*model.PortScanResult
}

func (m *mockScanStore) CreateScanJob(job *model.ScanJob) error {
	m.createdJobs = append(m.createdJobs, job)
	return nil
}
func (m *mockScanStore) GetScanJob(id string) (*model.ScanJob, error) {
	return nil, errors.New("not implemented")
}
func (m *mockScanStore) UpdateScanJob(job *model.ScanJob) error {
	m.updatedJobs = append(m.updatedJobs, job)
	return nil
}
func (m *mockScanStore) ListScanJobsByAsset(assetID string) ([]*model.ScanJob, error) {
	return nil, nil
}

func (m *mockScanStore) CreateSubdomain(sd *model.Subdomain) error { return nil }
func (m *mockScanStore) GetSubdomainsByAsset(assetID string) ([]*model.Subdomain, error) {
	return nil, nil
}
func (m *mockScanStore) GetSubdomainsByScan(scanJobID string) ([]*model.Subdomain, error) {
	return nil, nil
}

func (m *mockScanStore) CreateDNSRecord(r *model.DNSRecord) error { return nil }
func (m *mockScanStore) GetDNSRecordsByAsset(assetID string) ([]*model.DNSRecord, error) {
	return nil, nil
}
func (m *mockScanStore) GetDNSRecordsByScan(scanJobID string) ([]*model.DNSRecord, error) {
	return nil, nil
}

func (m *mockScanStore) CreateWHOISRecord(r *model.WHOISRecord) error { return nil }
func (m *mockScanStore) GetWHOISRecordByAsset(assetID string) (*model.WHOISRecord, error) {
	return nil, nil
}
func (m *mockScanStore) GetWHOISRecordsByScan(scanJobID string) ([]*model.WHOISRecord, error) {
	return nil, nil
}

func (m *mockScanStore) CreateIPResult(r *model.IPResult) error {
	m.ipResults = append(m.ipResults, r)
	return nil
}
func (m *mockScanStore) GetIPResultsByAsset(assetID string) ([]*model.IPResult, error) {
	return nil, nil
}
func (m *mockScanStore) GetIPResultsByScan(scanJobID string) ([]*model.IPResult, error) {
	return nil, nil
}

func (m *mockScanStore) CreatePortScanResult(r *model.PortScanResult) error {
	m.portResults = append(m.portResults, r)
	return nil
}
func (m *mockScanStore) GetPortScanResultsByAsset(assetID string) ([]*model.PortScanResult, error) {
	return nil, nil
}
func (m *mockScanStore) GetPortScanResultsByScan(scanJobID string) ([]*model.PortScanResult, error) {
	return nil, nil
}

// -- Fake scanners ---------------------------------------------------------
type fakeIPScanner struct{}

func (f *fakeIPScanner) Scan(a *model.Asset) ([]*model.IPResult, error) {
	r := &model.IPResult{IPAddress: a.Name}
	r.Geolocation.Country = "Testland"
	r.ASN.Number = 64500
	r.CreatedAt = time.Now()
	return []*model.IPResult{r}, nil
}

type fakePortScanner struct{}

func (f *fakePortScanner) Scan(a *model.Asset) ([]*model.PortResult, error) {
	pr := &model.PortResult{IPAddress: a.Name, ClosedPorts: 999, TotalScanned: 1000, ScanDuration: 100}
	pr.OpenPorts = []model.OpenPort{{Port: 80, Protocol: "tcp", State: "open", Service: "http"}}
	pr.CreatedAt = time.Now()
	return []*model.PortResult{pr}, nil
}

// -- Tests ------------------------------------------------------------------
func TestStartScan_IP(t *testing.T) {
	ms := &mockStore{assets: map[string]*model.Asset{"a1": {ID: "a1", Name: "1.2.3.4", Type: model.TypeIP}}}
	mss := &mockScanStore{}

	svc := &ScanService{storage: ms, scanStorage: mss, ipScanner: &fakeIPScanner{}}

	job, err := svc.StartScan("a1", model.ScanTypeIP)
	if err != nil {
		t.Fatalf("StartScan failed: %v", err)
	}
	if job.Results != 1 {
		t.Fatalf("expected 1 result, got %d", job.Results)
	}
	if job.Status != model.ScanStatusCompleted {
		t.Fatalf("expected completed status, got %s", job.Status)
	}
	if len(mss.ipResults) != 1 {
		t.Fatalf("expected ip result saved, got %d", len(mss.ipResults))
	}
}

func TestStartScan_Port(t *testing.T) {
	ms := &mockStore{assets: map[string]*model.Asset{"a2": {ID: "a2", Name: "127.0.0.1", Type: model.TypeIP}}}
	mss := &mockScanStore{}

	svc := &ScanService{storage: ms, scanStorage: mss, portScanner: &fakePortScanner{}}

	job, err := svc.StartScan("a2", model.ScanTypePort)
	if err != nil {
		t.Fatalf("StartScan failed: %v", err)
	}
	if job.Results != 1 {
		t.Fatalf("expected 1 port-host result, got %d", job.Results)
	}
	if job.Status != model.ScanStatusCompleted {
		t.Fatalf("expected completed status, got %s", job.Status)
	}
	if len(mss.portResults) != 1 {
		t.Fatalf("expected port result saved, got %d", len(mss.portResults))
	}
}
