package service

import (
	"testing"
	"mini-asm/internal/model"
	"mini-asm/internal/storage"
)

// MockAssetStorage implements storage.Storage for testing
type MockAssetStorage struct {
	assets map[string]*model.Asset
}

func NewMockAssetStorage() *MockAssetStorage {
	return &MockAssetStorage{
		assets: make(map[string]*model.Asset),
	}
}

func (m *MockAssetStorage) Create(asset *model.Asset) error {
	m.assets[asset.ID] = asset
	return nil
}

func (m *MockAssetStorage) GetAll(params storage.QueryParams) (*storage.PaginatedResult, error) {
	data := make([]*model.Asset, 0, len(m.assets))
	for _, a := range m.assets {
		data = append(data, a)
	}
	return &storage.PaginatedResult{
		Data:       data,
		Total:      int64(len(data)),
		Page:       1,
		PageSize:   20,
		TotalPages: 1,
	}, nil
}

func (m *MockAssetStorage) GetByID(id string) (*model.Asset, error) {
	if asset, ok := m.assets[id]; ok {
		return asset, nil
	}
	return nil, model.ErrNotFound
}

func (m *MockAssetStorage) Update(id string, asset *model.Asset) error {
	if _, ok := m.assets[id]; !ok {
		return model.ErrNotFound
	}
	m.assets[id] = asset
	return nil
}

func (m *MockAssetStorage) Delete(id string) error {
	if _, ok := m.assets[id]; !ok {
		return model.ErrNotFound
	}
	delete(m.assets, id)
	return nil
}

func (m *MockAssetStorage) Count(params storage.QueryParams) (int64, error) {
	return int64(len(m.assets)), nil
}

func TestAssetService_Create(t *testing.T) {
	// Setup mock storage
	mockStorage := NewMockAssetStorage()
	service := NewAssetService(mockStorage)

	// Test case: valid asset
	asset, err := service.CreateAsset("example.com", model.TypeDomain)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if asset == nil || asset.ID == "" {
		t.Fatalf("expected asset with ID")
	}
	if asset.Name != "example.com" {
		t.Errorf("expected name example.com, got %s", asset.Name)
	}

	// Test case: invalid asset (empty name)
	_, err = service.CreateAsset("", model.TypeDomain)
	if err == nil {
		t.Fatalf("expected error for empty name")
	}
}

func TestAssetService_GetAssetByID(t *testing.T) {
	mockStorage := NewMockAssetStorage()
	service := NewAssetService(mockStorage)

	created, _ := service.CreateAsset("127.0.0.1", model.TypeIP)

	// Valid fetch
	fetched, err := service.GetAssetByID(created.ID)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if fetched.ID != created.ID {
		t.Errorf("expected ID %s, got %s", created.ID, fetched.ID)
	}

	// Invalid fetch
	_, err = service.GetAssetByID("non-existent")
	if err == nil {
		t.Fatalf("expected error for non-existent ID")
	}
}

func TestAssetService_UpdateAsset(t *testing.T) {
	mockStorage := NewMockAssetStorage()
	service := NewAssetService(mockStorage)

	created, _ := service.CreateAsset("example.com", model.TypeDomain)

	updated, err := service.UpdateAsset(created.ID, "updated.com", "", "")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if updated.Name != "updated.com" {
		t.Errorf("expected updated name updated.com, got %s", updated.Name)
	}
}

func TestAssetService_DeleteAsset(t *testing.T) {
	mockStorage := NewMockAssetStorage()
	service := NewAssetService(mockStorage)

	created, _ := service.CreateAsset("example.com", model.TypeDomain)

	err := service.DeleteAsset(created.ID)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	_, err = service.GetAssetByID(created.ID)
	if err == nil {
		t.Fatalf("expected error catching deleted asset")
	}
}
