package handler

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"mini-asm/internal/model"
	"mini-asm/internal/storage"
)

// MockAssetService minimal implementation for handler tests
type MockAssetService struct{}

func (m *MockAssetService) CreateAsset(name, assetType string) (*model.Asset, error) {
	return &model.Asset{ID: "a1", Name: name, Type: assetType, Status: model.StatusActive}, nil
}
func (m *MockAssetService) ListAssets(params storage.QueryParams) (*storage.PaginatedResult, error) {
	return &storage.PaginatedResult{Data: []*model.Asset{{ID: "a1"}}, Total: 1}, nil
}
func (m *MockAssetService) GetAssetByID(id string) (*model.Asset, error) {
	return &model.Asset{ID: id, Name: "x", Type: model.TypeDomain}, nil
}
func (m *MockAssetService) UpdateAsset(id, name, assetType, status string) (*model.Asset, error) {
	return &model.Asset{ID: id, Name: name, Type: assetType, Status: status}, nil
}
func (m *MockAssetService) DeleteAsset(id string) error { return nil }

// Ensure MockAssetService satisfies the interface used by handler (we keep it minimal)

func TestCreateAssetHandler(t *testing.T) {
	svc := &MockAssetService{}
	h := NewAssetHandler(svc)

	body := map[string]string{"name": "example.com", "type": string(model.TypeDomain)}
	b, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/assets", bytes.NewReader(b))
	w := httptest.NewRecorder()

	h.CreateAsset(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201 Created, got %d: %s", w.Code, w.Body.String())
	}
}

func TestGetAssetHandler(t *testing.T) {
	svc := &MockAssetService{}
	h := NewAssetHandler(svc)

	req := httptest.NewRequest(http.MethodGet, "/assets/a1", nil)

	w := httptest.NewRecorder()
	h.GetAsset(w, req)

	if w.Code != http.StatusOK && w.Code != http.StatusBadRequest {
		t.Fatalf("unexpected status code: %d", w.Code)
	}
}

func TestListAssetsHandler(t *testing.T) {
	svc := &MockAssetService{}
	h := NewAssetHandler(svc)

	req := httptest.NewRequest(http.MethodGet, "/assets?page=1&page_size=10", nil)

	w := httptest.NewRecorder()
	h.ListAssets(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("unexpected status code: %d", w.Code)
	}
}

func TestUpdateAssetHandler(t *testing.T) {
	svc := &MockAssetService{}
	h := NewAssetHandler(svc)

	body := map[string]string{"name": "updated.com", "type": string(model.TypeDomain)}
	b, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPut, "/assets/a1", bytes.NewReader(b))
	w := httptest.NewRecorder()

	h.UpdateAsset(w, req)

	if w.Code != http.StatusOK && w.Code != http.StatusBadRequest {
		t.Fatalf("unexpected status code: %d", w.Code)
	}
}

func TestDeleteAssetHandler(t *testing.T) {
	svc := &MockAssetService{}
	h := NewAssetHandler(svc)

	req := httptest.NewRequest(http.MethodDelete, "/assets/a1", nil)
	w := httptest.NewRecorder()

	h.DeleteAsset(w, req)

	if w.Code != http.StatusNoContent && w.Code != http.StatusBadRequest {
		t.Fatalf("unexpected status code: %d", w.Code)
	}
}

