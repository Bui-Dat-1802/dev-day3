package handler

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"mini-asm/internal/model"
)

func TestStartScanHandler_BadRequest(t *testing.T) {
	mock := &MockScanService{}
	h := NewScanHandler(mock)

	// invalid JSON body
	req := httptest.NewRequest(http.MethodPost, "/assets/a1/scan", bytes.NewReader([]byte("{bad json")))
	req.Header.Set("X-Path-id", "a1")
	w := httptest.NewRecorder()

	h.StartScan(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 Bad Request, got %d: %s", w.Code, w.Body.String())
	}
}

func TestGetScanJobHandler_NotFound(t *testing.T) {
	mock := &MockScanService{
		GetJobFunc: func(jobID string) (*model.ScanJob, error) { return nil, model.ErrNotFound },
	}
	h := NewScanHandler(mock)

	req := httptest.NewRequest(http.MethodGet, "/scan-jobs/missing", nil)
	req.Header.Set("X-Path-id", "missing")
	w := httptest.NewRecorder()

	h.GetScanJob(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404 Not Found, got %d: %s", w.Code, w.Body.String())
	}
}
