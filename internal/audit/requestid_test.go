package audit

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestWithRequestID_And_GetRequestID(t *testing.T) {
	t.Parallel()

	ctx := WithRequestID(t.Context(), "test-req-id")
	assert.Equal(t, "test-req-id", GetRequestID(ctx))
}

func TestGetRequestID_Empty(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "", GetRequestID(t.Context()))
}

func TestRequestIDMiddleware_GeneratesID(t *testing.T) {
	t.Parallel()

	var capturedID string
	handler := RequestIDMiddleware(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		capturedID = GetRequestID(r.Context())
	}))

	req := httptest.NewRequest(http.MethodPost, "/", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.NotEmpty(t, capturedID)
	assert.Equal(t, capturedID, rec.Header().Get(RequestIDHeader))
}

func TestRequestIDMiddleware_UsesExistingHeader(t *testing.T) {
	t.Parallel()

	var capturedID string
	handler := RequestIDMiddleware(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		capturedID = GetRequestID(r.Context())
	}))

	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.Header.Set(RequestIDHeader, "existing-id-123")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, "existing-id-123", capturedID)
	assert.Equal(t, "existing-id-123", rec.Header().Get(RequestIDHeader))
}
