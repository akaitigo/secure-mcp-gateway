package audit

import (
	"context"
	"net/http"
)

// requestIDKey is the context key for the request ID.
type requestIDKey struct{}

// RequestIDHeader is the HTTP header name for request correlation IDs.
const RequestIDHeader = "X-Request-Id"

// WithRequestID stores a request ID in the context.
func WithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, requestIDKey{}, id)
}

// GetRequestID retrieves the request ID from the context.
// Returns an empty string if not present.
func GetRequestID(ctx context.Context) string {
	id, ok := ctx.Value(requestIDKey{}).(string)
	if !ok {
		return ""
	}
	return id
}

// RequestIDMiddleware extracts or generates a request ID and stores it in the context.
// If the X-Request-Id header is present, it is used; otherwise a new UUID is generated.
// The request ID is always set on the response as well.
func RequestIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestID := r.Header.Get(RequestIDHeader)
		if requestID == "" {
			requestID = generateID()
		}

		w.Header().Set(RequestIDHeader, requestID)
		ctx := WithRequestID(r.Context(), requestID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
