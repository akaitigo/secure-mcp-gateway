// Package jsonrpc provides JSON-RPC 2.0 request/response types and parsing utilities.
package jsonrpc

import (
	"encoding/json"
	"errors"
	"fmt"
)

// Standard JSON-RPC 2.0 error codes.
const (
	CodeParseError     = -32700
	CodeInvalidRequest = -32600
	CodeMethodNotFound = -32601
	CodeInvalidParams  = -32602
	CodeInternalError  = -32603
)

// Request represents a JSON-RPC 2.0 request.
type Request struct {
	Params  json.RawMessage `json:"params,omitempty"`
	JSONRPC string          `json:"jsonrpc"`
	Method  string          `json:"method"`
	ID      json.RawMessage `json:"id"`
}

// Response represents a JSON-RPC 2.0 response.
type Response struct {
	Error   *Error          `json:"error,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
}

// Error represents a JSON-RPC 2.0 error object.
type Error struct {
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
	Code    int             `json:"code"`
}

// Parse decodes raw bytes into a JSON-RPC 2.0 request.
// It validates the jsonrpc version field and method presence.
func Parse(data []byte) (*Request, error) {
	var req Request
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}

	if req.JSONRPC != "2.0" {
		return nil, errors.New("jsonrpc field must be \"2.0\"")
	}

	if req.Method == "" {
		return nil, errors.New("method field is required")
	}

	return &req, nil
}

// NewErrorResponse creates a JSON-RPC 2.0 error response.
func NewErrorResponse(id json.RawMessage, code int, message string) *Response {
	return &Response{
		JSONRPC: "2.0",
		ID:      id,
		Error: &Error{
			Code:    code,
			Message: message,
		},
	}
}

// Marshal serializes a JSON-RPC 2.0 response to JSON bytes.
func (r *Response) Marshal() ([]byte, error) {
	return json.Marshal(r)
}
