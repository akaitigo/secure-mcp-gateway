// Package policy provides OPA-based authorization for MCP tool invocations.
// It evaluates tool-level allow/deny decisions against an external OPA server
// and fails closed (deny) when the policy engine is unreachable or returns an
// unexpected response.
package policy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// decisionPath is the OPA Data API path of the boolean allow decision.
// It corresponds to the `allow` rule in the `gateway.authz` Rego package
// (see policies/default.rego).
const decisionPath = "/v1/data/gateway/authz/allow"

// ErrDecisionUndefined is returned when OPA responds without a result,
// which means the decision document does not exist (e.g., the policy
// bundle is not loaded). Callers must treat this as a deny (fail-close).
var ErrDecisionUndefined = errors.New("policy decision undefined (is the policy loaded?)")

// Input is the document sent to OPA for policy evaluation.
type Input struct {
	// ClientID is the authenticated OAuth2 client identifier.
	ClientID string `json:"client_id"`
	// Method is the JSON-RPC method being invoked (e.g., "tools/call").
	Method string `json:"method"`
	// ToolName is the MCP tool name for "tools/call" requests.
	ToolName string `json:"tool_name,omitempty"`
	// Scopes is the list of OAuth2 scopes granted to the client.
	Scopes []string `json:"scopes,omitempty"`
}

// Evaluator defines the interface for policy evaluation.
// This allows mocking in tests.
type Evaluator interface {
	Evaluate(ctx context.Context, input *Input) (bool, error)
}

// Client evaluates authorization policies against an OPA server
// via the OPA REST Data API.
type Client struct {
	httpClient  *http.Client
	decisionURL string
}

// NewClient creates a new OPA policy client for the given OPA base URL
// (e.g., "http://localhost:8181").
func NewClient(opaURL string, httpClient *http.Client) (*Client, error) {
	if opaURL == "" {
		return nil, errors.New("OPA URL is required")
	}

	if _, err := url.ParseRequestURI(opaURL); err != nil {
		return nil, fmt.Errorf("invalid OPA URL: %w", err)
	}

	if httpClient == nil {
		httpClient = &http.Client{
			Timeout: 5 * time.Second,
		}
	}

	return &Client{
		decisionURL: strings.TrimRight(opaURL, "/") + decisionPath,
		httpClient:  httpClient,
	}, nil
}

// Evaluate queries OPA for an allow/deny decision on the given input.
// It returns an error when OPA is unreachable, responds with a non-200
// status, or the decision document is undefined. Callers must treat any
// error as a deny (fail-close).
func (c *Client) Evaluate(ctx context.Context, input *Input) (bool, error) {
	payload := struct {
		Input *Input `json:"input"`
	}{Input: input}

	body, err := json.Marshal(payload)
	if err != nil {
		return false, fmt.Errorf("failed to marshal policy input: %w", err)
	}

	// decisionURL is derived from the trusted OPA_URL server configuration, not user input.
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.decisionURL, bytes.NewReader(body)) //nolint:gosec // trusted config
	if err != nil {
		return false, fmt.Errorf("failed to create policy request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req) //nolint:gosec // trusted config (see above)
	if err != nil {
		return false, fmt.Errorf("policy evaluation request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("policy endpoint returned status %d", resp.StatusCode)
	}

	var result struct {
		Result *bool `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return false, fmt.Errorf("failed to decode policy response: %w", err)
	}

	if result.Result == nil {
		return false, ErrDecisionUndefined
	}

	return *result.Result, nil
}
