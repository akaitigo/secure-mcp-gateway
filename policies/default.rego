# Tool-level authorization policy for secure-mcp-gateway.
#
# The gateway queries POST /v1/data/gateway/authz/allow for every JSON-RPC
# request with the following input document:
#
#   input.client_id  - authenticated OAuth2 client ID
#   input.scopes     - granted OAuth2 scopes (optional)
#   input.method     - JSON-RPC method (e.g. "tools/call")
#   input.tool_name  - tool name for "tools/call" requests
#
# Client-to-tool grants live in the data document (policies/data.json):
#
#   data.gateway.permissions[client_id] = ["tool-a", "tool-b"]  # or ["*"]
#
# The gateway fails closed: if this decision is undefined or OPA is
# unreachable, the request is denied.
package gateway.authz

# Fail-safe default: deny everything not explicitly allowed.
default allow := false

# Protocol handshake and discovery methods allowed for any authenticated
# client. Tool invocations are NOT in this set and require explicit grants.
allowed_methods := {
	"initialize",
	"notifications/initialized",
	"ping",
	"tools/list",
}

allow if input.method in allowed_methods

# Tool invocations: the client must be granted the specific tool name...
allow if {
	input.method == "tools/call"
	some tool in data.gateway.permissions[input.client_id]
	tool == input.tool_name
}

# ...or the "*" wildcard, which grants every tool.
allow if {
	input.method == "tools/call"
	some tool in data.gateway.permissions[input.client_id]
	tool == "*"
}
