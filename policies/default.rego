package gateway.authz

# Default policy: deny all tool calls unless explicitly allowed.
# This is the base policy for secure-mcp-gateway.
# Production deployments should extend this with specific allow rules.

default allow := false

# Allow health check tools for any authenticated client.
allow if {
	input.tool_name == "health"
}

# Allow tools/list for any authenticated client.
allow if {
	input.method == "tools/list"
}
