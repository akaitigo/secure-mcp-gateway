# Unit tests for the gateway.authz policy.
# Run with: make policy-test
package gateway.authz_test

import data.gateway.authz

test_default_deny_unknown_method if {
	not authz.allow with input as {"client_id": "any-client", "method": "resources/read"}
}

test_empty_method_denied if {
	not authz.allow with input as {"client_id": "any-client", "method": ""}
}

test_tools_list_allowed if {
	authz.allow with input as {"client_id": "any-client", "method": "tools/list"}
}

test_initialize_allowed if {
	authz.allow with input as {"client_id": "any-client", "method": "initialize"}
}

test_ping_allowed if {
	authz.allow with input as {"client_id": "any-client", "method": "ping"}
}

test_tool_call_allowed_for_granted_client if {
	authz.allow with input as {
		"client_id": "demo-agent",
		"method": "tools/call",
		"tool_name": "mock-tool",
	}
		with data.gateway.permissions as {"demo-agent": ["mock-tool"]}
}

test_tool_call_denied_for_ungranted_tool if {
	not authz.allow with input as {
		"client_id": "demo-agent",
		"method": "tools/call",
		"tool_name": "secret-tool",
	}
		with data.gateway.permissions as {"demo-agent": ["mock-tool"]}
}

test_tool_call_denied_for_unknown_client if {
	not authz.allow with input as {
		"client_id": "stranger",
		"method": "tools/call",
		"tool_name": "mock-tool",
	}
		with data.gateway.permissions as {"demo-agent": ["mock-tool"]}
}

test_tool_call_denied_without_tool_name if {
	not authz.allow with input as {
		"client_id": "demo-agent",
		"method": "tools/call",
	}
		with data.gateway.permissions as {"demo-agent": ["mock-tool"]}
}

test_wildcard_allows_any_tool if {
	authz.allow with input as {
		"client_id": "admin-agent",
		"method": "tools/call",
		"tool_name": "anything-at-all",
	}
		with data.gateway.permissions as {"admin-agent": ["*"]}
}

test_wildcard_scoped_to_client if {
	not authz.allow with input as {
		"client_id": "other-agent",
		"method": "tools/call",
		"tool_name": "anything-at-all",
	}
		with data.gateway.permissions as {"admin-agent": ["*"]}
}
