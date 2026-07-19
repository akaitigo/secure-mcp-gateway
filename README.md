# secure-mcp-gateway

企業内MCPサーバーの手前でOAuth2認証・OPAによるツール粒度の認可・監査ログを提供するModel Context Protocol (MCP) ゲートウェイ。ポリシー評価はfail-close（OPA障害時はデフォルト拒否）で動作します。

## Features

- **MCP Proxy**: MCP over HTTP/SSE リクエストの透過的な中継
- **OAuth2 Token Validation**: ORY Hydra 連携による Bearer トークン検証
- **Tool-level Authorization**: OPA によるツール呼び出し粒度の認可ポリシー評価（fail-close: OPA到達不能時はデフォルト拒否）
- **Audit Logging**: 全アクセスの構造化ログ出力（ALLOW/DENY 両方を記録）

## Architecture

```
[AI Agent] → [secure-mcp-gateway] → [MCP Server] → [Data Sources]
                    ├── Token Validation (ORY Hydra)
                    ├── Policy Evaluation (OPA)
                    └── Audit Logging
```

## Tech Stack

- Go (proxy layer, ORY Go SDK)
- gRPC / Protocol Buffers (internal communication)
- ORY Hydra (OAuth2/OIDC)
- OPA (policy engine)

## Quick Start

### Prerequisites

- Go 1.24+
- Docker & Docker Compose
- (Optional) [golangci-lint](https://golangci-lint.run/), [gofumpt](https://github.com/mvdan/gofumpt)

### 1. Clone & Setup

```bash
git clone https://github.com/akaitigo/secure-mcp-gateway.git
cd secure-mcp-gateway
cp .env.example .env
```

### 2. Start Dependencies

Docker Compose starts ORY Hydra (OAuth2), OPA (policy engine), and a mock MCP server:

```bash
docker compose up -d

# Verify all services are healthy
docker compose ps
# Expected: hydra, opa, mock-mcp all "running"
```

| Service | Port | Purpose |
|---------|------|---------|
| ORY Hydra (Public) | `4444` | OAuth2 token endpoint |
| ORY Hydra (Admin) | `4445` | Token introspection |
| OPA | `8181` | Policy evaluation (tool-level authorization) |
| Mock MCP Server | `3001` | Upstream MCP (dev only) |

### 3. Build & Run

```bash
# Build
make build

# Run the gateway
./secure-mcp-gateway
# Proxy listens on :8080, gRPC on :9090
```

### 4. Create a Test Token & Send a Request

```bash
# Create an OAuth2 client in Hydra
docker compose exec hydra hydra create oauth2-client \
  --endpoint http://localhost:4445 \
  --grant-type client_credentials \
  --scope tools:read,tools:call \
  --format json

# Request a token (replace CLIENT_ID and CLIENT_SECRET from the output above)
TOKEN=$(curl -s -X POST http://localhost:4444/oauth2/token \
  -u "$CLIENT_ID:$CLIENT_SECRET" \
  -d grant_type=client_credentials \
  -d scope="tools:read tools:call" | jq -r .access_token)

# Call the gateway with the token
curl -s -X POST http://localhost:8080/ \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' | jq
```

### 5. Try Tool-level Authorization

ツール呼び出し（`tools/call`）はOPAポリシーで許可されたクライアント×ツールの組み合わせのみ通過します。許可リストは [`policies/data.json`](policies/data.json) で管理します:

```json
{
  "gateway": {
    "permissions": {
      "demo-agent": ["mock-tool"]
    }
  }
}
```

```bash
# 許可されたツール（data.jsonでclient_idに付与済み）→ 200 OK
curl -s -X POST http://localhost:8080/ \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"mock-tool"}}' | jq

# 許可されていないツール → 403 Forbidden ("denied by policy")
curl -s -X POST http://localhost:8080/ \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"secret-tool"}}' | jq
```

ポリシーの変更は `policies/` のRego/JSONを編集してOPAを再起動（`docker compose restart opa`）するだけで反映され、ゲートウェイの再デプロイは不要です。

### 6. Run Tests

```bash
# Unit + integration tests with race detector
make test

# Rego policy unit tests (Docker)
make policy-test

# Full check (format -> tidy -> lint -> test -> build)
make check
```

## Policy Configuration

- [`policies/default.rego`](policies/default.rego) — 認可ルール本体。デフォルト拒否で、`initialize` / `tools/list` などのディスカバリ系メソッドは認証済みクライアントに許可、`tools/call` は `data.json` の許可リストに一致した場合のみ許可
- [`policies/data.json`](policies/data.json) — クライアントID→許可ツール名のマッピング。`"*"` で全ツール許可
- [`policies/default_test.rego`](policies/default_test.rego) — ポリシーのユニットテスト（`make policy-test`）

**Fail-close**: OPAが停止・到達不能・ポリシー未ロードの場合、ゲートウェイは全リクエストを `403 Forbidden` で拒否します。セキュリティゲートウェイとしてfail-openにはなりません。

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `HYDRA_ADMIN_URL` | Yes | - | ORY Hydra Admin API URL |
| `OPA_URL` | Yes | - | OPA server base URL for policy evaluation |
| `UPSTREAM_MCP_URL` | Yes | - | Upstream MCP server URL |
| `PROXY_LISTEN_ADDR` | No | `:8080` | HTTP proxy listen address |
| `AUDIT_LOG_PATH` | No | `stdout` | Audit log output path (file path or `stdout`) |
| `GRPC_LISTEN_ADDR` | No | `:9090` | gRPC management API listen address |

> **NOTE**: Authentication, authorization, and audit logging must be properly configured before production use.

## Architecture Decision Records

Key design decisions are documented in [`docs/adr/`](docs/adr/):

- [ADR-001: MCP Transport Layer](docs/adr/0001-mcp-transport-layer.md) — HTTP/SSE を採用した理由
- [ADR-002: Policy Engine](docs/adr/0002-policy-engine-opa.md) — OPA を採用した理由
- [ADR-003: MVP OPA Deferred](docs/adr/0003-mvp-opa-deferred.md) — MVPではOPAポリシー評価を未実装とした決定（Superseded: Phase 2で実装済み）

## Development

```bash
# Install tools
bash .claude/startup.sh

# Lint
make lint

# Format
make format

# Quality gate (before ship)
make quality
```

## License

MIT
