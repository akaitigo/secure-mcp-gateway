# secure-mcp-gateway

> **WARNING: This project is under active development. Not ready for production use.**

企業内の機密データ（PostgreSQL/Redis）にAI Agentが安全にアクセスするための、ポリシー制御機能付きModel Context Protocol (MCP) ゲートウェイ。

## Features

- **MCP Proxy**: MCP over HTTP/SSE リクエストの透過的な中継
- **OAuth2 Token Validation**: ORY Hydra 連携による Bearer トークン検証
- **Tool-level Authorization**: OPA によるツール呼び出し粒度の認可ポリシー
- **Audit Logging**: 全アクセスの構造化ログ出力

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

```bash
# Clone
git clone https://github.com/akaitigo/secure-mcp-gateway.git
cd secure-mcp-gateway

# Set up environment variables
cp .env.example .env

# Start local development dependencies (ORY Hydra + OPA + mock MCP server)
docker compose up -d

# Build
make build

# Run tests
make test

# Full check (format → tidy → lint → test → build)
make check
```

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `HYDRA_ADMIN_URL` | Yes | ORY Hydra Admin API URL |
| `HYDRA_PUBLIC_URL` | Yes | ORY Hydra Public API URL |
| `OPA_URL` | Yes | OPA server URL |
| `UPSTREAM_MCP_URL` | Yes | Upstream MCP server URL |
| `PROXY_LISTEN_ADDR` | No | Listen address (default: `:8080`) |
| `AUDIT_LOG_PATH` | No | Audit log output path (default: `stdout`) |

> **NOTE**: Authentication, authorization, and audit logging must be properly configured before production use.

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
