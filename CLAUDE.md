# secure-mcp-gateway

## 概要

企業内の機密データ（PostgreSQL/Redis）にAI Agentが安全にアクセスするための、ポリシー制御機能付きModel Context Protocol (MCP) サーバー。MCP + ReBAC + 監査ログを一体提供するプロキシゲートウェイ。

## 重要: MVP制限事項

- **ポリシー評価は未実装**: OPAによるツール粒度の認可はPhase 2で対応予定。認証済みユーザーは全ツールにアクセス可能。詳細は [ADR-003](docs/adr/0003-mvp-opa-deferred.md) を参照。

## 技術スタック

- Go — プロキシ層、ORY Go SDK統合
- TypeScript MCP SDK — MCPプロトコル処理（サイドカー）
- gRPC / Protocol Buffers — 内部サービス間通信
- ORY Hydra — OAuth2/OIDC認証基盤
- OPA (Open Policy Agent) — ポリシーエンジン（Phase 2で統合予定）

## コーディングルール

- Go: 標準の Go スタイルガイドに従うこと。golangci-lint + gofumpt を使用
- Proto/gRPC: `~/.claude/rules/proto.md` のルールに従うこと
  - フィールド番号の再利用禁止。削除時は `reserved` で予約
  - `buf lint` / `buf breaking` / `buf format -w` を編集後に実行

## ビルド & テスト

```bash
# 全チェック（lint → test → build）
make check

# 個別実行
make build        # Go バイナリビルド
make test         # テスト実行（race detector 有効）
make lint         # golangci-lint
make format       # gofumpt + goimports

# 品質チェック（Ship前）
make quality
```

## ディレクトリ構造

```
cmd/secure-mcp-gateway/   -- エントリポイント
internal/                  -- 内部パッケージ（プロキシ、認可、監査ログ）
pkg/                       -- 外部公開パッケージ
proto/gateway/v1/          -- gRPC / Proto定義
test/contract/             -- 契約テスト
docs/                      -- ドキュメント（ADR、品質チェックリスト）
.github/                   -- CI/CD、Issue/PRテンプレート
```

## 環境変数

```bash
# ORY Hydra
HYDRA_ADMIN_URL=          # ORY Hydra Admin API URL（必須）
HYDRA_PUBLIC_URL=         # ORY Hydra Public API URL（必須）

# プロキシ
UPSTREAM_MCP_URL=         # 上流MCPサーバーURL（必須）
PROXY_LISTEN_ADDR=        # リッスンアドレス（デフォルト: :8080）

# 監査ログ
AUDIT_LOG_PATH=           # 監査ログ出力先（デフォルト: stdout）

# gRPC
GRPC_LISTEN_ADDR=         # gRPCリッスンアドレス（デフォルト: :9090）
```
