# secure-mcp-gateway

## 概要

企業内MCPサーバーの手前でOAuth2認証・OPAによるツール粒度の認可・監査ログを提供するModel Context Protocol (MCP) ゲートウェイ。ReBACは将来必要になった場合に再検討する。

## セキュリティ方針

- **ポリシー評価はfail-close**: OPA到達不能・ポリシー未ロード時は403でデフォルト拒否。fail-openにしない
- ポリシーは `policies/default.rego` + `policies/data.json`（クライアントID×ツール名の許可リスト）。経緯は [ADR-003](docs/adr/0003-mvp-opa-deferred.md)（Superseded）を参照

## 技術スタック

- Go — プロキシ層、ORY Go SDK統合
- TypeScript MCP SDK — MCPプロトコル処理（サイドカー）
- gRPC / Protocol Buffers — 内部サービス間通信
- ORY Hydra — OAuth2/OIDC認証基盤
- OPA (Open Policy Agent) — ポリシーエンジン（ツール粒度認可）

## コーディングルール

- Go: 標準の Go スタイルガイドに従うこと。golangci-lint + gofumpt を使用
- Proto/gRPC: `~/.claude/rules/proto.md` のルールに従うこと（フィールド番号再利用禁止・削除時は `reserved`。編集後に `buf lint` / `buf breaking` / `buf format -w`）

## ビルド & テスト

```bash
make check        # 全チェック（format → tidy → lint → test → build）
make test         # Goテスト（race detector 有効）
make policy-test  # Regoポリシーテスト（Docker）
make quality      # 品質チェック（Ship前）
```

## ディレクトリ構造

```
cmd/secure-mcp-gateway/   -- エントリポイント
internal/                  -- 内部パッケージ（プロキシ、認証、ポリシー、監査ログ）
policies/                  -- OPA Regoポリシー + 許可リスト（data.json）
proto/gateway/v1/          -- gRPC / Proto定義
docs/                      -- ドキュメント（ADR、品質チェックリスト）
```

## 環境変数

必須: `HYDRA_ADMIN_URL` / `OPA_URL` / `UPSTREAM_MCP_URL`。任意（デフォルトあり）: `PROXY_LISTEN_ADDR` / `AUDIT_LOG_PATH` / `GRPC_LISTEN_ADDR`。詳細は [README](README.md#environment-variables) と `.env.example` を参照。
