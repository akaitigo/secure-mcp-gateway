# アーキテクチャ概要

## 全体構成

```
[AI Agent] --MCP over HTTP/SSE--> [Go Proxy]
                                     |
                          +----------+----------+
                          |          |          |
                     [Token Verify] [Policy]  [Audit]
                     (ORY Hydra)    (OPA)     (Logger)
                          |
                   [Upstream MCP Server]
                          |
                   [Data Sources (PG/Redis)]
```

## 主要な設計判断

- ADR-001: (未作成) MCP トランスポート層の選定
- ADR-002: (未作成) ポリシーエンジンの選定（OPA vs OpenFGA）
- ADR-003: (未作成) Go + TypeScript サイドカー構成の理由

## 外部サービス連携

| サービス | 用途 | 通信方式 |
|----------|------|----------|
| ORY Hydra | OAuth2 トークン検証 | HTTP REST |
| OPA | ポリシー評価 | HTTP REST |
| 上流MCPサーバー | ツール呼び出し転送 | MCP over HTTP/SSE |

## セキュリティ考慮事項

- 全通信はTLS必須（本番環境）
- トークンはメモリ上でのみ保持、ログに出力しない
- 監査ログは改ざん検知のためハッシュチェーンを使用（v2）
