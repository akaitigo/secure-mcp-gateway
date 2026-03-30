# PRD: secure-mcp-gateway

**作成者**: Ryusei | **日付**: 2026-03-29 | **ステータス**: ドラフト
**アイデアID**: 1 | **ドメイン**: Security / AI Agent | **難易度**: High

## 問題定義

AI Agentが企業内の機密データ（PostgreSQL/Redis等）にアクセスする際、適切な認可制御が存在しない。MCP（Model Context Protocol）は2026年のAI Agent間通信の最重要プロトコルだが、公式ロードマップが「ゲートウェイパターン未定義」「認可伝播の標準なし」と明記しており、ツール呼び出し粒度でのきめ細かなアクセス制御は未解決の課題である。

既存のソリューション（Gravitee、Ory Oathkeeper、Stytch等）は汎用的な認証・認可の部品を提供するに留まり、MCP固有のセッション伝播・ツール粒度認可・監査ログを一体提供するプロキシは市場に存在しない。

## 目標と成功指標

| 目標 | 指標 | ターゲット |
|------|------|----------|
| MCPプロキシとして全ツール呼び出しを中継できる | ツール呼び出しの中継成功率 | 99.9% |
| OAuthトークンによるアクセス制御 | 不正トークンの拒否率 | 100% |
| ツール粒度の認可ポリシー適用 | ポリシー評価のレイテンシ | < 10ms (p99) |
| 全アクセスの監査ログ出力 | ログカバレッジ | 100% |
| OSS コミュニティでの認知獲得 | GitHub Stars | 50+ (3ヶ月) |

## スコープ外

- Web UI / ダッシュボード（SaaS版で提供予定）
- マルチテナント対応（v2以降）
- ReBAC/ABAC エンジンの自前実装（OPA/OpenFGA等の外部エンジンを利用）
- MCP以外のプロトコル（REST/GraphQL）のプロキシ
- 暗号化・鍵管理（既存のVault等を利用）

## ユーザーストーリー

- SRE/セキュリティエンジニアとして、AI Agentの全ツール呼び出しを監査ログで追跡したい。なぜなら、インシデント発生時に「いつ・誰が・何にアクセスしたか」を即座に特定する必要があるから。
- プラットフォームエンジニアとして、MCPサーバーの前段にゲートウェイを配置し、OAuthトークンでアクセス制御したい。なぜなら、各MCPサーバーに個別に認証ロジックを実装するのは非効率で一貫性を欠くから。
- セキュリティアーキテクトとして、ツール呼び出し単位で許可/拒否ポリシーを定義したい。なぜなら、「DBの読み取りは許可するが書き込みは禁止」といった細粒度の制御が必要だから。
- 開発者として、既存のMCPサーバーを修正せずにゲートウェイ経由でセキュアにできるようにしたい。なぜなら、セキュリティ対応のためにサービスコードを変更するコストを最小化したいから。

## 技術要件

### 技術スタック

- **Go** — プロキシ層、ORY Go SDK統合、高パフォーマンスな中継処理
- **TypeScript MCP SDK** — MCPプロトコル処理、サイドカーパターン
- **gRPC** — 内部サービス間通信
- **Protocol Buffers** — サービス定義、スキーマ管理
- **ORY Hydra** — OAuth2/OIDC認証基盤
- **OPA (Open Policy Agent)** — ポリシーエンジン（ツール粒度認可）

### アーキテクチャ

```
[AI Agent] → [secure-mcp-gateway (Go proxy)]
                    ├── OAuth token validation (ORY Hydra)
                    ├── Policy evaluation (OPA)
                    ├── Audit logging
                    └── [MCP Server (upstream)] → [Data Sources]
```

- **Go プロキシ**: MCP over HTTP/SSE のリクエストを受信し、トークン検証→ポリシー評価→上流転送→監査ログの一連の処理を実行
- **TypeScript サイドカー**: MCP SDK を使用してプロトコル準拠を保証。Go プロキシとgRPCで通信

### 非機能要件

- **パフォーマンス**: プロキシ追加レイテンシ < 5ms (p50), < 15ms (p99)
- **セキュリティ**: OAuth2/OIDC準拠、TLS必須、監査ログの改ざん防止
- **スケーラビリティ**: 1,000 req/s（単一インスタンス）

## 競合分析

| 競合 | URL | ギャップ |
|------|-----|---------|
| Gravitee + OpenFGA MCP Authorization | https://www.gravitee.io/blog/mcp-authorization-with-openfga-and-authzen | APIゲートウェイ+認可エンジンの組み合わせ。MCP専用設計ではなく汎用ゲートウェイに後付け。ツール呼び出し粒度の認可ポリシーは未提供 |
| Ory Oathkeeper + Hydra (MCP対応) | https://www.ory.com/blog/mcp-server-oauth-with-ory-hydra-authentication-ai-agent-integration-guide | OAuth2/OIDC認証は強力だがMCPゲートウェイとしてのプロキシ機能・セッション伝播・監査ログはスコープ外 |
| Stytch / WorkOS MCP Auth SDK | https://stytch.com/blog/MCP-authentication-and-authorization-guide/ | 認証プロバイダとしてのSDK提供。ゲートウェイ・プロキシ層の実装やReBAC/ABACによるツール粒度認可は含まない |

**差別化ポイント**: MCP 2026ロードマップが明示的に「ゲートウェイパターン未定義」「認可伝播の標準なし」と認めている。MCP + ReBAC + AI Agent固有の認可パターン（ツール呼び出し粒度の制御・セッション伝播・監査ログ）を一体提供するプロキシは市場に存在しない

## 技術リスク

| リスク | 発生可能性 | 影響 | 軽減策 |
|--------|----------|------|--------|
| MCP仕様の変更（プロトコル不安定） | 高 | 高 | MCP SDKを使用しプロトコル処理を抽象化。バージョンごとのアダプタパターン |
| 認証/認可プロトコルの仕様準拠とセキュリティ検証 | 中 | 高 | ORY Hydra（実績ある実装）を使用。独自実装を最小限に |
| Go ↔ TypeScript サイドカー間通信の複雑さ | 中 | 中 | gRPCで型安全な通信。統合テストでカバー |
| OPAポリシー設計の学習コスト | 低 | 中 | MVPでは単純なallow/denyポリシーに限定。Regoの複雑なパターンはv2 |
| 依存技術の成熟度（実験的段階） | 中 | 中 | MCP SDKの安定版を使用。不安定な機能はフィーチャーフラグで分離 |

## マイルストーン

### Phase 0: MVP（2週間）

1. **MCPプロキシの基本ルーティング実装** — MCP over HTTP/SSEリクエストの受信と上流MCPサーバーへの転送
2. **OAuthトークン検証ミドルウェア** — ORY Hydra連携によるBearerトークンの検証・拒否
3. **ツール呼び出しの許可/拒否ログ出力** — 構造化ログ（JSON）による全リクエストの監査記録

### Phase 1: ポリシーエンジン統合（2週間）

4. OPA統合によるツール粒度の認可ポリシー評価
5. ポリシー設定のYAML/JSON管理

### Phase 2: プロダクション品質（2週間）

6. gRPC Health Checking Protocol
7. メトリクス（Prometheus）
8. Dockerイメージ公開
9. ドキュメント・デモ

## マネタイズ

OSS (Community Edition) + SaaS (監査ログ・ダッシュボード・SSO統合)

## 未解決事項

- MCP over HTTP/SSE vs MCP over stdio — プロキシ対象のトランスポート層の決定 (ADR-001で決定予定)
- OPA vs OpenFGA — ポリシーエンジンの最終選定（MVPではOPAを採用し、v2でOpenFGAも検討）(ADR-002で決定予定)
- TypeScriptサイドカーのデプロイ方式 — 同一プロセス内埋め込み vs 別コンテナ
- 監査ログのストレージ — ファイル vs DB vs 外部サービス（MVPではファイル出力）
