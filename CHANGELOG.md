# Changelog

## v1.1.0 (2026-07-19)

### Tool-level Authorization (Phase 2)

- feat: OPAによるツール粒度の認可ポリシー評価を実装（ADR-003のPhase 2対応）
  - `internal/policy`: OPAクライアント（`/v1/data/gateway/authz/allow`）とポリシー評価ミドルウェアを追加
  - ミドルウェアチェーンを RequestID → Audit → Auth → Policy → Proxy に拡張。ポリシー拒否は403で監査ログにDENY記録
  - fail-close: OPA到達不能・非200応答・decision未定義時はデフォルト拒否（fail-openにしない）
  - `OPA_URL` 環境変数を必須設定として再導入
- feat: `policies/default.rego` をクライアントID×ツール名の許可制御に整備、許可リストを `policies/data.json` に分離（`"*"` ワイルドカード対応）
- test: Regoポリシーのユニットテスト（`policies/default_test.rego`）と `make policy-test` を追加、CIに組込み
- docs: README / CLAUDE.md / ADR-003（Superseded）を実装済みの記述に更新

## v1.0.0 (2026-04-01)

### Initial Release

- chore: upgrade dependencies (#20)
- build(deps): bump actions/checkout from 4 to 6 (#14)
- harden: migrate golangci-lint v2 and fix security/lint warnings (#19)
- fix: forward query string to upstream in proxy and SSE handlers (#13) (#18)
- fix: use YAML literal block scalar for mock-mcp inline Python (#16) (#17)
- fix: remove unused OPA_URL config and respect token exp in cache TTL
- docs: harvest retrospective
- docs: add CHANGELOG.md for v1.0.0
- feat #5: integration tests, ADRs, and documentation (#12)
- feat #4: audit logging (rebased on main) (#11)
- feat #3: OAuth token verification middleware (rebased on main) (#8)
- feat #2: implement MCP proxy with JSON-RPC routing, SSE streaming, and input validation (#7)
- feat #1: CI/CD, test framework, and local dev environment (#6)
- Initial project scaffold from idea #1