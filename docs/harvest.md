# Harvest: secure-mcp-gateway

## 使えたもの
- [x] Makefile (make check / make quality)
- [x] lint設定 (golangci-lint + gofumpt)
- [x] CI YAML
- [x] CLAUDE.md (69行 → Ship時に圧縮必要だった)
- [x] ADR テンプレート (2件: MCP transport, OPA policy)
- [x] 品質チェックリスト (make quality)
- [x] E2Eテスト (test/contract/smoke.sh)
- [x] Hooks（PostToolUse golangci-lint）
- [x] lefthook
- [x] startup.sh

## 使えなかったもの（理由付き）
- CLAUDE.md 50行制限: Launch時に69行で生成された。Ship時に手動削減が必要だった

## テンプレート改善提案

| 対象ファイル | 変更内容 | 根拠 |
|-------------|---------|------|
| .golangci.yml テンプレート | v2形式に更新 | 3 Go PJでv1/v2不一致発生 |
| idea-launch SKILL.md | CLAUDE.md生成後にwc -lチェック追加 | 5/5PJで50行超 |
| audit middleware | RequestID→Audit→Authの順序が正しい | Auth DENY時にAuditに到達しない問題を修正 |

## メトリクス

| 項目 | 値 |
|------|-----|
| Issue (closed/total) | 5/5 |
| PR merged | 5 |
| テスト数 | 93 |
| CI失敗数 | 0 |
| ADR数 | 2 |
| テンプレート実装率 | 95% |
| CLAUDE.md行数 | 69 (Ship前) |

## 次のPJへの申し送り
- ミドルウェアチェーンの順序はセキュリティ上重要。RequestID→Audit→Authが正しい順序
- golangci-lint v2 への移行はテンプレートレベルで対応すべき
