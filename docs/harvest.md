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

## レビューループ履歴 (2026-04-04)

### Stage 1: CI修正 (PR #23)
- **問題**: golangci-lint v2.1.6 が Go 1.25.0 に非対応でCIが3回以上失敗
- **修正**: golangci-lint を v2.11.4 に更新、actions/checkout v6→v4、actions/setup-go v6→v5
- **結果**: CI グリーン回復

### R1-R2: 信頼性・セキュリティ (PR #24)
| 重要度 | 問題 | 修正内容 |
|--------|------|---------|
| CRITICAL | gRPCサーバーがエラー起動時にGracefulStopされない | startupErrを保存してGracefulStopを常に呼ぶよう修正 |
| HIGH | 監査ログファイルのfd漏れ | closer io.Closer フィールドと Close() メソッドを追加 |
| HIGH | X-Audit-Client-Id ヘッダーが upstream に漏洩 | copyHeaders の excluded マップに追加 |
| STYLE | interface{} -> any | Go 1.18+ 推奨型を統一 |

### R3-R5: SSE・ミドルウェア堅牢性 (PR #25)
| 重要度 | 問題 | 修正内容 |
|--------|------|---------|
| HIGH | SSE応答ヘッダーが upstream から引き継がれない | handleSSE で copyHeaders を WriteHeader 前に実行 |
| MEDIUM | statusRecorder.Write() が未オーバーライドで暗黙的WriteHeader時に audit header を取得できない | Write() オーバーライドを追加、ゼロ値初期化に変更 |
| MEDIUM | 実質ゼロステータスが ALLOW と誤判定される可能性 | effectiveStatus ロジックでゼロを200として扱う |
| PERF | strings.NewReader(string(body)) の不要なコピー | bytes.NewReader(body) に変更 |

### R4+R5: 統合検証・堅牢性 (PR #26)
| 重要度 | 問題 | 修正内容 |
|--------|------|---------|
| MEDIUM | extractToolName が io.ReadAll エラー時にbodyを復元しない | エラー時もpartial bodyを r.Body に復元してから返す |

### 終了判定
- CRITICAL = 0, HIGH = 0, MEDIUM = 0
- make check 全パス (golangci-lint 0 issues, go test -race ./... 全パス)
- シークレット漏洩ゼロ確認 (Authorization header の upstream 非転送を単体テストで保証)
- 前ラウンドの修正で新たな問題なし

## メトリクス

| 項目 | 値 |
|------|-----|
| Issue (closed/total) | 7/7 |
| PR merged | 21 |
| レビューループPR | 4 (PR #23-#26) |
| テスト数 | ~100 (新規テスト追加含む) |
| CI失敗数 (ループ前) | 3+ (Go 1.25 golangci-lint非対応) |
| CI失敗数 (ループ後) | 0 |
| ADR数 | 3 |
| golangci-lint issues | 0 |

## 次のPJへの申し送り
- ミドルウェアチェーンの順序はセキュリティ上重要。RequestID→Audit→Authが正しい順序
- golangci-lint v2 への移行はテンプレートレベルで対応すべき
- io.ReadAll のエラーパスでは常に読み取り済みデータを復元すること。特に MaxBytesReader と組み合わせる場合
- Go 1.25 では golangci-lint v2.11.4 以上が必要。go.mod の Go バージョン更新時は lint ツールのバージョンも確認する
- gRPC サーバーはエラー起動時にも GracefulStop() を呼ぶこと（select の両ブランチで）
- SSE プロキシは upstream ヘッダーを WriteHeader 前に copyHeaders でコピーしてからSSE専用ヘッダーで上書きする順序が重要
