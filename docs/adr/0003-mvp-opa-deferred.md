# ADR-003: MVPではOPAポリシー評価を未実装とする

## ステータス
Superseded（2026-07-19: Phase 2でOPAポリシー評価を実装済み）

本ADRの決定は役割を終えた。`OPA_URL` 設定と `internal/policy` ミドルウェア（fail-close）が導入され、認証済みクライアントであってもポリシーで許可されていないツールは呼び出せない。

## コンテキスト
ADR-002でOPAをポリシーエンジンとして採用する決定を行ったが、MVP時点では以下の状況にある:

- `OPA_URL` を設定として読み込んでいたが、実際のポリシー評価ミドルウェアは未実装
- 有効なBearerトークンを持つクライアントが全upstream toolを呼び出し可能な状態
- 未使用の設定項目がコードベースに残り、利用者に誤解を与えるリスクがあった

## 決定
MVP（Phase 1）ではOPAポリシー評価を実装せず、Phase 2で対応する。

具体的な対応:
1. `config.go` から `OPA_URL` フィールドと読み込みを削除
2. `CLAUDE.md` / `README.md` に「認証済みユーザーは全ツールにアクセス可能」の警告を明記
3. Phase 2でOPAミドルウェアを実装する際に `OPA_URL` を再導入する

## 根拠
- 未使用コードを残すと「ポリシー制御が有効」という誤った安心感を与える
- MVPの目的はMCPプロキシ + OAuth2認証 + 監査ログの基本フローの検証であり、ツール粒度の認可はスコープ外
- 削除することでコードと設定の一貫性が保たれる

## 結果
- 認証済みクライアントは全MCPツールにアクセス可能（MVP制限事項）
- Phase 2で `OPA_URL` 設定とポリシー評価ミドルウェアを追加する
- Phase 2着手時は本ADRのステータスを「Phase 2で置換」に更新する

## 追記（2026-07-19: Phase 2実装完了）
Phase 2の実装が完了し、本ADRはSupersededとなった:
1. `config.go` に `OPA_URL`（必須）を再導入
2. `internal/policy` パッケージでOPAクライアントとポリシー評価ミドルウェアを実装（ミドルウェア順: RequestID → Audit → Auth → Policy → Proxy）
3. OPA到達不能・ポリシー未ロード時はfail-close（403でデフォルト拒否）。fail-openにはしない
4. `policies/default.rego` + `policies/data.json` でクライアント×ツール名のallow/deny制御（PRDの「MVPでは単純なallow/denyポリシーに限定」の方針を踏襲）
