# 品質チェックリスト追加分 — gRPCサービス

> Layer-0（共通）+ Layer-1（言語別）のチェックリストに**追加**する項目のみ。

## gRPC固有の品質基準

### Proto定義
- [ ] `buf lint` がエラーゼロで通過する
- [ ] `buf breaking --against .git#branch=main` で後方互換性が保たれている
- [ ] `buf format -w` でフォーマットが統一されている
- [ ] 全 message / field / rpc にコメントが記述されている
- [ ] deprecated フィールドに `[deprecated = true]` と代替手段が記載されている
- [ ] フィールド番号の再利用がない（削除時は `reserved` で予約）

### gRPC設計
- [ ] 適切な gRPC Status Code を返している（`INVALID_ARGUMENT`, `NOT_FOUND`, `INTERNAL` 等）
- [ ] クライアント側で Deadline/タイムアウトが設定されている
- [ ] サーバー側で `Context.deadline` が伝播されている
- [ ] 大量データは Server Streaming で返している
- [ ] 認証トークンが `authorization` メタデータキーで伝播されている
- [ ] 相関IDが `x-request-id` で伝播されている

### 契約テスト
- [ ] 全 RPC メソッドの正常系テストが存在する
- [ ] エラー系テスト（INVALID_ARGUMENT, NOT_FOUND 等）が存在する
- [ ] Streaming RPC のテストが存在する（該当する場合）
- [ ] 契約テストが CI で実行される

### リフレクション・ヘルスチェック
- [ ] gRPC Health Checking Protocol が実装されている
- [ ] 開発環境でリフレクションが有効（grpcurl でのデバッグ用）
- [ ] 本番環境でリフレクションが無効

### メタデータ・インターセプタ
- [ ] メタデータ値のサニタイズが行われている
- [ ] ロギングインターセプタが設定されている
- [ ] メトリクスインターセプタが設定されている（Prometheus 等）
