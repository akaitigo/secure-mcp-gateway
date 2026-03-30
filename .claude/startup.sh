#!/usr/bin/env bash
# =============================================================================
# セッション起動ルーチン
#
# セッション開始時に実行し、ツールの自動インストールとヘルスチェックを行う。
# 状態管理は git log + GitHub Issues で行う。
#
# オプション:
#   --dev    開発サーバーも起動する（Web App/API 向け）
#   --skip-checks  ヘルスチェックをスキップ（デバッグ用）
# =============================================================================
set -euo pipefail

START_DEV=false
SKIP_CHECKS=false

for arg in "$@"; do
  case "$arg" in
    --dev) START_DEV=true ;;
    --skip-checks) SKIP_CHECKS=true ;;
  esac
done

echo "=== Session Startup ==="

# 1. 作業ディレクトリ確認
[ -d ".git" ] || { echo "ERROR: Not in git repository"; exit 1; }

# 1.5. 言語検出と必須ツールの自動インストール
echo "=== Tool auto-install ==="
if [ -f "go.mod" ]; then
  echo "Detected: Go"
  command -v golangci-lint &>/dev/null || { echo "Installing golangci-lint..."; go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest 2>/dev/null || echo "WARN: golangci-lint install failed"; }
  command -v gofumpt &>/dev/null || { echo "Installing gofumpt..."; go install mvdan.cc/gofumpt@latest 2>/dev/null || echo "WARN: gofumpt install failed"; }
fi
if [ -f "pyproject.toml" ]; then
  echo "Detected: Python"
  command -v ruff &>/dev/null || { echo "Installing ruff..."; pip install ruff 2>/dev/null || echo "WARN: ruff install failed"; }
fi
if [ -f "package.json" ]; then
  echo "Detected: TypeScript/JavaScript"
  command -v oxlint &>/dev/null || { echo "Installing oxlint..."; npm install -g oxlint 2>/dev/null || echo "WARN: oxlint install failed"; }
  npx biome --version &>/dev/null 2>&1 || { echo "Installing biome..."; npm install -g @biomejs/biome 2>/dev/null || echo "WARN: biome install failed"; }
fi
if [ -f "build.gradle.kts" ] || [ -f "build.gradle" ]; then
  echo "Detected: Kotlin/JVM"
  if [ -f "gradlew" ]; then
    chmod +x gradlew
    echo "Gradle wrapper found. Running detekt check..."
    ./gradlew detekt --dry-run 2>/dev/null && echo "detekt configured." || echo "WARN: detekt not configured in build.gradle.kts"
  else
    echo "WARN: gradlew not found. Run 'gradle wrapper' to generate."
  fi
fi
if [ -f "Cargo.toml" ]; then
  echo "Detected: Rust"
  rustup component add clippy rustfmt 2>/dev/null || echo "WARN: rustup component install failed"
  command -v wasm-pack &>/dev/null || { echo "Installing wasm-pack..."; cargo install wasm-pack 2>/dev/null || echo "WARN: wasm-pack install failed"; }
fi
# lefthook（全言語共通: git hooks 管理）
command -v lefthook &>/dev/null || { echo "Installing lefthook..."; go install github.com/evilmartians/lefthook@latest 2>/dev/null || npm install -g lefthook 2>/dev/null || echo "WARN: lefthook install failed"; }
# lefthook install: git hooks を有効化（インストールだけでは動かない）
if command -v lefthook &>/dev/null && [ -f "lefthook.yml" ]; then
  lefthook install 2>/dev/null && echo "lefthook hooks installed." || echo "WARN: lefthook install failed"
fi
echo "Tool check complete."

# 2. Gitログ読取（記述的コミットメッセージがセッション間ブリッジとして機能）
echo "=== Recent commits ==="
git log --oneline -10

# 3. ヘルスチェック
if [ "$SKIP_CHECKS" = true ]; then
  echo "=== Health check SKIPPED (--skip-checks) ==="
else
  echo "=== Health check ==="
  if make check 2>&1 | tail -10; then
    echo "All checks passed. Ready to work."
  else
    echo "WARN: Checks failed. Review issues before proceeding."
  fi
fi

# 4. 開発サーバー起動（オプション）
if [ "$START_DEV" = true ]; then
  echo "=== Starting dev server ==="
  if [ -f "package.json" ]; then
    npm run dev &
    echo "Dev server started (npm run dev)"
  elif [ -f "Makefile" ] && grep -q "run-dev" Makefile; then
    make run-dev &
    echo "Dev server started (make run-dev)"
  else
    echo "WARN: No dev server configuration found"
  fi
fi

echo ""
echo "=== Session started at $(date -u +"%Y-%m-%dT%H:%M:%SZ") ==="
echo "Ready to work. State management: git log + GitHub Issues."
