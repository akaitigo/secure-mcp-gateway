#!/usr/bin/env bash
set -euo pipefail

input="$(cat)"
file="$(jq -r '.tool_input.file_path // .tool_input.path // empty' <<< "$input")"

case "$file" in *.go) ;; *) exit 0 ;; esac

cd "$(git rev-parse --show-toplevel 2>/dev/null || dirname "$file")"

# 0. ツール存在チェック（なければ自動インストール）
if ! command -v golangci-lint &>/dev/null; then
  go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest 2>/dev/null || { echo "WARN: golangci-lint install failed" >&2; exit 0; }
fi
if ! command -v gofumpt &>/dev/null; then
  go install mvdan.cc/gofumpt@latest 2>/dev/null || true
fi

# 1. 自動修正を先に（サイレント）
golangci-lint run --fix "$file" >/dev/null 2>&1 || true

# 2. 残った違反だけをJSON返却
diag="$(golangci-lint run "$file" 2>&1 | head -20)"
if [ -n "$diag" ]; then
  jq -Rn --arg msg "$diag" \
    '{ hookSpecificOutput: { hookEventName: "PostToolUse", additionalContext: $msg } }'
fi
