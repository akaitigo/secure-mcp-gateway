#!/usr/bin/env bash
# =============================================================================
# gRPC 契約テスト -- スモークテスト
#
# secure-mcp-gateway のgRPC APIが契約通りに動作することを検証する。
#
# 前提:
#   - grpcurl がインストール済み
#   - 対象サービスが起動済み
# =============================================================================

set -euo pipefail

SERVICE_HOST="${GRPC_HOST:-localhost}"
SERVICE_PORT="${GRPC_PORT:-9090}"
TARGET="${SERVICE_HOST}:${SERVICE_PORT}"

GRPCURL="grpcurl -plaintext"

PASS=0
FAIL=0

run_test() {
    local name="$1"
    shift
    echo -n "  CONTRACT: ${name} ... "
    if OUTPUT=$("$@" 2>&1); then
        echo "PASS"
        PASS=$((PASS + 1))
    else
        echo "FAIL"
        echo "    Output: ${OUTPUT}"
        FAIL=$((FAIL + 1))
    fi
}

echo "=== 契約テスト: スモーク ==="
echo "Target: ${TARGET}"
echo ""

echo "[サービスメソッド確認]"
run_test "GatewayService が公開されている" \
    bash -c "$GRPCURL ${TARGET} list | grep -q 'gateway.v1.GatewayService'"

run_test "Health メソッドが存在する" \
    bash -c "$GRPCURL ${TARGET} describe gateway.v1.GatewayService.Health"

run_test "ListAuditLogs メソッドが存在する" \
    bash -c "$GRPCURL ${TARGET} describe gateway.v1.GatewayService.ListAuditLogs"

echo ""
echo "[レスポンス構造確認]"

run_test "Health のレスポンスに status フィールドがある" \
    bash -c "$GRPCURL -d '{}' ${TARGET} gateway.v1.GatewayService/Health | jq -e '.status'"

run_test "ListAuditLogs のレスポンスに auditLogs 配列がある" \
    bash -c "$GRPCURL -d '{\"pageSize\": 10}' ${TARGET} gateway.v1.GatewayService/ListAuditLogs | jq -e '.auditLogs'"

echo ""
echo "=== 契約テスト結果 ==="
echo "  PASS: ${PASS}"
echo "  FAIL: ${FAIL}"
echo "  TOTAL: $((PASS + FAIL))"

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
