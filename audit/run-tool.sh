#!/usr/bin/env bash
# Calls a single AgentAegis tool through the live MCP HTTP transport.
# Usage: ./run-tool.sh <tool_name> <args_json> [output_file]
#
# Authenticates with $AEGIS_API_KEY which must be exported.

set -euo pipefail

TOOL="${1:?tool name required}"
ARGS="${2:?args json required}"
OUT="${3:-/dev/stdout}"

API="${AEGIS_API:-https://agentaegis-mcp-production.up.railway.app}"
KEY="${AEGIS_API_KEY:?AEGIS_API_KEY env var required}"

# Initialize a session and capture the Mcp-Session-Id from response headers.
INIT_BODY='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"agentaegis-self-audit","version":"1"}}}'
HEADERS_FILE=$(mktemp)
INIT_RESP=$(curl -sS -X POST "$API/mcp" \
  -H "Authorization: Bearer $KEY" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -D "$HEADERS_FILE" \
  -d "$INIT_BODY")

SESSION_ID=$(grep -i '^mcp-session-id:' "$HEADERS_FILE" | head -1 | awk -F': ' '{print $2}' | tr -d '\r\n')
rm -f "$HEADERS_FILE"

if [ -z "$SESSION_ID" ]; then
  echo "Failed to initialize MCP session. Response: $INIT_RESP" >&2
  exit 1
fi

# Send initialized notification
curl -sS -X POST "$API/mcp" \
  -H "Authorization: Bearer $KEY" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -H "Mcp-Session-Id: $SESSION_ID" \
  -d '{"jsonrpc":"2.0","method":"notifications/initialized"}' > /dev/null

# Build call body via Node (always available) — no jq dependency
CALL_BODY=$(node -e "
const args = JSON.parse(process.argv[1]);
console.log(JSON.stringify({
  jsonrpc: '2.0',
  id: 2,
  method: 'tools/call',
  params: { name: process.argv[2], arguments: args }
}));
" "$ARGS" "$TOOL")

curl -sS -X POST "$API/mcp" \
  -H "Authorization: Bearer $KEY" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -H "Mcp-Session-Id: $SESSION_ID" \
  -d "$CALL_BODY" \
  -o "$OUT"

# Clean up session
curl -sS -X DELETE "$API/mcp" \
  -H "Authorization: Bearer $KEY" \
  -H "Mcp-Session-Id: $SESSION_ID" > /dev/null 2>&1 || true
