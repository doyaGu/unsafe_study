#!/bin/bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
AUDIT_MANIFEST="$PROJECT_ROOT/unsafe-audit/Cargo.toml"
STUDY_MANIFEST="$PROJECT_ROOT/study/manifest.toml"

build_audit_binary() {
	cargo build \
		--manifest-path "$AUDIT_MANIFEST" \
		--bin unsafe-audit \
		--message-format=json-render-diagnostics |
		python3 -c '
import json
import sys

for line in sys.stdin:
		try:
				message = json.loads(line)
		except json.JSONDecodeError:
				continue

		if message.get("reason") != "compiler-artifact":
				continue

		target = message.get("target", {})
		if target.get("name") != "unsafe-audit":
				continue

		executable = message.get("executable")
		if executable:
				print(executable)
				break
'
}

if command -v python3 >/dev/null 2>&1; then
	AUDIT_BIN="$(build_audit_binary)"
	if [[ -n "$AUDIT_BIN" && -x "$AUDIT_BIN" ]]; then
		exec "$AUDIT_BIN" "$STUDY_MANIFEST" "$@"
	fi
fi

exec cargo run --manifest-path "$AUDIT_MANIFEST" -- "$STUDY_MANIFEST" "$@"
