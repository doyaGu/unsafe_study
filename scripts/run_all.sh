#!/bin/bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
exec cargo run --manifest-path "$PROJECT_ROOT/unsafe-audit/Cargo.toml" -- "$PROJECT_ROOT/study/manifest.toml" "$@"
