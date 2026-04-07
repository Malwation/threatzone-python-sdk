#!/usr/bin/env bash
# Run the CI workflow locally via act.
#
# Usage:
#   ./scripts/act-ci.sh                 # run all jobs (lint, type-check, test matrix, build)
#   ./scripts/act-ci.sh lint            # run only the lint job
#   ./scripts/act-ci.sh type-check      # run only mypy
#   ./scripts/act-ci.sh test            # run the full python matrix (3.9 → 3.13)
#   ./scripts/act-ci.sh build           # run only the build/wheel-smoke job
#
# Requires: act >= 0.2.87, docker daemon running.

set -euo pipefail

cd "$(dirname "$0")/.."

JOB="${1:-}"
WORKFLOW=".github/workflows/ci.yml"
EVENT=".github/act-events/push.json"

ACT_ARGS=(
  --workflows "$WORKFLOW"
  --eventpath "$EVENT"
  push
)

if [[ -n "$JOB" ]]; then
  ACT_ARGS+=(--job "$JOB")
fi

echo "▶ act ${ACT_ARGS[*]}"
exec act "${ACT_ARGS[@]}"
