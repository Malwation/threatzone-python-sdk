#!/usr/bin/env bash
# Run the Publish workflow locally via act in DRY-RUN mode.
#
# Dry run means: execute test + lint + type-check + build + wheel smoke,
# but DO NOT publish to PyPI. The publish-pypi job is gated behind
# `dry_run == 'false'` and is skipped automatically when we trigger via
# workflow_dispatch with the default dry_run=true input.
#
# Usage:
#   ./scripts/act-publish.sh                # run every non-publish job
#   ./scripts/act-publish.sh build          # run a single job by id
#   ./scripts/act-publish.sh --release      # simulate a real release event
#                                           # (still won't publish unless you
#                                           # provide real PyPI credentials)
#
# Requires: act >= 0.2.87, docker daemon running.

set -euo pipefail

cd "$(dirname "$0")/.."

WORKFLOW=".github/workflows/publish.yml"

if [[ "${1:-}" == "--release" ]]; then
  shift
  EVENT=".github/act-events/release.json"
  ACT_ARGS=(--workflows "$WORKFLOW" --eventpath "$EVENT" release)
else
  EVENT=".github/act-events/workflow_dispatch.json"
  ACT_ARGS=(--workflows "$WORKFLOW" --eventpath "$EVENT" workflow_dispatch)
fi

JOB="${1:-}"
if [[ -n "$JOB" ]]; then
  ACT_ARGS+=(--job "$JOB")
fi

echo "▶ act ${ACT_ARGS[*]}"
exec act "${ACT_ARGS[@]}"
