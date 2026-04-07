# Local workflow testing with `act`

This SDK ships two GitHub Actions workflows:

| File | Triggers | Jobs |
|---|---|---|
| `ci.yml` | `push` / `pull_request` on `main`,`develop`; `workflow_dispatch` | `lint`, `type-check`, `test` (Python 3.10–3.13 matrix), `build` |
| `publish.yml` | `release: published`; `workflow_dispatch` (with `dry_run` input) | `test` (matrix), `lint`, `type-check`, `version-check`, `build`, `publish-pypi` |

Both workflows are fully runnable **locally** via [`act`](https://github.com/nektos/act) so you can iterate on CI without pushing dummy commits. Everything needed for local runs is committed alongside the workflows:

```
.actrc                        # default image, --reuse, --defaultbranch main
.github/act-events/           # realistic event payloads (push, PR, release, workflow_dispatch)
scripts/act-ci.sh             # wrapper around `act` for ci.yml
scripts/act-publish.sh        # wrapper around `act` for publish.yml (dry-run by default)
```

## Prerequisites

1. **Docker** running locally.
2. **`act` ≥ 0.2.87** on your PATH:
   ```bash
   curl --proto '=https' --tlsv1.2 -sSf https://raw.githubusercontent.com/nektos/act/master/install.sh | sudo bash
   sudo mv ./bin/act /usr/local/bin/act
   act --version
   ```
3. First invocation will pull `catthehacker/ubuntu:act-latest` (~1 GB). Subsequent runs reuse it.

## Running CI

```bash
./scripts/act-ci.sh              # run every CI job (lint + type-check + 4-python matrix + build)
./scripts/act-ci.sh lint         # ruff check + ruff format --check
./scripts/act-ci.sh type-check   # mypy
./scripts/act-ci.sh test         # pytest matrix (Python 3.10 → 3.13), 4 parallel containers
./scripts/act-ci.sh build        # uv build, wheel import smoke, artifact upload
```

The `test` job is the slowest — act spins up one container per Python version. Use `./scripts/act-ci.sh test -j test --matrix python-version:3.12` if you only want to exercise a single version.

## Running Publish (dry-run)

`publish.yml` gates the real PyPI upload behind `github.event.inputs.dry_run == 'false'` or a `release` event. The wrapper defaults to `workflow_dispatch` with `dry_run=true`, which means:

- ✅ `lint`, `type-check`, `test` matrix, `build`, wheel-import smoke ALL run
- ⏭ `version-check` is skipped (only runs for real `release` events)
- ⏭ `publish-pypi` is skipped (dry-run gate)

```bash
./scripts/act-publish.sh              # dry-run: every job except publish-pypi
./scripts/act-publish.sh build        # dry-run, single job
./scripts/act-publish.sh --release    # simulate a real release event
```

The `--release` mode will trigger `version-check` and attempt to reach `publish-pypi` but still fails safely because no real PyPI token is wired into the local act environment — this is the correct behavior for a pre-transfer sanity check.

## Event payloads

Every fixture under `.github/act-events/` is a realistic-enough subset of the GitHub webhook payload to let the workflow expressions (`github.event_name`, `github.ref`, `github.event.inputs.dry_run`) resolve correctly. Edit the files if a new workflow needs additional fields.

## Known local-run caveats

| Step | Behavior under act | Why |
|---|---|---|
| `actions/upload-artifact@v4` | Skipped via `if: ${{ !env.ACT }}` | v4 requires `ACTIONS_RUNTIME_TOKEN` which act cannot provide. The step runs normally on real GitHub. Consequence: `publish-pypi` under `--release` cannot find the artifact locally, but that path also can't reach PyPI without credentials so it's moot. |
| `codecov/codecov-action@v4` | Runs, upload silently fails | Gated behind `github.event_name == 'push' && github.ref == 'refs/heads/main'` — the push event payload satisfies this but no codecov token is wired in locally. Non-fatal. |
| `pypa/gh-action-pypi-publish@release/v1` | Never reached | Blocked by the dry-run gate; see above. |

## Pre-transfer checklist

Before moving this repo out of `threatzone-services`, verify:

- [ ] `./scripts/act-ci.sh` exits 0 end-to-end
- [ ] `./scripts/act-publish.sh` exits 0 end-to-end (dry-run)
- [ ] No workflow file references `Malwation/threatzone-services` paths
- [ ] `.github/act-events/*.json` `repository.full_name` matches `Malwation/threatzone-python-sdk`
- [ ] `pyproject.toml` project URLs point at `github.com/Malwation/threatzone-python-sdk`
- [ ] PyPI trusted publishing is configured for the package `threatzone` under the `pypi` environment on the new repo
