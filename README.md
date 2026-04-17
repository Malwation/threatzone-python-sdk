# Threat.Zone Python SDK

Official Python SDK for the [Threat.Zone](https://threat.zone) malware analysis platform.
Targets the Threat.Zone Public API, ships fully typed Pydantic v2
models for every endpoint, and exposes both synchronous (`ThreatZone`) and asynchronous
(`AsyncThreatZone`) clients with identical method surfaces. Requires **Python 3.10+**.

> [!WARNING]
> ## ⚠️ Version Compatibility Notice
>
> **This SDK requires Threat.Zone v3.2.0 or later.**
>
> This SDK targets the Public API shipped with **Threat.Zone v3.2.0**. It will **not** function correctly against earlier versions of the platform.
>
>
> Running an older Threat.Zone version? Pin to a pre-v3.2.0 release of this SDK, or coordinate with your admin to upgrade the platform first.

## Install

```bash
pip install threatzone
# or
uv add threatzone
```

## Configure

```python
from threatzone import ThreatZone

client = ThreatZone(api_key="<your-api-key>")
```

The client reads `THREATZONE_API_KEY` from the environment, so `ThreatZone()` is enough
if you export it. The default `base_url` is `https://app.threat.zone/public-api`.

For on-prem or local development, pass `base_url` explicitly:

```python
client = ThreatZone(
    api_key="<your-api-key>",
    base_url="https://threatzone.your-company.internal/public-api",
)
```

The `base_url` **must** include the `/public-api` suffix. For self-signed certs, leave
`verify_ssl=False` (the default).

## Quick usage

```python
from pathlib import Path

account = client.get_user_info()
print(f"Workspace: {account.workspace_name}")

submission = client.create_sandbox_submission(Path("./sample.exe"))
completed = client.wait_for_completion(submission.uuid, timeout=600)
print(f"Verdict: {completed.level}")
print(f"MITRE techniques: {completed.mitre_techniques}")
```

## Core concepts

- **Submissions** — one analysis target (file or URL) with a stable `uuid`, a workspace
  owner, a `private` flag, and up to four reports.
- **Reports** — `dynamic`, `static`, `cdr`, `url_analysis`. Independent; poll each via
  `submission.is_complete()` / `submission.has_errors()`. Every report carries its own
  `status`, `level`, `score`.
- **Observation streams** — the dynamic report produces `indicators` (rule hits),
  `iocs` (concrete IOC values), `behaviours` (OS-level operations — the `os` query param
  is required), and `syscalls` (raw log lines).
- **Artifacts** — files produced or extracted during analysis; keyed by `hashes.sha256`.
- **Access control** — public submissions are visible to every API key; private
  submissions are workspace-scoped. Cross-workspace reads of private submissions raise
  `PermissionDeniedError` (403).

## Async

`AsyncThreatZone` mirrors `ThreatZone` method-for-method:

```python
import asyncio
from threatzone import AsyncThreatZone

async def main() -> None:
    async with AsyncThreatZone(api_key="<your-api-key>") as client:
        account = await client.get_user_info()
        print(account.email)

asyncio.run(main())
```

Use `asyncio.gather()` for concurrent fan-out. See [recipe 10](./docs/RECIPES.md#10-use-the-async-client).

## Errors

Every error inherits from `ThreatZoneError`. HTTP errors additionally inherit from
`APIError` and carry the parsed error envelope on `.body`, with the structured code at
`.body["code"]`. Branch on `.code`, never on `.message`.

| Status | Exception | When |
|---|---|---|
| — | `ThreatZoneError` | Base class. Catch for a single safety net. |
| — | `APIError` | HTTP error base class. `.status_code`, `.body`, `.response`. |
| 400 | `BadRequestError` | `INVALID_UUID`, `INVALID_QUERY_PARAM`. |
| 401 | `AuthenticationError` | Missing/invalid API key. |
| 402 | `PaymentRequiredError` | Workspace subscription inactive. |
| 403 | `PermissionDeniedError` | Cross-workspace private read, or module not enabled. |
| 404 | `NotFoundError` | Submission, artifact, or media missing. |
| 409 | `ReportUnavailableError` | Required report not yet available. Carries `.code`, `.submission_uuid`, `.required_report`, `.current_status`, `.available_reports`. |
| 429 | `RateLimitError` | API quota exceeded. Has `.retry_after`. |
| 5xx | `InternalServerError` | Server-side failure. |
| — | `TimeoutError` | HTTP request timed out. |
| — | `ConnectionError` | Network-level failure. |
| — | `AnalysisTimeoutError` | `wait_for_completion()` exceeded its timeout. `.uuid`, `.elapsed`. |
| 202 | `YaraRulePendingError` | YARA rule generation still in progress. `.retry_after`. |

```python
from threatzone import ReportUnavailableError, ThreatZone

try:
    indicators = client.get_indicators("00000000-0000-0000-0000-000000000000")
except ReportUnavailableError as exc:
    if exc.code == "DYNAMIC_REPORT_UNAVAILABLE":
        print(f"Dynamic report not ready (status: {exc.current_status}).")
```

See [recipe 9](./docs/RECIPES.md#9-discriminate-errors-by-their-code-field) for the full
discrimination pattern and [recipe 7](./docs/RECIPES.md#7-handle-the-reportunavailableerror-exception)
for the recommended retry loop.

## Documentation

| Document | Purpose |
|---|---|
| [Recipes](./docs/RECIPES.md) | 12 runnable examples covering common tasks. |
| [Type Reference](./docs/TYPES.md) | Pydantic model overview grouped by feature area. |

## Testing utilities

The SDK ships a stateful in-process fake Threat.Zone API for consumer-side tests:

```python
from threatzone import ThreatZone
from threatzone.testing import FakeThreatZoneAPI, scenarios

fake = FakeThreatZoneAPI()
scenarios.seed_malicious_pe(fake, sha256="a" * 64)

client = ThreatZone(
    api_key="test-key",
    base_url="https://fake.threat.zone/public-api",
    http_client=fake.as_httpx_client(),
)
```

Available scenarios: `seed_malicious_pe`, `seed_benign_document`, `seed_cdr_document`,
`seed_phishing_url`, `seed_static_only_submission`, `seed_private_cross_workspace`.

## Development

```bash
uv sync --all-extras --dev
uv run pytest tests/
uv run ruff check src/ tests/
uv run mypy src/threatzone
uv build
```

All tests run in-process against `FakeThreatZoneAPI` — no network, no API token. Live
smoke-testing uses the scripts in `examples/` with `PUBLIC_API_TOKEN` exported; see
`examples/README.md`.

GitHub Actions workflows can be exercised locally via `act` — see
[`.github/workflows/README.md`](./.github/workflows/README.md).

## Links

- [Threat.Zone platform](https://threat.zone)
- [Public API reference](https://app.threat.zone/public-api/docs)
- [PyPI package](https://pypi.org/project/threatzone/)
- [GitHub repository](https://github.com/Malwation/threatzone-python-sdk)

## License

MIT — see [LICENSE](LICENSE).
