# Threat.Zone Python SDK Examples

Each script mirrors a recipe in [docs/RECIPES.md](../docs/RECIPES.md).

## Running against a live Threat.Zone instance

```bash
export PUBLIC_API_TOKEN="<your-api-token>"
export PUBLIC_API_BASE_URL="https://app.threat.zone/public-api"  # optional; default shown
python examples/recipe_01_submit_and_wait.py
```

For on-prem:
```bash
export PUBLIC_API_BASE_URL="https://threatzone.your-company.internal/public-api"
```

## Running in CI

Every example's `main()` is imported by `tests/integration/test_examples.py` and
exercised against the `FakeThreatZoneAPI`. Examples can't rot — if a recipe breaks,
CI fails.

## Recipes

| # | File | What it does |
|---|---|---|
| 1 | `recipe_01_submit_and_wait.py` | Submit a file, wait for analysis, print verdict |
| 2 | `recipe_02_url_analysis.py` | Submit a URL, wait, print phishing findings |
| 3 | `recipe_03_get_malicious_indicators.py` | Filter indicators by level=malicious |
| 4 | `recipe_04_download_all_artifacts.py` | Download every artifact to a directory |
| 5 | `recipe_05_search_by_sha256.py` | Find prior submissions by file hash |
| 6 | `recipe_06_export_network_iocs.py` | Collect domains, IPs, URLs from network data |
| 7 | `recipe_07_handle_report_unavailable.py` | Gracefully handle 409 ReportUnavailableError |
| 8 | `recipe_08_paginate_submissions.py` | Walk through a paginated submission list |
| 9 | `recipe_09_discriminate_errors_by_code.py` | Branch on ApiError.code enum values |
| 10 | `recipe_10_async_client.py` | Use AsyncThreatZone with asyncio |
| 11 | `recipe_11_daily_summary.py` | Aggregate submission counts for a dashboard |
| 12 | `recipe_12_mitre_cross_reference.py` | Cross-reference indicators with MITRE techniques |
