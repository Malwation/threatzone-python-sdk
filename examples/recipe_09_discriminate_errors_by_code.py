"""Recipe 9: Discriminate API errors by their typed exception class / code.

Runnable two ways:

1. Against a live Threat.Zone instance:
       export PUBLIC_API_TOKEN="<your-api-token>"
       export PUBLIC_API_BASE_URL="https://app.threat.zone/public-api"  # optional
       python examples/recipe_09_discriminate_errors_by_code.py <submission_uuid>

2. Imported by tests/integration/test_examples.py — Task 55 wires each example's
   main() into a pytest case running against FakeThreatZoneAPI.
"""

from __future__ import annotations

import os
import sys

from threatzone import (
    APIError,
    AuthenticationError,
    BadRequestError,
    NotFoundError,
    PermissionDeniedError,
    RateLimitError,
    ReportUnavailableError,
    ThreatZone,
)


def main(client: ThreatZone, submission_uuid: str) -> str:
    """Call get_indicators and return a string describing which error code fired."""
    try:
        response = client.get_indicators(submission_uuid)
    except AuthenticationError:
        return "AUTHENTICATION_ERROR"
    except PermissionDeniedError as exc:
        code = (exc.body or {}).get("code") if exc.body else None
        return f"PERMISSION_DENIED:{code or 'unknown'}"
    except NotFoundError:
        return "NOT_FOUND"
    except BadRequestError as exc:
        code = (exc.body or {}).get("code") if exc.body else None
        return f"BAD_REQUEST:{code or 'unknown'}"
    except ReportUnavailableError as exc:
        return f"REPORT_UNAVAILABLE:{exc.code or 'unknown'}"
    except RateLimitError as exc:
        return f"RATE_LIMITED:retry_after={exc.retry_after}"
    except APIError as exc:
        return f"API_ERROR:{exc.status_code}"

    print(f"Got {response.total} indicators.")
    return "OK"


if __name__ == "__main__":
    api_key = os.environ.get("PUBLIC_API_TOKEN")
    if not api_key:
        raise SystemExit("PUBLIC_API_TOKEN env var is required to run this example live.")
    if len(sys.argv) < 2:
        raise SystemExit(
            "Usage: python examples/recipe_09_discriminate_errors_by_code.py <submission_uuid>"
        )

    base_url = os.environ.get("PUBLIC_API_BASE_URL", "https://app.threat.zone/public-api")

    client = ThreatZone(api_key=api_key, base_url=base_url)
    try:
        result = main(client, sys.argv[1])
        print(result)
    finally:
        client.close()
