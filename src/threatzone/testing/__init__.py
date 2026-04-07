"""In-process fake Threat.Zone Public API for SDK consumers' tests.

Usage::

    from threatzone import ThreatZone
    from threatzone.testing import FakeThreatZoneAPI, scenarios

    fake = FakeThreatZoneAPI()
    scenarios.seed_malicious_pe(fake)

    client = ThreatZone(
        api_key="test-key",
        base_url="https://fake.threat.zone/public-api",
        http_client=fake.as_httpx_client(),
    )

The fake ships with the ``threatzone`` wheel so consumers can use it to test
their own code against the SDK without hitting the real Threat.Zone API.
"""

from . import scenarios
from .fake_api import FakeThreatZoneAPI

__all__ = ["FakeThreatZoneAPI", "scenarios"]
