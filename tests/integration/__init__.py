"""Fake-backed integration tests for the Threat.Zone Python SDK.

These tests exercise the real ``ThreatZone`` and ``AsyncThreatZone`` clients
against the in-process ``FakeThreatZoneAPI``. No network access, no env vars,
no token required — they run anywhere ``pytest`` runs.
"""
