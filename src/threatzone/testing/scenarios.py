"""Preset seed functions for the in-process fake Threat.Zone API.

These scenarios are the building blocks integration tests and example
scripts use to populate the fake with realistic-looking data without
duplicating boilerplate.
"""

from __future__ import annotations

from .fake_api import FakeThreatZoneAPI


def seed_malicious_pe(fake: FakeThreatZoneAPI, *, sha256: str | None = None) -> str:
    """Seed a fully-analysed malicious PE with dynamic report, indicators,
    network threats, YARA matches, IoCs, and MITRE techniques."""
    target_sha = sha256 or ("a" * 64)
    fake.register_sample(
        sha256=target_sha,
        filename="malware.exe",
        verdict="malicious",
        advance_after_polls=2,
        indicators=[
            ("T1055", "malicious", [1508, 4068]),
            ("T1547.001", "malicious", [1508]),
            ("T1112", "suspicious", [1508]),
        ],
        network_threats=[
            ("ET MALWARE Cobalt Strike Beacon", "high", "TLS"),
            ("ET TROJAN AsyncRAT CnC Activity", "high", "HTTP"),
        ],
        yara_rules=[
            ("Win_Trojan_CobaltStrike", "malicious"),
            ("AsyncRat_Payload", "malicious"),
        ],
        iocs=[
            ("domain", "malware-c2.example.com"),
            ("ip", "192.0.2.10"),
            ("sha256", "b" * 64),
        ],
        mitre_techniques=["T1055", "T1547.001", "T1112", "T1059.001"],
    )
    return target_sha


def seed_benign_document(fake: FakeThreatZoneAPI, *, sha256: str | None = None) -> str:
    """Seed a clean document with a static report and no dynamic report."""
    target_sha = sha256 or ("c" * 64)
    fake.register_sample(
        sha256=target_sha,
        filename="invoice.pdf",
        verdict="benign",
        advance_after_polls=1,
        indicators=[],
        network_threats=[],
        yara_rules=[],
        iocs=[],
        mitre_techniques=[],
        include_static_report=True,
        include_cdr_report=False,
    )
    pending = fake._pending_seeds[target_sha]
    pending.has_dynamic_report = False
    return target_sha


def seed_cdr_document(fake: FakeThreatZoneAPI, *, sha256: str | None = None) -> str:
    """Seed a document that went through CDR sanitisation."""
    target_sha = sha256 or ("d" * 64)
    fake.register_sample(
        sha256=target_sha,
        filename="contract.docx",
        verdict="suspicious",
        advance_after_polls=1,
        indicators=[],
        network_threats=[],
        yara_rules=[],
        iocs=[],
        mitre_techniques=[],
        include_static_report=False,
        include_cdr_report=True,
    )
    pending = fake._pending_seeds[target_sha]
    pending.has_dynamic_report = False
    return target_sha


def seed_phishing_url(fake: FakeThreatZoneAPI, *, url: str = "https://phishing.example.com") -> str:
    """Seed a URL submission with a url_analysis report and a phishing verdict."""
    fake.register_url_analysis(
        url=url,
        verdict="malicious",
        advance_after_polls=1,
        final_url=url,
        screenshot_available=True,
        threat_analysis_summary="Phishing kit targeting banking credentials",
    )
    return url


def seed_static_only_submission(fake: FakeThreatZoneAPI, *, sha256: str | None = None) -> str:
    """Seed a submission with ONLY a static report. Dynamic/CDR endpoints
    return ``409 DYNAMIC_REPORT_UNAVAILABLE``/``CDR_REPORT_UNAVAILABLE``."""
    target_sha = sha256 or ("e" * 64)
    fake.register_sample(
        sha256=target_sha,
        filename="sample.exe",
        verdict="suspicious",
        advance_after_polls=1,
        indicators=[("T1059.001", "suspicious", [2048])],
        network_threats=[],
        yara_rules=[("Suspicious_PowerShell", "suspicious")],
        iocs=[],
        mitre_techniques=["T1059.001"],
        include_static_report=True,
        include_cdr_report=False,
    )
    pending = fake._pending_seeds[target_sha]
    pending.has_dynamic_report = False
    return target_sha


def seed_private_cross_workspace(fake: FakeThreatZoneAPI, *, sha256: str | None = None) -> str:
    """Seed a submission marked private in a workspace other than the test
    token's. Any access attempt returns ``403 SUBMISSION_PRIVATE``."""
    target_sha = seed_malicious_pe(fake, sha256=sha256)
    pending = fake._pending_seeds.get(target_sha)
    if pending is None:
        return target_sha
    pending.private = True
    pending.owning_workspace = "other-workspace"
    return target_sha
