#!/usr/bin/env python3
from __future__ import annotations

import os
import sys
from pathlib import Path

from threatzone import NotFoundError, PermissionDeniedError, ThreatZone


def env(name: str, default: str | None = None) -> str | None:
    v = os.environ.get(name)
    if v is None or v.strip() == "":
        return default
    return v


def normalize_base_url(base_url: str) -> str:
    b = base_url.rstrip("/")
    if not b.endswith("/public-api"):
        return f"{b}/public-api"
    return b


def main() -> int:
    api_key = env("THREATZONE_API_KEY")
    base_url = env("THREATZONE_E2E_BASE_URL", "http://localhost:8002/public-api")
    test_file = env("THREATZONE_E2E_TEST_FILE", str(Path(__file__).resolve().parents[1] / "tests/fixtures/sample.pdf"))

    if not api_key:
        print("Missing THREATZONE_API_KEY", file=sys.stderr)
        return 2

    file_path = Path(test_file)
    if not file_path.exists():
        print(f"Test file not found: {file_path}", file=sys.stderr)
        return 2

    print(f"Base URL: {base_url}")
    print(f"Test file: {file_path}")

    with ThreatZone(api_key=api_key, base_url=normalize_base_url(base_url)) as client:
        me = client.get_user_info()
        print(f"/me OK: {me.email} ({me.workspace.name})")

        envs = client.get_environments()
        default_env = next((e for e in envs if e.default), envs[0])
        print(f"/config/environments OK: default={default_env.key}")

        static_created = client.create_static_submission(str(file_path), private=False)
        print(f"Created static: uuid={static_created.uuid} sha256={static_created.sha256}")
        client.get_submission(static_created.uuid)
        client.get_summary(static_created.uuid)
        client.get_network_summary(static_created.uuid)
        with client.download_sample(static_created.uuid) as resp:
            print(f"download_sample OK: {resp.size} bytes")

        cdr_created = client.create_cdr_submission(str(file_path), private=False)
        print(f"Created cdr: uuid={cdr_created.uuid}")
        with client.download_sample(cdr_created.uuid) as resp:
            print(f"cdr download_sample OK: {resp.size} bytes")

        # Sandbox
        try:
            sandbox_meta = client.get_metafields("sandbox")
            sandbox_meta_list = []
            if sandbox_meta:
                sandbox_meta_list = [{"key": sandbox_meta[0].key, "value": sandbox_meta[0].default}]

            sandbox_created = client.create_sandbox_submission(
                str(file_path),
                environment=default_env.key,
                metafields=sandbox_meta_list or None,
                private=True,
                configurations={},
            )
            print(f"Created sandbox: uuid={sandbox_created.uuid} (enqueued)")
            client.get_submission(sandbox_created.uuid)
            client.get_network_summary(sandbox_created.uuid)
        except PermissionDeniedError:
            print("Sandbox submission not allowed by plan (403)")

        # Optional URL
        if env("THREATZONE_E2E_ENABLE_URL", "0") == "1":
            test_url = env("THREATZONE_E2E_TEST_URL", "https://example.com") or "https://example.com"
            try:
                url_created = client.create_url_submission(test_url, private=False)
                print(f"Created url: uuid={url_created.uuid} (enqueued)")
                try:
                    screenshot = client.get_screenshot(url_created.uuid)
                    print(f"screenshot OK: {len(screenshot)} bytes")
                except NotFoundError:
                    print("screenshot not found yet (expected without workers)")
            except PermissionDeniedError:
                print("URL submission not allowed by plan (403)")

    print("SDK smoke completed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
