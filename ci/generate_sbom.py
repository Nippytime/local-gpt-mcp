"""Generate a deterministic CycloneDX inventory of actually installed Python packages.

This is an inventory, not a vulnerability scanner or proof of provenance.
Dependency audit remains a distinct mandatory gate.
"""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from importlib.metadata import Distribution, distributions
from pathlib import Path
from typing import Any

NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+!_-]*$")


def build_sbom(installed: list[Distribution]) -> dict[str, Any]:
    components: list[dict[str, str]] = []
    seen: set[str] = set()
    for dist in installed:
        name = dist.metadata.get("Name", "")
        version = dist.version
        if not NAME.fullmatch(name) or not VERSION.fullmatch(version):
            raise ValueError("Unparseable installed distribution name or version")
        canonical = re.sub(r"[-_.]+", "-", name).lower()
        purl = f"pkg:pypi/{canonical}@{version}"
        if purl in seen:
            continue
        seen.add(purl)
        components.append(
            {
                "type": "library",
                "name": canonical,
                "version": version,
                "purl": purl,
                "bom-ref": purl,
            }
        )
    components.sort(key=lambda item: item["purl"])
    if not components:
        raise ValueError("No installed dependencies were discovered")
    fingerprint = hashlib.sha256(
        json.dumps(components, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, fingerprint)}",
        "version": 1,
        "metadata": {
            "component": {"type": "application", "name": "local-gpt-mcp", "version": "0.1.0"}
        },
        "components": components,
    }


def main() -> int:
    report = build_sbom(list(distributions()))
    destination = Path("artifacts/ci/sbom.cdx.json")
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"Generated CycloneDX dependency inventory: {destination}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
