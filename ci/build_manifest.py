"""Create a hash-verifiable inventory for actual build artifacts.

The inventory records exact bytes and source revision. It does not sign, attest,
or imply that an unreleased package is production-ready.
"""

from __future__ import annotations

import hashlib
import json
import sys
import tomllib
from pathlib import Path
from typing import Any

from ci.run import ROOT, checked_revision


def inventory(artifacts: list[Path], *, revision: str, version: str) -> dict[str, Any]:
    if len(revision) != 40 or any(char not in "0123456789abcdef" for char in revision):
        raise ValueError("Source revision must be a full verified Git SHA")
    prefix = f"local_gpt_mcp-{version}"
    entries: list[dict[str, str | int]] = []
    for path in sorted(artifacts):
        if (
            path.is_symlink()
            or not path.is_file()
            or not path.name.startswith(prefix)
            or not path.name.endswith((".whl", ".tar.gz"))
        ):
            raise ValueError("Unexpected or linked distribution artifact")
        with path.open("rb") as stream:
            sha256 = hashlib.file_digest(stream, "sha256").hexdigest()
        entries.append({"file": path.name, "size_bytes": path.stat().st_size, "sha256": sha256})
    if not entries or any(entry["size_bytes"] == 0 for entry in entries):
        raise ValueError("Nonempty built distributions are required")
    if len({entry["file"] for entry in entries}) != len(entries):
        raise ValueError("Duplicate distribution filename")
    return {
        "schema_version": 1,
        "package": "local-gpt-mcp",
        "version": version,
        "source_commit": revision,
        "artifacts": entries,
        "signed": False,
    }


def main() -> int:
    try:
        metadata = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        version = metadata["project"]["version"]
        if not isinstance(version, str) or not version:
            raise ValueError("Package version is unavailable")
        dist = ROOT / "dist"
        files = [*dist.glob("*.whl"), *dist.glob("*.tar.gz")]
        report = inventory(files, revision=checked_revision(), version=version)
        output = ROOT / "artifacts" / "ci" / "build-manifest.json"
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    except (OSError, ValueError, KeyError, TypeError, tomllib.TOMLDecodeError) as error:
        print(f"Unable to verify release artifact provenance: {error}", file=sys.stderr)
        return 1
    print(f"Build checksums and source commit recorded: {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
