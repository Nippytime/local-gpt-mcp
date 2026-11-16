"""Checkpoints contain only hash, sequence and state, never secrets or action data."""

from __future__ import annotations

import json
import os
import stat
import tempfile
from pathlib import Path
from typing import Protocol

from local_gpt_mcp.orchestrator.models import Checkpoint


class CheckpointStore(Protocol):
    def read(self, plan_id: str) -> Checkpoint | None: ...

    def save(self, plan_id: str, checkpoint: Checkpoint) -> None: ...


class MemoryCheckpointStore:
    def __init__(self) -> None:
        self._items: dict[str, Checkpoint] = {}

    def read(self, plan_id: str) -> Checkpoint | None:
        return self._items.get(plan_id)

    def save(self, plan_id: str, checkpoint: Checkpoint) -> None:
        self._items[plan_id] = checkpoint


class FileCheckpointStore:
    """Local path selected by user/operator; no remote file-path input."""

    def __init__(self, directory: Path) -> None:
        self._directory = directory
        self._directory.mkdir(parents=True, exist_ok=True, mode=0o700)

    def _file(self, plan_id: str) -> Path:
        from local_gpt_mcp.orchestrator.models import IDENTIFIER

        if not IDENTIFIER.fullmatch(plan_id):
            raise ValueError("Invalid plan identifier")
        return self._directory / f"{plan_id}.json"

    def read(self, plan_id: str) -> Checkpoint | None:
        file = self._file(plan_id)
        if not file.exists():
            return None
        if file.is_symlink():
            raise ValueError("Symlink checkpoints are prohibited")
        content = json.loads(file.read_text(encoding="utf-8"))
        if not isinstance(content, dict) or set(content) != {"plan_digest", "index", "state"}:
            raise ValueError("Unexpected checkpoint data")
        return Checkpoint(**content)

    def save(self, plan_id: str, checkpoint: Checkpoint) -> None:
        destination = self._file(plan_id)
        if destination.is_symlink():
            raise ValueError("Symlink checkpoints are prohibited")
        encoded = json.dumps(
            {
                "plan_digest": checkpoint.plan_digest,
                "index": checkpoint.index,
                "state": checkpoint.state,
            },
            sort_keys=True,
        ).encode("utf-8")
        fd, tmp = tempfile.mkstemp(prefix=".checkpoint-", dir=self._directory)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(encoded)
                stream.flush()
                os.fsync(stream.fileno())
            os.chmod(tmp, stat.S_IRUSR | stat.S_IWUSR)
            os.replace(tmp, destination)
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)
