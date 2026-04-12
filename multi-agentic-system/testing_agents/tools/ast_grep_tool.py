from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

from ..tracing import ConsoleTracer


class AstGrepTool:
    def __init__(self, repo_root: Path, binary: str = "ast-grep", tracer: ConsoleTracer | None = None) -> None:
        self.repo_root = repo_root
        self.binary = binary
        self.tracer = tracer

    def ensure_available(self) -> None:
        result = subprocess.run(
            [self.binary, "--version"],
            cwd=self.repo_root,
            text=True,
            capture_output=True,
        )
        if result.returncode != 0:
            raise RuntimeError(
                "ast-grep is required but not available on PATH. "
                "Install it with `uv sync`, `pip install ast-grep-cli`, or your preferred package manager."
            )
        if self.tracer:
            self.tracer.tool("AstGrepTool.ensure_available", ".", "available")

    def run_pattern(
        self,
        pattern: str,
        paths: list[str],
        lang: str | None = None,
    ) -> list[dict[str, Any]]:
        command = [self.binary, "run", "--pattern", pattern, "--json=stream"]
        if lang:
            command.extend(["--lang", lang])
        command.extend(paths)
        result = subprocess.run(
            command,
            cwd=self.repo_root,
            text=True,
            capture_output=True,
        )
        if result.returncode == 1 and not result.stdout.strip():
            return []
        if "Cannot parse query as a valid pattern" in result.stderr:
            return []
        if result.returncode not in {0, 1}:
            raise RuntimeError(result.stderr.strip() or f"ast-grep failed for pattern: {pattern}")

        matches: list[dict[str, Any]] = []
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            matches.append(json.loads(line))
        if self.tracer:
            target = paths[0] if len(paths) == 1 else f"{len(paths)} files"
            self.tracer.tool("AstGrepTool.run_pattern", target, f"{len(matches)} matches")
        return matches
