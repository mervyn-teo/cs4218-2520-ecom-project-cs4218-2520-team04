from __future__ import annotations

import shutil
import unittest
from pathlib import Path
from unittest.mock import patch

from testing_agents.tools.repo_search import RepoSearchTool


FIXTURE_ROOT = Path(__file__).resolve().parent / "_repo_search_fixture"


class RepoSearchToolTests(unittest.TestCase):
    def setUp(self) -> None:
        if FIXTURE_ROOT.exists():
            shutil.rmtree(FIXTURE_ROOT)
        (FIXTURE_ROOT / "src").mkdir(parents=True)
        (FIXTURE_ROOT / "src" / "file.js").write_text("const token = 'abc';\n", encoding="utf-8")
        (FIXTURE_ROOT / ".venv").mkdir()
        (FIXTURE_ROOT / ".venv" / "ignored.txt").write_text("ignore\n", encoding="utf-8")

    def tearDown(self) -> None:
        if FIXTURE_ROOT.exists():
            shutil.rmtree(FIXTURE_ROOT)

    def test_files_falls_back_without_rg(self) -> None:
        tool = RepoSearchTool(FIXTURE_ROOT)
        with patch("testing_agents.tools.repo_search.subprocess.run", side_effect=FileNotFoundError):
            files = tool.files()

        self.assertEqual(files, ["src/file.js"])

    def test_search_falls_back_without_rg(self) -> None:
        tool = RepoSearchTool(FIXTURE_ROOT)
        with patch("testing_agents.tools.repo_search.subprocess.run", side_effect=FileNotFoundError):
            matches = tool.search("token")

        self.assertEqual(matches, ["src/file.js:1:const token = 'abc';"])


if __name__ == "__main__":
    unittest.main()
