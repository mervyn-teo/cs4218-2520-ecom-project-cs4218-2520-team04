from __future__ import annotations

import unittest

from testing_agents.tools.js_heuristics import JSHeuristicsTool


class FakeAstGrep:
    def run_pattern(self, pattern: str, paths: list[str], lang: str | None = None):
        if pattern == "res.status($CODE)":
            return [
                {
                    "text": "res.status(400)",
                    "range": {"start": {"line": 10, "column": 2}},
                    "file": paths[0],
                }
            ]
        return []


class JSHeuristicsToolTests(unittest.TestCase):
    def test_backend_status_code_becomes_behavior(self) -> None:
        tool = JSHeuristicsTool(repo_root=None, ast_grep=FakeAstGrep())  # type: ignore[arg-type]
        records = tool.detect_behaviors("controllers/authController.js", "controller")
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].category, "error-path")
        self.assertEqual(records[0].suite_hint, "integration")


if __name__ == "__main__":
    unittest.main()
