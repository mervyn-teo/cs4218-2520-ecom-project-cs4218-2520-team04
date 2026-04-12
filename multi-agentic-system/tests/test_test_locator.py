from __future__ import annotations

import unittest

from testing_agents.schemas import RepoMap, TestInventory
from testing_agents.tools.test_locator import TestLocatorTool


class TestLocatorToolTests(unittest.TestCase):
    def test_prefers_existing_sibling_unit_test(self) -> None:
        locator = TestLocatorTool()
        repo_map = RepoMap(
            source_files=[],
            test_files=["controllers/authController.test.js"],
            config_files=[],
            ownership_links={},
        )
        inventory = TestInventory()
        candidates = locator.rank_candidates("controllers/authController.js", "unit", repo_map, inventory)
        self.assertEqual(candidates[0].target_file, "controllers/authController.test.js")
        self.assertEqual(candidates[0].append_vs_create, "append")

    def test_react_file_gets_unit_and_integration_candidates(self) -> None:
        locator = TestLocatorTool()
        repo_map = RepoMap(source_files=[], test_files=[], config_files=[], ownership_links={})
        inventory = TestInventory()
        candidates = locator.rank_candidates("client/src/pages/HomePage.js", "integration", repo_map, inventory)
        self.assertEqual(candidates[0].target_file, "client/src/pages/HomePage.test.js")
        self.assertEqual(candidates[1].target_file, "client/src/pages/HomePage.integration.test.js")


if __name__ == "__main__":
    unittest.main()
