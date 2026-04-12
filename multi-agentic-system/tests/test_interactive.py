from __future__ import annotations

import unittest

from testing_agents.interactive import select_gap_ids
from testing_agents.schemas import GapPlanItem


def sample_items() -> list[GapPlanItem]:
    return [
        GapPlanItem(
            gap_id="g1",
            priority="P0",
            source_file="controllers/authController.js",
            source_kind="controller",
            behavior_summary="Auth branch",
            rationale="Missing coverage",
            suite_type="unit",
            target_file="controllers/authController.test.js",
            target_command="npm run test:backend -- controllers/authController.test.js --runInBand",
            append_mode="append",
            coverage_status="uncovered",
            confidence=0.9,
            scenario_summary="covers auth branch",
        ),
        GapPlanItem(
            gap_id="g2",
            priority="P1",
            source_file="client/src/pages/HomePage.js",
            source_kind="page",
            behavior_summary="Navigation branch",
            rationale="Missing coverage",
            suite_type="integration",
            target_file="client/src/pages/HomePage.integration.test.js",
            target_command="npm run test:integration -- client/src/pages/HomePage.integration.test.js --runInBand",
            append_mode="create",
            coverage_status="uncovered",
            confidence=0.8,
            scenario_summary="covers homepage navigation",
        ),
    ]


class InteractiveSelectionTests(unittest.TestCase):
    def test_select_by_index_and_priority(self) -> None:
        items = sample_items()
        self.assertEqual(select_gap_ids(items, "1,P1"), ["g1", "g2"])

    def test_select_all(self) -> None:
        items = sample_items()
        self.assertEqual(select_gap_ids(items, "all"), ["g1", "g2"])


if __name__ == "__main__":
    unittest.main()
