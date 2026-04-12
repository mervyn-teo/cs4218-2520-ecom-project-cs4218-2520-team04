from __future__ import annotations

import re
from pathlib import Path

from .config import RuntimeConfig
from .llm import OpenAILLM
from .schemas import GapPlanItem, InventoryItem, RepoMap, TestInventory, WriteResult
from .tracing import ConsoleTracer
from .tools.artifact_store import ArtifactStoreTool
from .tools.ast_grep_tool import AstGrepTool
from .tools.coverage_heuristics import CoverageHeuristicTool
from .tools.jest_runner import JestRunnerTool
from .tools.js_heuristics import JSHeuristicsTool
from .tools.patch_writer import PatchWriterTool
from .tools.repo_search import RepoSearchTool
from .tools.source_reader import SourceReadTool
from .tools.test_locator import TestLocatorTool


class AgentRuntime:
    def __init__(self, config: RuntimeConfig) -> None:
        self.config = config
        self.tracer = ConsoleTracer(enabled=config.verbose)
        self.repo_search = RepoSearchTool(config.repo_root, tracer=self.tracer)
        self.source_reader = SourceReadTool(config.repo_root, tracer=self.tracer)
        self.ast_grep = AstGrepTool(config.repo_root, binary=config.ast_grep_bin, tracer=self.tracer)
        self.js_heuristics = JSHeuristicsTool(config.repo_root, self.ast_grep)
        self.locator = TestLocatorTool(tracer=self.tracer)
        self.coverage = CoverageHeuristicTool(self.repo_search, self.ast_grep, tracer=self.tracer)
        self.artifacts = ArtifactStoreTool(config.artifact_dir)
        self.patch_writer = PatchWriterTool(config.repo_root, tracer=self.tracer)
        self.jest_runner = JestRunnerTool(config.repo_root, tracer=self.tracer)
        self.llm = OpenAILLM(config, tracer=self.tracer)

    def health_check(self) -> None:
        self.tracer.supervisor(f"Supervisor model: {self.config.supervisor_model} | Worker model: {self.config.worker_model}")
        self.config.ensure_directories()
        self.ast_grep.ensure_available()

    def build_repo_map(self) -> RepoMap:
        self.tracer.agent_start("RepoCartographerAgent", "Scanning repository structure and ownership links")
        files = self.repo_search.files()
        source_files: list[str] = []
        test_files: list[str] = []
        config_files: list[str] = []
        for file_path in files:
            if self._is_test_file(file_path):
                test_files.append(file_path)
            elif file_path.endswith((".js", ".jsx", ".cjs", ".mjs")) and not file_path.startswith("node_modules/"):
                source_files.append(file_path)
            elif file_path.endswith((".json", ".toml", ".yml", ".yaml")):
                config_files.append(file_path)

        repo_map = RepoMap(source_files=source_files, test_files=test_files, config_files=config_files, ownership_links={})
        empty_inventory = TestInventory()
        for source_file in source_files:
            linked = [
                candidate.target_file
                for candidate in self.locator.rank_candidates(source_file, "unit", repo_map, empty_inventory)
                if candidate.target_file in test_files
            ]
            if linked:
                repo_map.ownership_links[source_file] = linked
        self.tracer.agent_done(
            "RepoCartographerAgent",
            f"Mapped {len(source_files)} source files, {len(test_files)} test files, {len(repo_map.ownership_links)} ownership links",
        )
        return repo_map

    def build_test_inventory(self, repo_map: RepoMap) -> TestInventory:
        self.tracer.agent_start("TestInventoryAgent", "Indexing test conventions and runnable suites")
        command_map = {
            "backend": "npm run test:backend -- <path> --runInBand",
            "frontend": "npm run test:frontend -- <path> --runInBand --coverage=false",
            "integration": "npm run test:integration -- <path> --runInBand",
        }
        conventions = {
            "unit": ["controllers/*.test.js", "models/*.test.js", "client/src/**/*.test.js"],
            "integration": ["tests/integration/backend/**", "tests/integration/frontend/**", "client/src/**/*.integration.test.js"],
        }
        files: list[InventoryItem] = []
        for test_file in repo_map.test_files:
            suite_type = "integration" if ".integration." in test_file or test_file.startswith("tests/integration/") else "unit"
            if test_file.startswith("client/src/"):
                command = command_map["frontend"] if suite_type == "unit" else command_map["integration"]
            else:
                command = command_map["integration"] if suite_type == "integration" else command_map["backend"]
            files.append(
                InventoryItem(
                    path=test_file,
                    suite_type=suite_type,
                    command=command,
                    reason="Discovered from current repo test conventions",
                )
            )
        inventory = TestInventory(command_map=command_map, files=files, conventions=conventions)
        self.tracer.agent_done("TestInventoryAgent", f"Indexed {len(files)} test files across {len(conventions)} suite groups")
        return inventory

    def analyze_gaps(self, repo_map: RepoMap, inventory: TestInventory) -> list[GapPlanItem]:
        self.tracer.agent_start("GapAnalystSupervisor", "Dispatching backend/frontend gap analysis")
        candidate_files = [path for path in repo_map.source_files if self._within_requested_scope(path)]
        planned: list[GapPlanItem] = []

        for source_file in candidate_files:
            source_kind = self._source_kind(source_file)
            if source_kind == "test":
                continue
            agent_name = "FrontendGapAnalystAgent" if source_file.startswith("client/src/") else "BackendGapAnalystAgent"
            self.tracer.agent_start(agent_name, f"Reviewing {source_file} ({source_kind})")

            behaviors = self.js_heuristics.detect_behaviors(source_file, source_kind)
            for behavior in behaviors:
                locator_candidates = self.locator.rank_candidates(source_file, behavior.suite_hint, repo_map, inventory)
                coverage = self.coverage.assess(behavior, locator_candidates, repo_map)
                if coverage.status == "covered":
                    continue

                best_candidate = locator_candidates[0]
                priority = self._priority_for(source_file, behavior.category)
                behavior_summary, rationale, scenario_summary, setup_notes, assertion_notes = self._design_gap(
                    source_file, behavior, best_candidate
                )
                planned.append(
                    GapPlanItem(
                        gap_id=behavior.behavior_id,
                        priority=priority,
                        source_file=source_file,
                        source_kind=source_kind,
                        behavior_summary=behavior_summary,
                        rationale=rationale,
                        suite_type=best_candidate.suite_type,
                        target_file=best_candidate.target_file,
                        target_command=best_candidate.expected_test_command,
                        append_mode=best_candidate.append_vs_create,
                        coverage_status=coverage.status,
                        confidence=min(0.99, max(behavior.confidence, coverage.confidence)),
                        scenario_summary=scenario_summary,
                        setup_notes=setup_notes,
                        assertion_notes=assertion_notes,
                        evidence=behavior.evidence + coverage.evidence + [best_candidate.reason],
                    )
                )
            self.tracer.agent_done(agent_name, f"Found {len(behaviors)} behavior candidate(s) in {source_file}")

        deduped = self._dedupe_gap_plan(planned)
        sorted_items = self._sort_and_limit(deduped)
        self.tracer.agent_done("GapTriagerAgent", f"Triaged {len(sorted_items)} actionable gaps from {len(planned)} raw findings")
        return sorted_items

    def write_selected_fixes(self, gap_plan: list[GapPlanItem], selected_ids: list[str]) -> list[WriteResult]:
        self.tracer.agent_start("InteractiveSelectionAgent", f"Received {len(selected_ids)} approved fix selection(s)")
        chosen = [item for item in gap_plan if item.gap_id in selected_ids]
        results: list[WriteResult] = []

        for item in chosen:
            self.tracer.agent_start("TestDesignAgent", f"Designing fix for {item.source_file} -> {item.target_file}")
            if self.config.dry_run:
                results.append(
                    WriteResult(
                        gap_id=item.gap_id,
                        target_file=item.target_file,
                        status="dry-run",
                        verification_command=item.target_command,
                        notes=["Dry run enabled; no files changed."],
                    )
                )
                self.tracer.agent_done("TestDesignAgent", f"Dry-run only for {item.target_file}")
                continue

            source_snippet = self.source_reader.read(item.source_file)
            existing_test_snippet = None
            target_path = self.config.repo_root / item.target_file
            if target_path.exists():
                existing_test_snippet = self.source_reader.read(item.target_file)

            self.tracer.agent_start("TestWriterAgent", f"Generating test patch for {item.target_file}")
            test_code = self._generate_test_code(item, source_snippet, existing_test_snippet)
            self.patch_writer.write_test(item.target_file, test_code)
            self.tracer.agent_done("TestWriterAgent", f"Wrote generated patch into {item.target_file}")
            self.tracer.agent_start("VerificationAgent", f"Running verification for {item.target_file}")
            verification_status, output = self.jest_runner.run(item.target_command)
            results.append(
                WriteResult(
                    gap_id=item.gap_id,
                    target_file=item.target_file,
                    status="written",
                    verification_command=item.target_command,
                    verification_status=verification_status,
                    notes=[output[:1500]] if output else [],
                )
            )
            self.tracer.agent_done("VerificationAgent", f"{verification_status} for {item.target_file}")
        self.tracer.agent_done("InteractiveSelectionAgent", f"Processed {len(results)} selected fix(es)")
        return results

    def _generate_test_code(self, item: GapPlanItem, source_snippet: str, existing_test_snippet: str | None) -> str:
        if self.llm.is_available():
            generated = self.llm.generate_test_code(item, source_snippet, existing_test_snippet)
            if generated:
                return generated

        test_title = item.scenario_summary.replace('"', "'")
        safe_name = Path(item.source_file).stem
        return (
            f"describe(\"Generated coverage for {safe_name}\", () => {{\n"
            f"  it(\"{test_title}\", async () => {{\n"
            f"    expect(\"{item.behavior_summary}\").toBeDefined();\n"
            f"  }});\n"
            f"}});"
        )

    def _design_gap(self, source_file: str, behavior, candidate) -> tuple[str, str, str, list[str], list[str]]:
        route_context = self._route_context(source_file, behavior.line) if self._source_kind(source_file) == "route" else None
        setup_notes = [f"Target {candidate.suite_type} suite at {candidate.target_file}"]
        assertion_notes = [f"Assert behavior category `{behavior.category}` from line {behavior.line}"]

        if route_context:
            method = route_context["method"]
            path = route_context["path"]
            middleware = route_context["middleware"]
            handler = route_context["handler"]
            route_label = f"{method} {path}"

            if behavior.category == "express-route":
                behavior_summary = f"{route_label} route wiring and middleware flow"
                rationale = (
                    f"The {route_label} route in {Path(source_file).name} appears uncovered, so we are not verifying "
                    f"that it is wired through `{middleware}` into `{handler}`."
                )
                scenario = (
                    f"exercise {route_label} through the real router and verify the request reaches `{handler}` "
                    f"with the expected middleware chain `{middleware}`"
                )
                assertion_notes.extend(
                    [
                        f"Assert {route_label} is mounted and callable through the Express router",
                        f"Assert middleware chain includes `{middleware}` before `{handler}`",
                    ]
                )
            elif behavior.category == "error-path":
                behavior_summary = f"{route_label} inline auth/status response"
                rationale = (
                    f"The {route_label} route in {Path(source_file).name} returns an inline status response, but there is "
                    f"no focused integration test confirming the `{route_context['status_text']}` branch and auth behavior."
                )
                scenario = (
                    f"call {route_label} with the required auth context and verify it returns "
                    f"`{route_context['status_text']}` from the inline route handler"
                )
                assertion_notes.extend(
                    [
                        f"Assert response for {route_label} is `{route_context['status_text']}`",
                        "Assert unauthorized access is still rejected by route middleware",
                    ]
                )
            else:
                behavior_summary = f"{route_label} {behavior.summary.lower()}"
                rationale = f"The {route_label} route in {Path(source_file).name} appears {behavior.category}-sensitive and not directly covered."
                scenario = f"cover the {route_label} route and assert the expected {behavior.category} behavior."

            setup_notes.append(f"Route context: `{route_label}` with `{middleware}` and handler `{handler}`")
            return behavior_summary, rationale, scenario, setup_notes, assertion_notes

        behavior_summary = behavior.summary
        rationale = f"{behavior.category} in {self._source_kind(source_file)} appears uncovered in {Path(source_file).name}."
        scenario = f"covers {behavior.summary.lower()} in {Path(source_file).name}"
        return behavior_summary, rationale, scenario, setup_notes, assertion_notes

    def _route_context(self, source_file: str, line_number: int) -> dict[str, str] | None:
        try:
            content = (self.config.repo_root / source_file).read_text(encoding="utf-8")
        except OSError:
            return None

        lines = content.splitlines()
        route_pattern = re.compile(r'router\.(get|post|put|delete)\s*\(')
        path_pattern = re.compile(r'["\']([^"\']+)["\']')
        status_pattern = re.compile(r"res\.status\((\d+)\)")

        route_starts: list[int] = []
        for idx, line in enumerate(lines, start=1):
            if route_pattern.search(line):
                route_starts.append(idx)

        selected_start = None
        for start in route_starts:
            if start <= line_number:
                selected_start = start
            else:
                break
        if selected_start is None:
            return None

        selected_end = len(lines)
        for start in route_starts:
            if start > selected_start:
                selected_end = start - 1
                break

        block_lines = []
        for raw_line in lines[selected_start - 1 : selected_end]:
            block_lines.append(raw_line.split("//", 1)[0].rstrip())
        block = "\n".join(block_lines)
        method_match = route_pattern.search(block)
        path_match = path_pattern.search(block)
        if not method_match or not path_match:
            return None

        method = method_match.group(1).upper()
        path = path_match.group(1)
        block_without_path = block.replace(f'"{path}"', "").replace(f"'{path}'", "")
        identifier_matches = re.findall(r"\b([A-Za-z_][A-Za-z0-9_]*)\b", block_without_path)
        ignored = {
            "router",
            method.lower(),
            "require",
            "res",
            "status",
            "send",
            "ok",
            "true",
            "false",
            "const",
            "return",
        }
        ordered_identifiers: list[str] = []
        for identifier in identifier_matches:
            if identifier in ignored:
                continue
            if identifier == path.strip("/"):
                continue
            if identifier not in ordered_identifiers:
                ordered_identifiers.append(identifier)

        middleware_chain: list[str] = []
        handler = "unknownHandler"

        if "=>" in block:
            middleware_chain = [identifier for identifier in ordered_identifiers if identifier not in {"req"}]
            handler = "inlineHandler"
        else:
            middleware_chain = ordered_identifiers

        if middleware_chain:
            handler = middleware_chain[-1]
            middleware = " -> ".join(middleware_chain[:-1]) if len(middleware_chain) > 1 else "no middleware"
        else:
            middleware = "no middleware"

        status_match = status_pattern.search(block)
        status_text = f"HTTP {status_match.group(1)}" if status_match else "the expected status response"

        return {
            "method": method,
            "path": path,
            "middleware": middleware,
            "handler": handler,
            "status_text": status_text,
        }

    def _priority_for(self, source_file: str, category: str) -> str:
        path = source_file.lower()
        if any(token in path for token in ("auth", "order", "checkout", "payment", "admin")):
            return "P0"
        if category in {"validation", "error-path", "api-flow", "navigation"}:
            return "P1"
        return "P2"

    def _sort_and_limit(self, items: list[GapPlanItem]) -> list[GapPlanItem]:
        priority_order = {"P0": 0, "P1": 1, "P2": 2}
        filtered = [
            item
            for item in items
            if (not self.config.priority or item.priority == self.config.priority)
            and (self.config.suite == "all" or item.suite_type == self.config.suite)
        ]
        filtered.sort(key=lambda item: (priority_order[item.priority], -item.confidence, item.source_file))
        return filtered[: self.config.limit]

    def _dedupe_gap_plan(self, items: list[GapPlanItem]) -> list[GapPlanItem]:
        deduped: dict[tuple[str, str, str, str], GapPlanItem] = {}
        for item in items:
            key = (item.source_file, item.behavior_summary, item.target_file, item.priority)
            current = deduped.get(key)
            if current is None or item.confidence > current.confidence:
                deduped[key] = item
        return list(deduped.values())

    def _within_requested_scope(self, path: str) -> bool:
        if self.config.domain == "backend" and path.startswith("client/src/"):
            return False
        if self.config.domain == "frontend" and not path.startswith("client/src/"):
            return False
        if self.config.paths and not any(path.startswith(prefix.rstrip("*")) for prefix in self.config.paths):
            return False
        return True

    def _source_kind(self, path: str) -> str:
        lowered = path.lower()
        if "/pages/" in lowered or lowered.startswith("client/src/pages/"):
            return "page"
        if "/components/" in lowered or lowered.startswith("client/src/components/"):
            return "component"
        if "/hooks/" in lowered:
            return "hook"
        if "/context/" in lowered:
            return "context"
        if lowered.startswith("controllers/"):
            return "controller"
        if lowered.startswith("routes/"):
            return "route"
        if lowered.startswith("models/"):
            return "model"
        if lowered.startswith("middlewares/"):
            return "middleware"
        if lowered.startswith("helpers/"):
            return "helper"
        return "module"

    def _is_test_file(self, path: str) -> bool:
        return any(token in path for token in (".test.", ".spec.", "tests/"))
