from __future__ import annotations

import json
from textwrap import dedent

from .config import RuntimeConfig
from .schemas import GapPlanItem
from .tracing import ConsoleTracer


class OpenAILLM:
    def __init__(self, config: RuntimeConfig, tracer: ConsoleTracer | None = None) -> None:
        self.config = config
        self.tracer = tracer

    def is_available(self) -> bool:
        return bool(self.config.openai_api_key)

    def _client(self):
        if not self.config.openai_api_key:
            raise RuntimeError("OPENAI_API_KEY is required for LLM-backed generation.")
        from openai import OpenAI

        return OpenAI(api_key=self.config.openai_api_key)

    def supervisor_model(self) -> str:
        return self.config.supervisor_model

    def worker_model(self) -> str:
        return self.config.worker_model

    def generate_test_code(
        self,
        plan: GapPlanItem,
        source_snippet: str,
        existing_test_snippet: str | None,
    ) -> str:
        prompt = dedent(
            f"""
            You are generating one Jest test patch for a JavaScript full-stack application.
            Use model constraints appropriate for {self.worker_model()}.

            Return ONLY JavaScript test code, no markdown fences.

            Plan:
            {json.dumps(plan.to_dict(), indent=2)}

            Source snippet:
            {source_snippet}

            Existing target test snippet:
            {existing_test_snippet or "No existing file content."}

            Rules:
            - Preserve existing test style.
            - Write only one focused describe/it block for this gap.
            - Avoid placeholders like TODO.
            - Prefer deterministic mocks.
            """
        ).strip()

        if self.tracer:
            self.tracer.llm_call("WORKER", self.worker_model(), f"Generating test code for {plan.target_file}")
        response = self._client().responses.create(
            model=self.worker_model(),
            input=prompt,
        )
        output = (response.output_text or "").strip()
        if self.tracer:
            self.tracer.tool("OpenAILLM.generate_test_code", plan.target_file, "completed")
        return output
