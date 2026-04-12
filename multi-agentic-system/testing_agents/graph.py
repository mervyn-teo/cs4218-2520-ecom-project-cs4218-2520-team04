from __future__ import annotations

from .agents import AgentRuntime
from .state import GraphState


def _langgraph_import():
    try:
        from langgraph.graph import END, START, StateGraph
    except ImportError as exc:
        raise RuntimeError(
            "LangGraph is not installed. Run `uv sync` inside multi-agentic-system before using the CLI."
        ) from exc
    return START, END, StateGraph


def build_analyze_graph(runtime: AgentRuntime):
    START, END, StateGraph = _langgraph_import()
    graph = StateGraph(GraphState)

    def repo_cartographer(state: GraphState) -> GraphState:
        runtime.tracer.supervisor("Calling subagent RepoCartographerAgent")
        repo_map = runtime.build_repo_map()
        runtime.artifacts.write_json("repo_map.json", repo_map.to_dict())
        return {"repo_map": repo_map}

    def inventory_agent(state: GraphState) -> GraphState:
        runtime.tracer.supervisor("Calling subagent TestInventoryAgent")
        inventory = runtime.build_test_inventory(state["repo_map"])
        runtime.artifacts.write_json("test_inventory.json", inventory.to_dict())
        return {"test_inventory": inventory}

    def analyze_agent(state: GraphState) -> GraphState:
        runtime.tracer.supervisor("Calling subagents BackendGapAnalystAgent, FrontendGapAnalystAgent, GapTriagerAgent")
        gap_plan = runtime.analyze_gaps(state["repo_map"], state["test_inventory"])
        runtime.artifacts.write_json("gap_plan.json", [item.to_dict() for item in gap_plan])
        return {"gap_plan": gap_plan}

    graph.add_node("repo_cartographer", repo_cartographer)
    graph.add_node("test_inventory", inventory_agent)
    graph.add_node("analyze", analyze_agent)
    graph.add_edge(START, "repo_cartographer")
    graph.add_edge("repo_cartographer", "test_inventory")
    graph.add_edge("test_inventory", "analyze")
    graph.add_edge("analyze", END)
    return graph.compile()


def build_write_graph(runtime: AgentRuntime):
    START, END, StateGraph = _langgraph_import()
    graph = StateGraph(GraphState)

    def writer_agent(state: GraphState) -> GraphState:
        runtime.tracer.supervisor("Calling subagents InteractiveSelectionAgent, TestDesignAgent, TestWriterAgent, VerificationAgent")
        write_results = runtime.write_selected_fixes(state["gap_plan"], state["selected_gap_ids"])
        runtime.artifacts.write_json("write_report.json", [item.to_dict() for item in write_results])
        return {"write_results": write_results}

    graph.add_node("write", writer_agent)
    graph.add_edge(START, "write")
    graph.add_edge("write", END)
    return graph.compile()
