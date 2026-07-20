"""F8 — LangGraph orchestration of the persona synthesis.

This module owns ONLY the control flow + checkpointing. The actual work of each
persona stage lives in ``synthesis_steps`` and is injected as a ``SynthSteps``
bundle, so this graph is unit-testable in isolation (no DB / LLM / orchestrator
import needed — tests pass fake steps).

Topology (mirrors the legacy ``_step_synthesis`` exactly):

    START → l1 ─┬─(short-circuit FP/benign)─────────────► END
                └─► l2 ─┬─(L2 failed)──────────────────► END
                        ├─(hunt warranted)─► hunt ─┬─► forensic ─► manager ─► END
                        ├─(forensic only)─────────► forensic ─► manager ─► END
                        └─(neither)───────────────────────────► manager ─► END

Runtime objects (the live SQLAlchemy session, the Incident, and the in-memory
SynthCtx) are passed through a ``contextvars.ContextVar`` rather than the graph
state, so the checkpointer only ever serializes the tiny routing dict
(``{"route": ...}``) — never a DB session.

Checkpointer: ``MemorySaver`` by default. A durable, resumable
``AsyncPostgresSaver`` (the prerequisite for making the human gate a true
graph ``interrupt`` that resumes on Approve) is a documented follow-up — it
needs the ``langgraph-checkpoint-postgres`` package + a DSN and can only be
verified against a real Postgres, so it is intentionally not wired here.
"""

from __future__ import annotations

import contextvars
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, TypedDict

from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import END, START, StateGraph

from ..logging_config import get_logger
from ..settings import settings

logger = get_logger("isoc.pipeline.graph")


class SynthState(TypedDict, total=False):
    """The only thing the checkpointer serializes — the next route to take."""

    route: str


# The per-run runtime objects (session, incident, ctx). Set just before
# ``ainvoke`` and read inside every node. A ContextVar (not graph state) keeps
# unserializable objects out of the checkpoint.
_RUN: contextvars.ContextVar[tuple[Any, Any, Any]] = contextvars.ContextVar("isoc_synth_run")


# Each step is an async callable. Injected so the graph has no hard dependency
# on the real (DB/LLM-touching) implementations and can be tested with fakes.
StepFn = Callable[[Any, Any, Any], Awaitable[Any]]
PredFn = Callable[[Any], bool]


@dataclass(frozen=True)
class SynthSteps:
    run_l1: StepFn
    maybe_short_circuit: StepFn  # returns True if it short-circuited (→ END)
    run_l2: StepFn  # returns False if L2 failed (→ END)
    should_hunt: PredFn
    run_hunt: StepFn
    skip_hunt: StepFn
    should_forensics: PredFn
    run_forensic: StepFn
    skip_forensic: StepFn
    run_manager: StepFn


def build_synthesis_graph(steps: SynthSteps, checkpointer: Any | None = None):
    """Compile the synthesis StateGraph over ``steps``.

    Nodes are closures over ``steps`` and read the live (session, incident, ctx)
    from the ``_RUN`` ContextVar.
    """

    async def l1_node(state: SynthState) -> SynthState:
        session, incident, ctx = _RUN.get()
        await steps.run_l1(session, incident, ctx)
        if await steps.maybe_short_circuit(session, incident, ctx):
            return {"route": "end"}
        return {"route": "l2"}

    async def l2_node(state: SynthState) -> SynthState:
        session, incident, ctx = _RUN.get()
        ok = await steps.run_l2(session, incident, ctx)
        if not ok:
            return {"route": "end"}
        if steps.should_hunt(ctx):
            return {"route": "hunt"}
        await steps.skip_hunt(session, incident)
        if steps.should_forensics(ctx):
            return {"route": "forensic"}
        await steps.skip_forensic(session, incident)
        return {"route": "manager"}

    async def hunt_node(state: SynthState) -> SynthState:
        session, incident, ctx = _RUN.get()
        await steps.run_hunt(session, incident, ctx)
        if steps.should_forensics(ctx):
            return {"route": "forensic"}
        await steps.skip_forensic(session, incident)
        return {"route": "manager"}

    async def forensic_node(state: SynthState) -> SynthState:
        session, incident, ctx = _RUN.get()
        await steps.run_forensic(session, incident, ctx)
        return {"route": "manager"}

    async def manager_node(state: SynthState) -> SynthState:
        session, incident, ctx = _RUN.get()
        await steps.run_manager(session, incident, ctx)
        return {"route": "end"}

    def _route(state: SynthState) -> str:
        return state.get("route", "end")

    g: StateGraph = StateGraph(SynthState)
    g.add_node("l1", l1_node)
    g.add_node("l2", l2_node)
    g.add_node("hunt", hunt_node)
    g.add_node("forensic", forensic_node)
    g.add_node("manager", manager_node)

    g.add_edge(START, "l1")
    g.add_conditional_edges("l1", _route, {"l2": "l2", "end": END})
    g.add_conditional_edges(
        "l2", _route, {"hunt": "hunt", "forensic": "forensic", "manager": "manager", "end": END}
    )
    g.add_conditional_edges("hunt", _route, {"forensic": "forensic", "manager": "manager"})
    g.add_edge("forensic", "manager")
    g.add_edge("manager", END)

    return g.compile(checkpointer=checkpointer or MemorySaver())


def _make_checkpointer() -> Any:
    """Resolve the checkpointer from settings.

    ``memory`` → in-process MemorySaver (default). ``postgres`` is reserved for
    the durable AsyncPostgresSaver follow-up; until that's wired we log and fall
    back to MemorySaver so a misconfig can't break synthesis.
    """
    backend = (settings.isoc_langgraph_checkpointer or "memory").lower()
    if backend == "postgres":
        logger.warning(
            "synthesis_graph.postgres_checkpointer_not_wired",
            detail="falling back to MemorySaver — durable checkpointing is a follow-up",
        )
    return MemorySaver()


_COMPILED: Any | None = None


def _compiled() -> Any:
    """Lazily build + cache the compiled graph with the REAL steps."""
    global _COMPILED  # noqa: PLW0603
    if _COMPILED is None:
        from . import synthesis_steps as st

        steps = SynthSteps(
            run_l1=st.run_l1,
            maybe_short_circuit=st.maybe_short_circuit,
            run_l2=st.run_l2,
            should_hunt=st.should_hunt,
            run_hunt=st.run_hunt,
            skip_hunt=st.skip_hunt,
            should_forensics=st.should_forensics,
            run_forensic=st.run_forensic,
            skip_forensic=st.skip_forensic,
            run_manager=st.run_manager,
        )
        _COMPILED = build_synthesis_graph(steps, _make_checkpointer())
    return _COMPILED


async def run_synthesis_graph(session: Any, incident: Any, *, force_deep: bool = False) -> None:
    """Graph-driven equivalent of the legacy ``_step_synthesis`` body.

    Builds the SynthCtx, binds the runtime objects into the ContextVar, and runs
    the compiled graph to the human gate (AWAITING_SIGNOFF) or a terminal state.
    """
    from . import synthesis_steps as st

    ctx = await st.build_synth_ctx(session, incident, force_deep)
    token = _RUN.set((session, incident, ctx))
    try:
        graph = _compiled()
        await graph.ainvoke(
            {},
            config={"configurable": {"thread_id": str(incident.id)}},
        )
    finally:
        _RUN.reset(token)
