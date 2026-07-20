"""F8 — unit tests for the LangGraph synthesis topology.

These exercise the graph's control flow in isolation: the real phase logic is
replaced by fake steps that just record the route taken, so we verify the
StateGraph wiring (short-circuit, L2-fail, hunt/forensic gates, manager→gate)
without any DB / LLM / orchestrator import. The checkpointer is the real
MemorySaver, so a regression in graph compilation or checkpointing surfaces too.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from isoc_api.pipeline.synthesis_graph import _RUN, SynthSteps, build_synthesis_graph


@dataclass
class FakeCtx:
    short_circuit: bool = False
    l2_ok: bool = True
    hunt: bool = False
    forensics: bool = False
    calls: list[str] = field(default_factory=list)


def _fake_steps() -> SynthSteps:
    async def run_l1(session, incident, ctx):
        ctx.calls.append("l1")

    async def maybe_short_circuit(session, incident, ctx):
        ctx.calls.append("sc")
        return ctx.short_circuit

    async def run_l2(session, incident, ctx):
        ctx.calls.append("l2")
        return ctx.l2_ok

    def should_hunt(ctx):
        return ctx.hunt

    async def run_hunt(session, incident, ctx):
        ctx.calls.append("hunt")

    async def skip_hunt(session, incident):
        # session/incident are None in these tests; we record via the ctx var.
        _RUN.get()[2].calls.append("skip_hunt")

    def should_forensics(ctx):
        return ctx.forensics

    async def run_forensic(session, incident, ctx):
        ctx.calls.append("forensic")

    async def skip_forensic(session, incident):
        _RUN.get()[2].calls.append("skip_forensic")

    async def run_manager(session, incident, ctx):
        ctx.calls.append("manager")

    return SynthSteps(
        run_l1=run_l1,
        maybe_short_circuit=maybe_short_circuit,
        run_l2=run_l2,
        should_hunt=should_hunt,
        run_hunt=run_hunt,
        skip_hunt=skip_hunt,
        should_forensics=should_forensics,
        run_forensic=run_forensic,
        skip_forensic=skip_forensic,
        run_manager=run_manager,
    )


async def _drive(ctx: FakeCtx) -> FakeCtx:
    graph = build_synthesis_graph(_fake_steps())
    token = _RUN.set((None, None, ctx))
    try:
        await graph.ainvoke({}, config={"configurable": {"thread_id": "t"}})
    finally:
        _RUN.reset(token)
    return ctx


async def test_full_path_hunt_and_forensics():
    ctx = await _drive(FakeCtx(hunt=True, forensics=True))
    assert ctx.calls == ["l1", "sc", "l2", "hunt", "forensic", "manager"]


async def test_short_circuit_stops_after_l1():
    ctx = await _drive(FakeCtx(short_circuit=True))
    assert ctx.calls == ["l1", "sc"]  # no l2/hunt/forensic/manager


async def test_l2_failure_stops_before_hunt():
    ctx = await _drive(FakeCtx(l2_ok=False, hunt=True, forensics=True))
    assert ctx.calls == ["l1", "sc", "l2"]  # failed → END


async def test_no_hunt_no_forensics_goes_straight_to_manager():
    ctx = await _drive(FakeCtx(hunt=False, forensics=False))
    assert ctx.calls == ["l1", "sc", "l2", "skip_hunt", "skip_forensic", "manager"]


async def test_no_hunt_but_forensics():
    ctx = await _drive(FakeCtx(hunt=False, forensics=True))
    assert ctx.calls == ["l1", "sc", "l2", "skip_hunt", "forensic", "manager"]


async def test_hunt_but_no_forensics():
    ctx = await _drive(FakeCtx(hunt=True, forensics=False))
    assert ctx.calls == ["l1", "sc", "l2", "hunt", "skip_forensic", "manager"]


async def test_graph_has_expected_nodes():
    graph = build_synthesis_graph(_fake_steps())
    nodes = set(graph.get_graph().nodes)
    for n in ("l1", "l2", "hunt", "forensic", "manager"):
        assert n in nodes
