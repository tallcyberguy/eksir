"""Feature 7 — branded automated per-customer reports.

Layering (pure → impure):
  periods.py   pure date/period + schedule-due math (unit-tested)
  registry.py  built-in template metadata (which sections each shows)
  data.py      pure build_report_context / section selection (unit-tested)
  gather.py    async DB aggregation — reuses feature-6 trends + the monthly
               summary + feature-4's confirmed-IOC selection
  render.py    Jinja HTML + lazy-imported WeasyPrint PDF

The scheduler (worker.report_generate) only ever generates to a DRAFT
GeneratedReport; delivery stays analyst-gated (routes/reports.py::send).
"""
