"""Case-number prefix rename — disambiguate incidents from customer cases.

The two identifiers used to look alike: incidents `CASE-000123`, customer cases
`CCASE-000123`. New convention (aligned with the sidebar tabs):
    incidents       →  INC-<seq>
    customer cases  →  CASE-<seq>

This runs every boot and is idempotent:
  1. Re-point the column DEFAULTs (the model server_default only takes effect on a
     brand-new column via create_all; an existing DB keeps its old default).
  2. Renumber existing rows still on the old prefix — a bijective prefix swap that
     preserves the unique numeric suffix, so the UNIQUE constraint always holds.
The `WHERE ... LIKE 'old-%'` guards make re-runs no-ops. Historical snapshots that
embedded a number (audit diffs, generated report bodies) are left untouched.
"""

from __future__ import annotations

from sqlalchemy import text as sql_text
from sqlalchemy.ext.asyncio import AsyncEngine

from ..logging_config import get_logger

logger = get_logger("isoc.case_number.backfill")


async def rename_case_number_prefixes(engine: AsyncEngine) -> None:
    async with engine.begin() as conn:
        # 1) Column defaults for future inserts.
        await conn.execute(
            sql_text(
                "ALTER TABLE incidents ALTER COLUMN case_number "
                "SET DEFAULT ('INC-' || lpad(nextval('isoc_case_seq')::text, 6, '0'))"
            )
        )
        await conn.execute(
            sql_text(
                "ALTER TABLE customer_cases ALTER COLUMN case_number "
                "SET DEFAULT ('CASE-' || lpad(nextval('eksir_customer_case_seq')::text, 6, '0'))"
            )
        )
        # 2) Renumber existing rows (idempotent via the LIKE guard). 'CASE-' is 5
        #    chars, 'CCASE-' is 6 — substring keeps the numeric suffix verbatim.
        await conn.execute(
            sql_text(
                "UPDATE incidents SET case_number = 'INC-' || substring(case_number from 6) "
                "WHERE case_number LIKE 'CASE-%'"
            )
        )
        await conn.execute(
            sql_text(
                "UPDATE customer_cases SET case_number = 'CASE-' || substring(case_number from 7) "
                "WHERE case_number LIKE 'CCASE-%'"
            )
        )
    logger.info("case_number.prefixes_renamed")
