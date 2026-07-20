# Contributing to EKSIR

Thanks for your interest in improving EKSIR (repo codename `isoc`). This guide
covers how to get a local environment running, the checks your change must pass,
and how to get a pull request merged.

By participating you agree to abide by our
[Code of Conduct](./CODE_OF_CONDUCT.md). Found a security issue? Do **not** open a
public issue: follow [SECURITY.md](./SECURITY.md) instead.

## No CLA, no DCO

There is **no Contributor License Agreement and no Developer Certificate of Origin
sign-off required.** By opening a pull request you agree that your contribution is
licensed under the project's [Apache-2.0](./LICENSE) license. That is all.

## Prerequisites

- **Docker** with Docker Compose (for running the full stack; allocate ≥8 GiB to
  Docker if you use the REMnux forensics profile).
- **Python 3.11+** for backend work.
- **Node.js 20+** for frontend and landing work.
- **git** and a GitHub account for the fork/PR flow.

You do not need the full stack running to work on most of the backend: the test
suite is pure unit tests (see below).

## Local development setup

### Backend (`backend/`)

A virtualenv already exists at `backend/.venv`; create one if it does not.

```bash
cd backend
python -m venv .venv           # if you don't already have backend/.venv
source .venv/bin/activate
pip install -e ".[dev]"        # one-time; installs runtime + dev tooling
```

### Frontend (`frontend/`)

A `package-lock.json` is committed, so install with the lockfile. The
`--legacy-peer-deps` flag is required.

```bash
cd frontend
npm install --legacy-peer-deps
npm run dev                     # dev server on :3000
```

The landing site under `landing/` follows the same npm workflow.

### Running the full stack (optional)

From `deploy/`:

```bash
docker compose up -d                          # core services
docker compose --profile forensics up -d --build   # + REMnux (large, first build is slow)
docker compose --profile gpu up -d            # + vLLM
```

Access the UI through Caddy at **http://localhost** (port 80), not `:3000`.

> **Backend source is baked into the image, not host-mounted.** After changing
> any backend or worker code, rebuild and restart:
>
> ```bash
> cd deploy
> docker compose build backend worker && docker compose up -d backend worker
> ```
>
> Frontend changes also need `frontend` rebuilt.

## Checks your change must pass

Run these locally before pushing. CI runs lint and type-check and the frontend
build on every PR, but **CI does not run the backend tests**, so you must run
`pytest` yourself.

### Backend (from `backend/`)

```bash
ruff check isoc_api            # lint (CI gate); autofix with: ruff check --fix isoc_api
ruff format isoc_api           # formatter
mypy isoc_api                  # type-check (non-blocking in CI, but keep it clean)
pytest -q                      # ~681 pure unit tests
```

The tests are **pure unit tests**: they import `isoc_api.*` directly and need no
Postgres, Redis, Qdrant, or LLM. They run on the host without the stack up.
`asyncio_mode=auto`, so no `@pytest.mark.asyncio` decorators are needed. Useful
subsets:

```bash
pytest tests/test_scoring.py                    # one file
pytest tests/test_ioc_extract.py::test_clean_url_unchanged   # one test
pytest -k agent_pipeline                        # by keyword
```

Before touching a line that ruff flags, check `[tool.ruff.lint]` in
`backend/pyproject.toml`: several rules (`E501`, `B008`, `B904`, and others) are
intentionally ignored.

### Frontend (from `frontend/`)

```bash
npm run lint
npm run type                   # tsc --noEmit
npm run build
```

## Pre-commit and the secret gate

Install the hooks once:

```bash
pre-commit install
```

Every commit is then gated by **ruff**, **ruff-format**, and **detect-secrets**.
The detect-secrets hook blocks committing keys, tokens, and other credentials.
Run the whole suite manually with `pre-commit run --all-files`. You can bypass
hooks with `git commit --no-verify`, but do not use that to sneak past the secret
scanner: **no secrets and no real customer data belong in this repo.** Use only
synthetic example names (`acme`, `contoso`, `fabrikam`, `example.com`) in code,
tests, docs, and fixtures.

## Branch and pull-request flow

1. **Fork** the repository to your account.
2. Create a **topic branch** off `main` (for example `feat/defender-blocklist` or
   `fix/webhook-skew`).
3. Make your change. Add or update tests. Update
   [`CHANGELOG.md`](./CHANGELOG.md) under `## [Unreleased]` for any user-visible
   change (see the "How to use this file" note at the top of that file for what
   counts).
4. Run the checks above.
5. Open a **pull request into `main`** and fill in the
   [pull request template](./.github/PULL_REQUEST_TEMPLATE.md). Link the issue it
   closes.

PRs are reviewed and then **squash-merged into `main`**, so the PR title becomes
the commit on `main`: make it a clear, conventional summary.

## Commit and PR message expectations

- Write in the imperative mood: "add Defender blocklist action", not "added" or
  "adds".
- We use Conventional-Commit-style prefixes on merged commits (`feat:`, `fix:`,
  `docs:`, `refactor:`, `chore:`, optionally scoped like `feat(defender): ...`).
  Look at recent history for the pattern.
- Keep the subject under ~72 characters; put detail in the body.
- **Do not add `Co-Authored-By` / "Generated with" trailers.** Plain messages
  only.
- Because merges are squashed, the individual commit messages on your branch are
  less important than a clean PR title and description.

## Where things live

Start with [`CLAUDE.md`](./CLAUDE.md) at the repo root and the `docs/` directory:
`docs/DESIGN.md`, `docs/PIPELINE.md`, and the `docs/ADR-*.md` records explain the
architecture and the key decisions. The `CLAUDE.md` "Where things live" section
maps the backend package layout.

## Questions

Open a **GitHub Discussion** or email **hello@eksir.com**. For anything that could
be a vulnerability, use [SECURITY.md](./SECURITY.md) instead of a public channel.
