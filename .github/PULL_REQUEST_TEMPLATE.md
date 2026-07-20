<!--
Thanks for contributing to EKSIR! Fill in the sections below.
PRs are squash-merged into main, so this PR's title becomes the commit message.
Use a clear, conventional-commit-style title (e.g. "feat(defender): add blocklist action").
-->

## Summary

<!-- What does this change do, and why? One or two paragraphs. -->

## Linked issue

<!-- e.g. "Closes #123". Use "Closes"/"Fixes" so the issue auto-closes on merge. -->

Closes #

## Type of change

- [ ] Bug fix (non-breaking change that fixes an issue)
- [ ] New feature (non-breaking change that adds functionality)
- [ ] Breaking change (fix or feature that changes existing behavior or API)
- [ ] Docs only
- [ ] Refactor / internal (no user-visible change)
- [ ] Deploy / CI / tooling

## Test evidence

<!-- Show what you ran. Paste command output or summarize results. -->

Backend (from `backend/`):

- [ ] `ruff check isoc_api` passes
- [ ] `mypy isoc_api` clean (or unchanged)
- [ ] `pytest -q` passes (note: CI does not run the backend tests, so this is on you)

Frontend (from `frontend/`, if touched):

- [ ] `npm run lint` passes
- [ ] `npm run type` passes
- [ ] `npm run build` passes

```
<!-- paste relevant test / lint output here -->
```

## Checklist

- [ ] `CHANGELOG.md` updated under `## [Unreleased]` (or this change is not user-visible)
- [ ] No secrets, credentials, API keys, or real customer data added anywhere (detect-secrets passed; only synthetic names like acme / contoso / fabrikam / example.com used)
- [ ] Docs updated if behavior, config, or deploy steps changed
- [ ] I rebuilt the backend/worker image locally if I changed backend code (source is baked into the image, not host-mounted)
- [ ] This PR does not report or introduce a security vulnerability (those follow SECURITY.md)
