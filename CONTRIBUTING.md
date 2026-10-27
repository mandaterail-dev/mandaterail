# Contributing to MandateRail

Thanks for helping improve MandateRail.

## Ground rules

1. **No secrets** — never commit `.env`, API keys, or private keys.
2. **Fail closed** — policy and facilitator clients must deny on error; never fake `/settle`.
3. **Do not vendor GoPlausible** — call its HTTP API only; do not clone that repo into this monorepo.
4. **Node 20+** and TypeScript throughout.
5. **Tests** — policy changes in `@mandaterail/core` need Vitest coverage (≥5 cases maintained).

## Setup

```bash
pnpm install
pnpm test
```

## Workspace layout

- `packages/*` — libraries
- `apps/*` — runnable demos
- `docs/*` — protocol and architecture

## Pull requests

- Keep PRs focused; update docs when changing wire formats.
- Run `pnpm test` before submitting.
- Prefer Apache-2.0 compatible contributions only.

## Code of conduct

Be respectful. This is infrastructure for delegated spend — clarity and safety beat cleverness.
