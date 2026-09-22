# Adversary-in-the-loop

Real-world AI agent security proving ground. Read, in order of authority:
`PROJECT_VISION.md` (intent), `PRD.md` (requirements), `ARCHITECTURE.md`
(architecture), `CLAUDE.md` (engineering rules).

## Development

Requirements: [uv](https://docs.astral.sh/uv/) 0.8.17, Python 3.11, Docker with Compose v2.

```sh
uv sync --locked                     # install the pinned environment
uv run --locked ruff format --check .
uv run --locked ruff check .
uv run --locked mypy                 # strict
uv run --locked pytest               # unit + Compose topology + secret-hygiene tests
```

Local stack (single-host profile, ARCHITECTURE.md §31):

```sh
deploy/secrets/generate.sh           # per-deployment secrets -> deploy/secrets/generated/ (git-ignored)
docker compose --env-file deploy/versions.env up
```

All images are pinned by digest in `deploy/versions.env`; Compose refuses to
start without it. The network topology in `docker-compose.yml` is a security
boundary and is verified by `tests/security/test_compose_topology.py`.
