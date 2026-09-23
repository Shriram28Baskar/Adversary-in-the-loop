# Ephemeral database migration job image (ADR-022).
#
# Contains only the pinned migration dependencies (Alembic, SQLAlchemy,
# psycopg; hash-verified from deploy/migrate/requirements.txt, exported from the
# uv lockfile's `migrate` group) and the migrations directory. No application
# code, no server, no listening port. Runs as an unprivileged user and exits.
FROM python:3.11.15-slim-bookworm@sha256:d29f48a31a8b408ed19272ca1e7b10ebae13b240a27e862d3d4217c528e2e0c3

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

COPY deploy/migrate/requirements.txt /tmp/requirements.txt
RUN pip install --require-hashes --no-deps --only-binary=:all: -r /tmp/requirements.txt \
    && rm /tmp/requirements.txt

COPY migrations /opt/aitl/migrations

USER 65534:65534
WORKDIR /opt/aitl
ENTRYPOINT ["python", "/opt/aitl/migrations/job.py"]
