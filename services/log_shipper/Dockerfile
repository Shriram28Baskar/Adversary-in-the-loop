# Log Shipper image (ARCHITECTURE.md §9; PRD FR-004b, FR-005).
#
# Hash-locked dependencies exported from uv.lock (services/log_shipper/
# requirements.txt) plus the aitl_common and log_shipper sources. No server,
# no EXPOSE, no listening port: the shipper only reads a read-only directory
# and INSERTs into intel_raw as ingest_writer. Runs as an unprivileged user.
FROM python:3.11.15-slim-bookworm@sha256:d29f48a31a8b408ed19272ca1e7b10ebae13b240a27e862d3d4217c528e2e0c3

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONPATH=/opt/aitl/src

COPY services/log_shipper/requirements.txt /tmp/requirements.txt
RUN pip install --require-hashes --no-deps --only-binary=:all: -r /tmp/requirements.txt \
    && rm /tmp/requirements.txt

COPY packages/aitl_common/src/aitl_common /opt/aitl/src/aitl_common
COPY services/log_shipper/src/log_shipper /opt/aitl/src/log_shipper

# Mount point of the shipper's private position/health volume; a fresh named
# volume inherits this ownership, so the unprivileged user can write it.
RUN mkdir -p /srv/aitl/state && chown 65534:65534 /srv/aitl/state && chmod 0700 /srv/aitl/state

USER 65534:65534
WORKDIR /opt/aitl
ENTRYPOINT ["python", "-m", "log_shipper"]
