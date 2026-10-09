"""Container health check: ``python -m log_shipper.health``.

The shipper is portless, so health is the freshness of its last *committed*
heartbeat (ARCHITECTURE.md §9; NFR-008), recorded in its private state
volume. If the database is unreachable no heartbeat commits and the check
fails. Exit 0 healthy, 1 unhealthy.
"""

from __future__ import annotations

import json
import os
import sys
from datetime import UTC, datetime
from pathlib import Path

from log_shipper.config import ConfigError, ShipperSettings
from log_shipper.service import HEALTH_FILE


def healthy(state_dir: Path, heartbeat_seconds: int, now: datetime) -> bool:
    try:
        record = json.loads((state_dir / HEALTH_FILE).read_text(encoding="utf-8"))
        last = datetime.fromisoformat(record["last_heartbeat"])
    except (OSError, ValueError, KeyError, TypeError):
        return False
    if last.tzinfo is None:
        return False
    age = (now - last.astimezone(UTC)).total_seconds()
    return -60 <= age <= 3 * heartbeat_seconds


def main() -> int:
    try:
        settings = ShipperSettings.from_env(os.environ)
    except ConfigError:
        return 1
    return 0 if healthy(settings.state_dir, settings.heartbeat_seconds, datetime.now(UTC)) else 1


if __name__ == "__main__":
    sys.exit(main())
