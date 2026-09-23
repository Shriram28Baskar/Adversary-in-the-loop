"""Entry point: ``python -m log_shipper``. No listener, no arguments.

Exit codes: 2 configuration error (the service refuses to start); otherwise the
loop runs until SIGTERM/SIGINT.
"""

from __future__ import annotations

import logging
import os
import signal
import sys
import threading

from aitl_common.db.engine import DatabaseSettings, RuntimeIdentityError, create_role_engine
from aitl_common.logging import configure_logging, log_event
from log_shipper.config import ConfigError, ShipperSettings
from log_shipper.service import Shipper
from log_shipper.writer import INGEST_ROLE, StagingWriter

_log = logging.getLogger("log_shipper")


def main() -> int:
    configure_logging()
    try:
        settings = ShipperSettings.from_env(os.environ)
        engine = create_role_engine(INGEST_ROLE, DatabaseSettings.from_env(os.environ))
    except (ConfigError, RuntimeIdentityError) as exc:
        log_event(_log, logging.ERROR, "shipper.config_error", error=str(exc))
        return 2
    stop = threading.Event()
    for signum in (signal.SIGTERM, signal.SIGINT):
        signal.signal(signum, lambda *_: stop.set())
    log_event(_log, logging.INFO, "shipper.started", mode=settings.mode)

    def sleep(seconds: float) -> None:
        stop.wait(seconds)  # wakes immediately on shutdown

    Shipper(settings, StagingWriter(engine), sleep=sleep).run_forever(stop.is_set)
    log_event(_log, logging.INFO, "shipper.stopped", mode=settings.mode)
    return 0


if __name__ == "__main__":
    sys.exit(main())
