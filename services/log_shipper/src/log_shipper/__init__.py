"""Log Shipper: the portless, one-way telemetry path (ARCHITECTURE.md §9; ADR-009).

Reads Cowrie JSON lines (live mode) or the version-controlled fixture corpus
(fixture mode), validates every line as hostile input, and inserts it into the
``intel_raw`` staging tables as the INSERT-only ``ingest_writer`` role. It
opens no listening socket and never interprets what an attacker typed.
"""
