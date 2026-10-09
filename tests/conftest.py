"""Shared fixtures for database tests (see tests/pg_harness.py)."""

from __future__ import annotations

import secrets
from collections.abc import Iterator

import pytest

from tests.pg_harness import Cluster, cluster


@pytest.fixture(scope="session")
def pg() -> Iterator[Cluster]:
    with cluster() as disposable:
        yield disposable


@pytest.fixture(scope="session")
def migrated_db(pg: Cluster) -> Iterator[str]:
    """A database created from empty and upgraded to head, shared by read-mostly tests."""
    name = f"aitl_test_{secrets.token_hex(4)}"
    pg.create_database(name)
    pg.upgrade(name)
    yield name
    pg.drop_database(name)


@pytest.fixture
def fresh_db(pg: Cluster) -> Iterator[str]:
    """An empty database with roles bootstrapped but no migrations applied."""
    name = f"aitl_fresh_{secrets.token_hex(4)}"
    pg.create_database(name)
    yield name
    pg.drop_database(name)
