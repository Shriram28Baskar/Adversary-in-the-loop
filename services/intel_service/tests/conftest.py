"""Fixtures for P4 unit tests."""

from __future__ import annotations

import pytest

from aitl_common.config.schemas.intel import PhaseRules
from tests.fixtures.cowrie_events import load_phase_rules


@pytest.fixture(scope="session")
def phase_rules() -> PhaseRules:
    return load_phase_rules()
