"""Runtime services connect only as their own least-privilege role (ARCHITECTURE.md §24).

Exercises aitl_common.db.engine against real PostgreSQL: every runtime role
can build an engine for itself; any mismatch, the NOLOGIN owner, or a role that
has gained elevated attributes is refused.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest
import yaml

from aitl_common.db.engine import (
    DatabaseSettings,
    RuntimeIdentityError,
    create_role_engine,
)
from tests.pg_harness import MIGRATOR_ROLE, OWNER_ROLE, RUNTIME_ROLES, Cluster


def _settings(pg: Cluster, db: str, user: str, password: str) -> DatabaseSettings:
    return DatabaseSettings(host=pg.host, port=pg.port, dbname=db, user=user, password=password)


@pytest.mark.parametrize("role", RUNTIME_ROLES)
def test_each_runtime_role_connects_as_itself(pg: Cluster, migrated_db: str, role: str) -> None:
    engine = create_role_engine(role, _settings(pg, migrated_db, role, pg.passwords[role]))
    engine.dispose()


def test_configured_user_must_equal_expected_role(pg: Cluster, migrated_db: str) -> None:
    settings = _settings(pg, migrated_db, "eval_svc", pg.passwords["eval_svc"])
    with pytest.raises(RuntimeIdentityError, match="not the expected role"):
        create_role_engine("gateway_svc", settings)


@pytest.mark.parametrize("identity", [OWNER_ROLE, MIGRATOR_ROLE, "postgres", "aitl_admin"])
def test_owner_and_admin_identities_refused(pg: Cluster, migrated_db: str, identity: str) -> None:
    with pytest.raises(RuntimeIdentityError, match="not a runtime role"):
        create_role_engine(identity, _settings(pg, migrated_db, identity, "irrelevant"))


@pytest.fixture
def elevated_eval_svc(pg: Cluster) -> Iterator[None]:
    with pg.admin() as conn:
        conn.execute("ALTER ROLE eval_svc CREATEDB")
    try:
        yield
    finally:
        with pg.admin() as conn:
            conn.execute("ALTER ROLE eval_svc NOCREATEDB")


def test_role_with_elevated_attributes_refused(
    pg: Cluster, migrated_db: str, elevated_eval_svc: None
) -> None:
    settings = _settings(pg, migrated_db, "eval_svc", pg.passwords["eval_svc"])
    with pytest.raises(RuntimeIdentityError, match="elevated privileges"):
        create_role_engine("eval_svc", settings)


def test_settings_from_env_reads_password_file(tmp_path: Path) -> None:
    secret = tmp_path / "pw"
    secret.write_text("s3cret-value\n")
    env = {
        "AITL_DB_HOST": "db",
        "AITL_DB_NAME": "aitl",
        "AITL_DB_USER": "intel_svc",
        "AITL_DB_PASSWORD_FILE": str(secret),
    }
    settings = DatabaseSettings.from_env(env)
    assert settings.user == "intel_svc"
    assert settings.port == 5432
    assert "s3cret-value" not in repr(settings)
    assert "s3cret-value" in settings.url()


@pytest.mark.parametrize("inline", ["AITL_DB_PASSWORD", "AITL_DB_DSN"])
def test_inline_credentials_refused(tmp_path: Path, inline: str) -> None:
    secret = tmp_path / "pw"
    secret.write_text("x")
    env = {
        "AITL_DB_HOST": "db",
        "AITL_DB_NAME": "aitl",
        "AITL_DB_USER": "intel_svc",
        "AITL_DB_PASSWORD_FILE": str(secret),
        inline: "leaked",
    }
    with pytest.raises(RuntimeIdentityError, match="inline database credentials"):
        DatabaseSettings.from_env(env)


def test_missing_setting_refused() -> None:
    with pytest.raises(RuntimeIdentityError, match="AITL_DB_HOST"):
        DatabaseSettings.from_env({})


# Ephemeral deployment jobs (ADR-022) are not runtime services; the db receives
# the migrator password only to create the role on first initialization.
DEPLOYMENT_JOBS = frozenset({"db-migrate"})
MIGRATOR_SECRET = "aitl_migrator_password"  # noqa: S105 - a secret name, not a value


def _secret_names(service: dict[str, object]) -> list[str]:
    names = []
    for entry in service.get("secrets") or []:  # type: ignore[attr-defined]
        names.append(str(entry["source"] if isinstance(entry, dict) else entry))
    return names


def test_no_runtime_service_receives_owner_or_migration_credentials() -> None:
    """What services are actually given (environment, secrets, commands), not comments."""
    repo = Path(__file__).resolve().parents[2]
    compose = yaml.safe_load((repo / "docker-compose.yml").read_text())
    runtime = {n: s for n, s in compose["services"].items() if n not in DEPLOYMENT_JOBS}
    assert runtime, "no runtime services found"
    for name, service in runtime.items():
        environment = service.get("environment") or {}
        items = (
            environment.items()
            if isinstance(environment, dict)
            else [tuple(str(entry).split("=", 1)) for entry in environment]
        )
        for key, value in items:
            assert "MIGRAT" not in str(key).upper(), f"{name}: {key}"
            assert OWNER_ROLE not in str(value), f"{name}: {key}"
            assert MIGRATOR_ROLE not in str(value), f"{name}: {key}"
        secrets = _secret_names(service)
        assert not any("owner" in s for s in secrets), name
        if name != "db":
            assert not any("migrat" in s for s in secrets), name
        command = " ".join(str(c) for c in service.get("command") or [])
        assert OWNER_ROLE not in command, name
        assert MIGRATOR_ROLE not in command, name


def test_migration_job_receives_only_the_migrator_credential() -> None:
    repo = Path(__file__).resolve().parents[2]
    compose = yaml.safe_load((repo / "docker-compose.yml").read_text())
    job = compose["services"]["db-migrate"]
    assert _secret_names(job) == [MIGRATOR_SECRET]
    assert job["environment"]["AITL_MIGRATION_USER"] == MIGRATOR_ROLE
    assert job["environment"]["AITL_MIGRATION_PASSWORD_FILE"] == f"/run/secrets/{MIGRATOR_SECRET}"
    assert not any("PASSWORD" in k and not k.endswith("_FILE") for k in job["environment"])
