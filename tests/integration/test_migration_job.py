"""Ephemeral migration job (ADR-022; ARCHITECTURE.md §24, §31) against real PostgreSQL.

The job (``migrations/job.py``, the entrypoint of the db-migrate image) is run
in-process via ``main(env)`` exactly as the container would run it, connecting
as the deployment role ``aitl_migrator`` with its password read from a file.

Covers: migrating from empty as the migrator; idempotent re-runs; the result
being catalog-identical to the reference migration path; every failure mode
producing a distinct non-zero exit; the post-migration security check; the
migrator/owner/runtime credential separation; and that the job never listens
or logs a credential. Container-level facts (network attachment, profile, no
ports) are asserted on the rendered Compose file in
tests/security/test_compose_topology.py.
"""

from __future__ import annotations

import ast
import importlib.util
import secrets
import socket
from collections.abc import Iterator
from pathlib import Path
from types import ModuleType

import psycopg
import pytest

from tests.pg_harness import MIGRATOR_ROLE, OWNER_ROLE, RUNTIME_ROLES, Cluster

REPO_ROOT = Path(__file__).resolve().parents[2]
JOB_PATH = REPO_ROOT / "migrations" / "job.py"
APP_SCHEMAS = ("intel_raw", "intel", "agent", "security", "eval", "ops")
DENIED = "42501"


def _load_job() -> ModuleType:
    spec = importlib.util.spec_from_file_location("aitl_migration_job", JOB_PATH)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


job = _load_job()


def _env(pg: Cluster, dbname: str, password_file: Path, **overrides: str) -> dict[str, str]:
    env = {
        "AITL_DB_HOST": pg.host,
        "AITL_DB_PORT": str(pg.port),
        "AITL_DB_NAME": dbname,
        "AITL_MIGRATION_USER": MIGRATOR_ROLE,
        "AITL_MIGRATION_PASSWORD_FILE": str(password_file),
        "AITL_MIGRATION_WAIT_SECONDS": "5",
    }
    env.update(overrides)
    return env


@pytest.fixture
def password_file(pg: Cluster, tmp_path: Path) -> Path:
    path = tmp_path / "aitl_migrator_password"
    path.write_text(pg.passwords[MIGRATOR_ROLE] + "\n")
    return path


def _snapshot(pg: Cluster, dbname: str) -> dict[str, list[tuple[object, ...]]]:
    """Ownership, ACLs, triggers and functions of every application object."""
    schemas = list(APP_SCHEMAS)
    queries = {
        "schemas": (
            "SELECT nspname, pg_get_userbyid(nspowner), coalesce(nspacl::text, '') "
            "FROM pg_namespace WHERE nspname = ANY(%s) ORDER BY 1"
        ),
        "relations": (
            "SELECT n.nspname, c.relname, c.relkind::text, pg_get_userbyid(c.relowner), "
            "coalesce(c.relacl::text, '') FROM pg_class c "
            "JOIN pg_namespace n ON n.oid = c.relnamespace "
            "WHERE n.nspname = ANY(%s) ORDER BY 1, 2"
        ),
        "column_acls": (
            "SELECT c.oid::regclass::text, a.attname, a.attacl::text FROM pg_attribute a "
            "JOIN pg_class c ON c.oid = a.attrelid JOIN pg_namespace n ON n.oid = c.relnamespace "
            "WHERE n.nspname = ANY(%s) AND a.attacl IS NOT NULL ORDER BY 1, 2"
        ),
        "triggers": (
            "SELECT t.tgrelid::regclass::text, t.tgname, t.tgenabled::text FROM pg_trigger t "
            "JOIN pg_class c ON c.oid = t.tgrelid JOIN pg_namespace n ON n.oid = c.relnamespace "
            "WHERE n.nspname = ANY(%s) AND NOT t.tgisinternal ORDER BY 1, 2"
        ),
        "functions": (
            "SELECT n.nspname, p.proname, pg_get_userbyid(p.proowner), "
            "coalesce(p.proacl::text, ''), p.prosecdef FROM pg_proc p "
            "JOIN pg_namespace n ON n.oid = p.pronamespace "
            "WHERE n.nspname = ANY(%s) ORDER BY 1, 2"
        ),
        "public_types": (
            "SELECT t.typname, pg_get_userbyid(t.typowner) FROM pg_type t "
            "JOIN pg_namespace n ON n.oid = t.typnamespace "
            "WHERE n.nspname = 'public' AND t.typtype IN ('e', 'd') ORDER BY 1"
        ),
        "database": (
            "SELECT pg_get_userbyid(datdba), "
            "has_database_privilege('public', datname, 'CONNECT'), "
            "regexp_replace(coalesce(datacl::text, ''), 'aitl_[a-z0-9_]+=', '', 'g') "
            "FROM pg_database WHERE datname = current_database()"
        ),
        "version": ("SELECT version_num FROM public.alembic_version"),
    }
    with pg.admin(dbname) as conn:
        return {
            key: [tuple(row) for row in conn.execute(sql, (schemas,) if "%s" in sql else None)]
            for key, sql in queries.items()
        }


@pytest.fixture
def job_db(pg: Cluster, fresh_db: str, password_file: Path) -> str:
    """A fresh database migrated to head by the job itself."""
    assert job.main(_env(pg, fresh_db, password_file)) == job.EXIT_OK
    return fresh_db


# --- 6. The job executes the migrations -------------------------------------------


def test_job_migrates_empty_database_as_migrator(pg: Cluster, job_db: str) -> None:
    snapshot = _snapshot(pg, job_db)
    assert snapshot["version"] == [("0014",)]
    assert {row[0] for row in snapshot["schemas"]} == set(APP_SCHEMAS)
    assert {row[1] for row in snapshot["schemas"]} == {OWNER_ROLE}
    assert {row[3] for row in snapshot["relations"]} == {OWNER_ROLE}
    assert {row[2] for row in snapshot["functions"]} == {OWNER_ROLE}
    assert {row[1] for row in snapshot["public_types"]} == {OWNER_ROLE}
    assert snapshot["database"][0][:2] == (OWNER_ROLE, False)


def test_job_result_equals_reference_migration(pg: Cluster, job_db: str, migrated_db: str) -> None:
    """The job leaves exactly the runtime security state the reference path produces."""
    assert _snapshot(pg, job_db) == _snapshot(pg, migrated_db)


def test_job_database_enforces_scenario_writer_isolation(pg: Cluster, job_db: str) -> None:
    with pg.connect(job_db, "intel_svc") as conn:
        (allowed,) = conn.execute(  # type: ignore[misc]
            "SELECT has_table_privilege('intel.scenario', 'INSERT')"
        ).fetchone()
    assert allowed is False
    with pg.connect(job_db, "scenario_gen") as conn:
        (allowed,) = conn.execute(  # type: ignore[misc]
            "SELECT has_table_privilege('intel.scenario', 'INSERT')"
        ).fetchone()
    assert allowed is True


# --- 11. Idempotency ---------------------------------------------------------------


def test_job_rerun_is_a_no_op(pg: Cluster, job_db: str, password_file: Path) -> None:
    before = _snapshot(pg, job_db)
    assert job.main(_env(pg, job_db, password_file)) == job.EXIT_OK
    assert job.main(_env(pg, job_db, password_file)) == job.EXIT_OK
    assert _snapshot(pg, job_db) == before


# --- 12. Every failure is a non-zero deployment result ------------------------------


def test_wrong_password_fails_fast_with_config_error(
    pg: Cluster, fresh_db: str, tmp_path: Path
) -> None:
    wrong = tmp_path / "wrong"
    wrong.write_text(secrets.token_urlsafe(24))
    assert job.main(_env(pg, fresh_db, wrong)) == job.EXIT_CONFIG_ERROR


def test_runtime_role_password_cannot_run_the_job(
    pg: Cluster, fresh_db: str, tmp_path: Path
) -> None:
    for role in RUNTIME_ROLES:
        stolen = tmp_path / role
        stolen.write_text(pg.passwords[role])
        assert job.main(_env(pg, fresh_db, stolen)) == job.EXIT_CONFIG_ERROR


@pytest.mark.parametrize("user", [OWNER_ROLE, "intel_svc", "postgres", "aitl_admin"])
def test_job_refuses_any_identity_but_the_migrator(
    pg: Cluster, fresh_db: str, password_file: Path, user: str
) -> None:
    env = _env(pg, fresh_db, password_file, AITL_MIGRATION_USER=user)
    assert job.main(env) == job.EXIT_CONFIG_ERROR


@pytest.mark.parametrize(
    "inline", ["AITL_MIGRATION_PASSWORD", "AITL_MIGRATION_DSN"], ids=["password", "dsn"]
)
def test_job_refuses_inline_credentials(
    pg: Cluster, fresh_db: str, password_file: Path, inline: str
) -> None:
    env = _env(pg, fresh_db, password_file, **{inline: "literal"})
    assert job.main(env) == job.EXIT_CONFIG_ERROR


@pytest.mark.parametrize("content", [None, ""], ids=["missing", "empty"])
def test_job_refuses_missing_or_empty_password_file(
    pg: Cluster, fresh_db: str, tmp_path: Path, content: str | None
) -> None:
    path = tmp_path / "pw"
    if content is not None:
        path.write_text(content)
    assert job.main(_env(pg, fresh_db, path)) == job.EXIT_CONFIG_ERROR


def test_missing_setting_is_config_error(pg: Cluster, fresh_db: str, password_file: Path) -> None:
    env = _env(pg, fresh_db, password_file)
    del env["AITL_DB_HOST"]
    assert job.main(env) == job.EXIT_CONFIG_ERROR


def test_unreachable_database_times_out_non_zero(password_file: Path) -> None:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        closed_port = sock.getsockname()[1]
    env = {
        "AITL_DB_HOST": "127.0.0.1",
        "AITL_DB_PORT": str(closed_port),
        "AITL_DB_NAME": "aitl",
        "AITL_MIGRATION_USER": MIGRATOR_ROLE,
        "AITL_MIGRATION_PASSWORD_FILE": str(password_file),
        "AITL_MIGRATION_WAIT_SECONDS": "1",
    }
    assert job.main(env) == job.EXIT_DB_NOT_READY


def test_migration_failure_is_non_zero_and_atomic(
    pg: Cluster, fresh_db: str, password_file: Path
) -> None:
    # A pre-existing object that migration 0001 will collide with.
    with pg.admin(fresh_db) as conn:
        conn.execute("SET ROLE aitl_owner")
        conn.execute("CREATE SCHEMA intel_raw")
    assert job.main(_env(pg, fresh_db, password_file)) == job.EXIT_MIGRATION_FAILED
    with pg.admin(fresh_db) as conn:
        version_table = conn.execute("SELECT to_regclass('public.alembic_version')").fetchone()
        other_schemas = conn.execute(
            "SELECT nspname FROM pg_namespace WHERE nspname = ANY(%s)",
            (["intel", "agent", "security", "eval", "ops"],),
        ).fetchall()
    assert version_table == (None,)
    assert other_schemas == []


def test_mid_chain_failure_stops_at_last_completed_revision(
    pg: Cluster, fresh_db: str, password_file: Path
) -> None:
    """Each migration is atomic: a failure in 0002 leaves the database at 0001."""
    pg.upgrade(fresh_db, "0001")
    with pg.admin(fresh_db) as conn:
        conn.execute("SET ROLE aitl_owner")
        conn.execute("CREATE TABLE agent.agent_config (squatter int)")
    assert job.main(_env(pg, fresh_db, password_file)) == job.EXIT_MIGRATION_FAILED
    with pg.admin(fresh_db) as conn:
        version = conn.execute("SELECT version_num FROM public.alembic_version").fetchall()
        columns = conn.execute(
            "SELECT column_name FROM information_schema.columns "
            "WHERE table_schema = 'agent' AND table_name = 'agent_config'"
        ).fetchall()
    assert version == [("0001",)]
    assert columns == [("squatter",)]


@pytest.fixture
def owner_leaked_to_runtime(pg: Cluster) -> Iterator[None]:
    with pg.admin() as conn:
        conn.execute("GRANT aitl_owner TO eval_svc")
    try:
        yield
    finally:
        with pg.admin() as conn:
            conn.execute("REVOKE aitl_owner FROM eval_svc")


def test_postcondition_failure_is_non_zero(
    pg: Cluster, job_db: str, password_file: Path, owner_leaked_to_runtime: None
) -> None:
    assert job.main(_env(pg, job_db, password_file)) == job.EXIT_POSTCONDITION_FAILED


def test_job_never_logs_the_password(
    pg: Cluster,
    fresh_db: str,
    password_file: Path,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    wrong = tmp_path / "wrong"
    wrong_value = secrets.token_urlsafe(24)
    wrong.write_text(wrong_value)
    job.main(_env(pg, fresh_db, wrong))
    job.main(_env(pg, fresh_db, password_file))
    err = capsys.readouterr().err
    assert '"event": "migration.completed"' in err
    assert pg.passwords[MIGRATOR_ROLE] not in err
    assert wrong_value not in err


# --- 9. Credential separation -------------------------------------------------------


def test_owner_cannot_log_in(pg: Cluster, migrated_db: str) -> None:
    for password in (pg.passwords[MIGRATOR_ROLE], ""):
        with pytest.raises(psycopg.OperationalError):
            psycopg.connect(pg.conninfo(migrated_db, OWNER_ROLE, password))
    with pg.admin() as conn:
        row = conn.execute(
            "SELECT rolcanlogin FROM pg_roles WHERE rolname = %s", (OWNER_ROLE,)
        ).fetchone()
    assert row == (False,)


@pytest.mark.parametrize("role", RUNTIME_ROLES)
def test_runtime_password_cannot_authenticate_as_migrator(
    pg: Cluster, migrated_db: str, role: str
) -> None:
    with pytest.raises(psycopg.OperationalError, match="password authentication failed"):
        psycopg.connect(pg.conninfo(migrated_db, MIGRATOR_ROLE, pg.passwords[role]))


@pytest.mark.parametrize("role", RUNTIME_ROLES)
@pytest.mark.parametrize("target", [OWNER_ROLE, MIGRATOR_ROLE])
def test_runtime_role_cannot_assume_owner_or_migrator(
    pg: Cluster, migrated_db: str, role: str, target: str
) -> None:
    with pg.connect(migrated_db, role) as conn:
        conn.autocommit = True
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute(f"SET ROLE {target}")
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute(f"SET SESSION AUTHORIZATION {target}")


def test_migrator_has_no_privileges_without_set_role(pg: Cluster, migrated_db: str) -> None:
    """INHERIT FALSE: the migrator's own session holds no object privileges."""
    with pg.connect(migrated_db, MIGRATOR_ROLE) as conn:
        conn.autocommit = True
        for table in ("intel.scenario", "intel_raw.raw_ingest_record", "security.policy"):
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                conn.execute(f"SELECT 1 FROM {table} LIMIT 1")
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute("CREATE ROLE aitl_probe LOGIN")
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute("ALTER ROLE aitl_owner LOGIN")
        # It can act as the owner only by an explicit, logged SET ROLE.
        conn.execute("SET ROLE aitl_owner")
        assert conn.execute("SELECT current_user").fetchone() == (OWNER_ROLE,)


def test_migrator_database_privilege_is_connect_only(pg: Cluster, migrated_db: str) -> None:
    with pg.admin(migrated_db) as conn:
        row = conn.execute(
            "SELECT has_database_privilege(%s, current_database(), 'CONNECT'), "
            "has_database_privilege(%s, current_database(), 'CREATE'), "
            "has_database_privilege(%s, current_database(), 'TEMPORARY')",
            (MIGRATOR_ROLE, MIGRATOR_ROLE, MIGRATOR_ROLE),
        ).fetchone()
    # has_database_privilege ignores INHERIT FALSE memberships only for inherit
    # checks; verify the ACL entry itself as well.
    assert row is not None
    assert row[0] is True
    with pg.admin(migrated_db) as conn:
        (acl,) = conn.execute(  # type: ignore[misc]
            "SELECT datacl::text FROM pg_database WHERE datname = current_database()"
        ).fetchone()
    assert f"{MIGRATOR_ROLE}=c/" in str(acl)


def test_migrator_has_no_elevated_attributes(pg: Cluster) -> None:
    with pg.admin() as conn:
        row = conn.execute(
            "SELECT rolcanlogin, rolsuper, rolcreaterole, rolcreatedb, rolreplication, "
            "rolbypassrls, rolinherit FROM pg_roles WHERE rolname = %s",
            (MIGRATOR_ROLE,),
        ).fetchone()
        grant = conn.execute(
            "SELECT m.inherit_option, m.set_option, m.admin_option FROM pg_auth_members m "
            "JOIN pg_roles g ON g.oid = m.roleid JOIN pg_roles r ON r.oid = m.member "
            "WHERE g.rolname = %s AND r.rolname = %s",
            (OWNER_ROLE, MIGRATOR_ROLE),
        ).fetchall()
        members_of_migrator = conn.execute(
            "SELECT count(*) FROM pg_auth_members m JOIN pg_roles g ON g.oid = m.roleid "
            "WHERE g.rolname = %s",
            (MIGRATOR_ROLE,),
        ).fetchone()
    assert row == (True, False, False, False, False, False, False)
    assert grant == [(False, True, False)]
    assert members_of_migrator == (0,)


# --- 10. No listener ---------------------------------------------------------------

_LISTENER_MODULES = {
    "socket",
    "socketserver",
    "http",
    "http.server",
    "asyncio",
    "uvicorn",
    "fastapi",
    "starlette",
    "aiohttp",
    "flask",
}


def test_job_opens_no_listener() -> None:
    tree = ast.parse(JOB_PATH.read_text(encoding="utf-8"))
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module)
        elif isinstance(node, ast.Attribute):
            assert node.attr not in {"bind", "listen", "serve_forever", "start_server"}, node.attr
    assert not {name.split(".")[0] for name in imported} & _LISTENER_MODULES, imported
