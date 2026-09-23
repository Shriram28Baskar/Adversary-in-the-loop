"""Database grant matrix (ARCHITECTURE.md §24; PRD FR-044, FR-010c(b), FR-004b(c)).

The expected matrix below is transcribed independently from ARCHITECTURE.md
§24 (plus the engineering-plan §5.5 additions and the two read grants §24
implies), not derived from the migration code. Every runtime role x table x
operation is checked twice: in the catalog (``has_table_privilege``) and by
actually attempting the statement and requiring a PostgreSQL
``insufficient_privilege`` error where the operation must be denied.
"""

from __future__ import annotations

import secrets
from collections.abc import Iterator

import psycopg
import pytest
from psycopg import errors

from tests.pg_harness import OWNER_ROLE, RUNTIME_ROLES, Cluster

INTEL_RAW = ("intel_raw.raw_ingest_record", "intel_raw.quarantine_record")
INTEL = (
    "intel.attack_session",
    "intel.attack_event",
    "intel.attacker_behavior",
    "intel.behavior_event",
    "intel.ttp",
    "intel.ttp_technique",
    "intel.abstracted_threat_pattern",
    "intel.threat_pattern_source",
    "intel.scenario",
    "intel.scenario_step",
)
AGENT = (
    "agent.agent_config",
    "agent.agent_task",
    "agent.tool",
    "agent.data_asset",
    "agent.execution",
)
SECURITY = (
    "security.policy",
    "security.tool_invocation",
    "security.policy_decision",
    "security.tool_result",
    "security.data_flow_event",
    "security.security_violation",
    "security.system_failure_event",
    "security.model_call",
    "security.agent_final_response",
    "security.trajectory",
)
EVAL = (
    "eval.eval_config",
    "eval.replay_pair",
    "eval.replay_run",
    "eval.blast_radius",
    "eval.evaluation_result",
)
OPS = ("ops.events",)
SCENARIO_TABLES = ("intel.scenario", "intel.scenario_step")
ALL_TABLES = (*INTEL_RAW, *INTEL, *AGENT, *SECURITY, *EVAL, *OPS)

SEL, INS = "SELECT", "INSERT"


def _grant(tables: tuple[str, ...], *ops: str) -> dict[str, set[str]]:
    return {table: set(ops) for table in tables}


def _merge(*parts: dict[str, set[str]]) -> dict[str, frozenset[str]]:
    merged: dict[str, set[str]] = {}
    for part in parts:
        for table, ops in part.items():
            merged.setdefault(table, set()).update(ops)
    return {table: frozenset(ops) for table, ops in merged.items()}


# Table-level privileges each runtime role must hold (anything absent must be denied).
EXPECTED: dict[str, dict[str, frozenset[str]]] = {
    "ingest_writer": _merge(_grant(INTEL_RAW, INS)),
    # ADR-021: intel_svc reads attacker text, so it may not create scenarios.
    "intel_svc": _merge(
        _grant(INTEL_RAW, SEL),
        _grant(("intel_raw.quarantine_record",), INS),
        _grant(INTEL, SEL),
        _grant(tuple(t for t in INTEL if t not in SCENARIO_TABLES), INS),
        _grant(AGENT + SECURITY + EVAL, SEL),
        _grant(OPS, INS),
    ),
    "scenario_gen": _merge(
        _grant(("intel.abstracted_threat_pattern",), SEL),
        _grant(("intel.scenario",), SEL, INS),
        _grant(("intel.scenario_step",), INS),
        _grant(("agent.agent_task", "agent.data_asset"), SEL),
    ),
    "agent_svc": _merge(
        _grant(("intel.scenario",), SEL),
        _grant(AGENT, SEL, INS),
        _grant(OPS, INS),
        _grant(
            (
                "security.policy",
                "eval.eval_config",
                "security.system_failure_event",
                "security.model_call",
                "security.policy_decision",
            ),
            SEL,
        ),
    ),
    "gateway_svc": _merge(
        _grant(AGENT, SEL),
        _grant(("intel.scenario", "intel.scenario_step"), SEL),
        _grant(tuple(t for t in SECURITY if t != "security.trajectory"), INS),
        _grant(("security.policy",), SEL),
        _grant(OPS, INS),
    ),
    "eval_svc": _merge(
        _grant(INTEL + AGENT + SECURITY + EVAL, SEL),
        _grant(("security.trajectory",), INS),
        _grant(EVAL, INS),
        _grant(OPS, INS),
    ),
}

# The only UPDATE privileges anywhere: column-level.
EXPECTED_COLUMN_UPDATES: dict[tuple[str, str], frozenset[str]] = {
    ("intel_svc", "intel.scenario"): frozenset({"status"}),
    ("agent_svc", "agent.execution"): frozenset(
        {
            "lifecycle",
            "error_class",
            "termination_reason",
            "teardown_verified",
            "token_hash",
            "sandbox_image_digest_as_run",
            "gateway_build_as_run",
            "fixture_checksum_as_run",
            "started_at",
            "ended_at",
        }
    ),
}

TABLE_PRIVILEGES = ("SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER")


@pytest.fixture(scope="module")
def grants_db(pg: Cluster) -> Iterator[str]:
    """An empty, fully migrated database (no rows, so no statement can mutate data)."""
    name = f"aitl_grants_{secrets.token_hex(4)}"
    pg.create_database(name)
    pg.upgrade(name)
    yield name
    pg.drop_database(name)


def _columns(pg: Cluster, db: str, table: str, *, updatable_only: bool = False) -> list[str]:
    """Columns in order; ``updatable_only`` skips GENERATED ALWAYS identity columns, which
    PostgreSQL rejects (428C9) before checking privileges, so they cannot probe grants."""
    schema, name = table.split(".")
    with pg.admin(db) as conn:
        rows = conn.execute(
            "SELECT column_name, is_identity FROM information_schema.columns "
            "WHERE table_schema = %s AND table_name = %s ORDER BY ordinal_position",
            (schema, name),
        ).fetchall()
    return [str(col) for col, identity in rows if not (updatable_only and identity == "YES")]


def test_expected_matrix_covers_every_table(pg: Cluster, grants_db: str) -> None:
    with pg.admin(grants_db) as conn:
        rows = conn.execute(
            "SELECT schemaname || '.' || tablename FROM pg_tables WHERE schemaname IN "
            "('intel_raw', 'intel', 'agent', 'security', 'eval', 'ops')"
        ).fetchall()
    assert {row[0] for row in rows} == set(ALL_TABLES)
    for role in RUNTIME_ROLES:
        assert set(EXPECTED[role]) <= set(ALL_TABLES)


@pytest.mark.parametrize("role", RUNTIME_ROLES)
def test_catalog_privileges_match_matrix(pg: Cluster, grants_db: str, role: str) -> None:
    mismatches: list[str] = []
    with pg.admin(grants_db) as conn:
        for table in ALL_TABLES:
            for privilege in TABLE_PRIVILEGES:
                (held,) = conn.execute(  # type: ignore[misc]
                    "SELECT has_table_privilege(%s, %s, %s)", (role, table, privilege)
                ).fetchone()
                expected = privilege in EXPECTED[role].get(table, frozenset())
                if held != expected:
                    mismatches.append(f"{role} {privilege} {table}: held={held}")
    assert mismatches == []


@pytest.mark.parametrize("role", RUNTIME_ROLES)
def test_column_update_privileges_match_matrix(pg: Cluster, grants_db: str, role: str) -> None:
    mismatches: list[str] = []
    with pg.admin(grants_db) as conn:
        for table in ALL_TABLES:
            allowed = EXPECTED_COLUMN_UPDATES.get((role, table), frozenset())
            for column in _columns(pg, grants_db, table):
                (held,) = conn.execute(  # type: ignore[misc]
                    "SELECT has_column_privilege(%s, %s, %s, 'UPDATE')", (role, table, column)
                ).fetchone()
                if held != (column in allowed):
                    mismatches.append(f"{role} UPDATE({column}) {table}: held={held}")
    assert mismatches == []


def _probe(conn: psycopg.Connection[tuple[object, ...]], sql: str) -> str | None:
    """Run ``sql`` in a rolled-back transaction; return the SQLSTATE of any error."""
    try:
        conn.execute(sql)
    except psycopg.Error as exc:
        return exc.sqlstate
    finally:
        conn.rollback()
    return None


def _statements(table: str, first_column: str) -> dict[str, str]:
    return {
        "SELECT": f"SELECT 1 FROM {table} LIMIT 0",
        "INSERT": f"INSERT INTO {table} DEFAULT VALUES",
        "UPDATE": f"UPDATE {table} SET {first_column} = {first_column}",
        "DELETE": f"DELETE FROM {table}",
        "TRUNCATE": f"TRUNCATE {table}",
    }


@pytest.mark.parametrize("role", RUNTIME_ROLES)
def test_real_statements_enforce_matrix(pg: Cluster, grants_db: str, role: str) -> None:
    """Attempt every operation; denied ones must fail with insufficient_privilege (42501)."""
    failures: list[str] = []
    with pg.connect(grants_db, role) as conn:
        for table in ALL_TABLES:
            allowed = EXPECTED[role].get(table, frozenset())
            first_column = _columns(pg, grants_db, table, updatable_only=True)[0]
            for operation, sql in _statements(table, first_column).items():
                sqlstate = _probe(conn, sql)
                denied = sqlstate == errors.InsufficientPrivilege.sqlstate
                if operation in allowed and denied:
                    failures.append(f"{role} {operation} {table}: unexpectedly denied")
                if operation not in allowed and not denied:
                    failures.append(f"{role} {operation} {table}: not denied (sqlstate={sqlstate})")
    assert failures == []


def test_execution_column_updates_enforced_by_real_statements(pg: Cluster, grants_db: str) -> None:
    allowed = EXPECTED_COLUMN_UPDATES[("agent_svc", "agent.execution")]
    with pg.connect(grants_db, "agent_svc") as conn:
        for column in _columns(pg, grants_db, "agent.execution"):
            sqlstate = _probe(conn, f"UPDATE agent.execution SET {column} = {column} WHERE false")
            if column in allowed:
                assert sqlstate is None, column
            else:
                assert sqlstate == errors.InsufficientPrivilege.sqlstate, column


def test_scenario_only_status_is_updatable_by_intel_svc(pg: Cluster, grants_db: str) -> None:
    with pg.connect(grants_db, "intel_svc") as conn:
        assert _probe(conn, "UPDATE intel.scenario SET status = status WHERE false") is None
        for column in ("poisoned_content", "threat_pattern_id", "source_type", "content_sha256"):
            assert (
                _probe(conn, f"UPDATE intel.scenario SET {column} = {column} WHERE false")
                == errors.InsufficientPrivilege.sqlstate
            ), column


@pytest.mark.parametrize(
    "table", ["intel.attack_event", "intel.attacker_behavior", *INTEL_RAW, "intel.attack_session"]
)
def test_scenario_generator_cannot_read_attacker_text(
    pg: Cluster, grants_db: str, table: str
) -> None:
    """FR-010c(b): the scenario generator has no read path to attacker-derived data."""
    with pg.connect(grants_db, "scenario_gen") as conn:
        assert _probe(conn, f"SELECT * FROM {table}") == errors.InsufficientPrivilege.sqlstate


@pytest.mark.parametrize("table", [t for t in ALL_TABLES if t not in INTEL_RAW])
def test_ingest_writer_confined_to_staging(pg: Cluster, grants_db: str, table: str) -> None:
    """FR-004b(c): the Log Shipper's role can only INSERT into intel_raw staging."""
    with pg.connect(grants_db, "ingest_writer") as conn:
        for sql in (f"INSERT INTO {table} DEFAULT VALUES", f"SELECT 1 FROM {table} LIMIT 0"):
            assert _probe(conn, sql) == errors.InsufficientPrivilege.sqlstate, sql


def test_ingest_writer_cannot_read_its_own_staging(pg: Cluster, grants_db: str) -> None:
    with pg.connect(grants_db, "ingest_writer") as conn:
        for table in INTEL_RAW:
            assert _probe(conn, f"SELECT 1 FROM {table}") == errors.InsufficientPrivilege.sqlstate


@pytest.mark.parametrize("role", [r for r in RUNTIME_ROLES if r != "gateway_svc"])
def test_only_gateway_writes_security_telemetry(pg: Cluster, grants_db: str, role: str) -> None:
    with pg.connect(grants_db, role) as conn:
        for table in SECURITY:
            if table == "security.trajectory":
                continue
            assert (
                _probe(conn, f"INSERT INTO {table} DEFAULT VALUES")
                == errors.InsufficientPrivilege.sqlstate
            ), f"{role} {table}"


@pytest.mark.parametrize("role", RUNTIME_ROLES)
def test_no_role_can_modify_policy_or_eval_config(pg: Cluster, grants_db: str, role: str) -> None:
    with pg.connect(grants_db, role) as conn:
        for table in ("security.policy", "eval.eval_config"):
            for sql in (
                f"UPDATE {table} SET content_sha256 = content_sha256",
                f"DELETE FROM {table}",
                f"TRUNCATE {table}",
            ):
                assert _probe(conn, sql) == errors.InsufficientPrivilege.sqlstate, sql
        if role not in ("gateway_svc",):
            assert (
                _probe(conn, "INSERT INTO security.policy DEFAULT VALUES")
                == errors.InsufficientPrivilege.sqlstate
            )
        if role != "eval_svc":
            assert (
                _probe(conn, "INSERT INTO eval.eval_config DEFAULT VALUES")
                == errors.InsufficientPrivilege.sqlstate
            )


@pytest.mark.parametrize("role", RUNTIME_ROLES)
def test_runtime_roles_cannot_create_objects(pg: Cluster, grants_db: str, role: str) -> None:
    with pg.connect(grants_db, role) as conn:
        for sql in (
            "CREATE TABLE public.x (id int)",
            "CREATE TABLE intel.x (id int)",
            "CREATE TABLE security.x (id int)",
            "CREATE TEMP TABLE x (id int)",
            "CREATE SCHEMA rogue",
            "CREATE FUNCTION public.f() RETURNS int LANGUAGE sql AS 'SELECT 1'",
            "CREATE VIEW ops.v AS SELECT 1",
        ):
            assert _probe(conn, sql) == errors.InsufficientPrivilege.sqlstate, f"{role}: {sql}"


def test_runtime_roles_hold_no_elevated_attributes_or_ownership(
    pg: Cluster, grants_db: str
) -> None:
    with pg.admin(grants_db) as conn:
        rows = conn.execute(
            "SELECT rolname, rolsuper, rolcreaterole, rolcreatedb, rolreplication, rolbypassrls, "
            "rolcanlogin FROM pg_roles WHERE rolname = ANY(%s)",
            (list(RUNTIME_ROLES),),
        ).fetchall()
        assert len(rows) == len(RUNTIME_ROLES)
        for name, *elevated, can_login in rows:
            assert not any(elevated), name
            assert can_login, name
        owned = conn.execute(
            "SELECT c.relname, pg_get_userbyid(c.relowner) FROM pg_class c "
            "JOIN pg_namespace n ON n.oid = c.relnamespace "
            "WHERE n.nspname IN ('intel_raw', 'intel', 'agent', 'security', 'eval', 'ops') "
            "AND pg_get_userbyid(c.relowner) <> %s",
            (OWNER_ROLE,),
        ).fetchall()
        assert owned == []
        memberships = conn.execute(
            "SELECT r.rolname FROM pg_auth_members m JOIN pg_roles r ON r.oid = m.member "
            "WHERE m.roleid = (SELECT oid FROM pg_roles WHERE rolname = %s)",
            (OWNER_ROLE,),
        ).fetchall()
        assert [row for row in memberships if row[0] in RUNTIME_ROLES] == []


def test_owner_is_nologin_and_cannot_connect(pg: Cluster, grants_db: str) -> None:
    with pg.admin(grants_db) as conn:
        (can_login,) = conn.execute(  # type: ignore[misc]
            "SELECT rolcanlogin FROM pg_roles WHERE rolname = %s", (OWNER_ROLE,)
        ).fetchone()
        (db_owner,) = conn.execute(  # type: ignore[misc]
            "SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname = current_database()"
        ).fetchone()
    assert can_login is False
    assert db_owner == OWNER_ROLE
    with pytest.raises(psycopg.OperationalError):
        psycopg.connect(pg.conninfo(grants_db, OWNER_ROLE, "any-password"))


@pytest.fixture
def intruder(pg: Cluster, grants_db: str) -> Iterator[str]:
    """A fresh LOGIN role with no grants: it only has what PUBLIC has."""
    password = secrets.token_urlsafe(24)
    with pg.admin(grants_db) as conn:
        conn.execute(f"CREATE ROLE aitl_intruder LOGIN PASSWORD '{password}'")
    yield password
    with pg.admin(grants_db) as conn:
        conn.execute(f'REVOKE ALL ON DATABASE "{grants_db}" FROM aitl_intruder')
        conn.execute("DROP ROLE aitl_intruder")


def test_public_cannot_connect(pg: Cluster, grants_db: str, intruder: str) -> None:
    with pytest.raises(psycopg.OperationalError, match="permission denied"):
        psycopg.connect(pg.conninfo(grants_db, "aitl_intruder", intruder))


def test_public_has_no_object_privileges(pg: Cluster, grants_db: str, intruder: str) -> None:
    """Even with CONNECT, a role holding only PUBLIC privileges can use nothing."""
    with pg.admin(grants_db) as conn:
        conn.execute(f'GRANT CONNECT ON DATABASE "{grants_db}" TO aitl_intruder')
    with psycopg.connect(pg.conninfo(grants_db, "aitl_intruder", intruder)) as conn:
        for table in ALL_TABLES:
            for sql in (f"SELECT 1 FROM {table} LIMIT 0", f"INSERT INTO {table} DEFAULT VALUES"):
                assert _probe(conn, sql) == errors.InsufficientPrivilege.sqlstate, sql
        for sql in (
            "SELECT CAST('x' AS public.untrusted_text)",
            "SELECT CAST('honeypot' AS public.source_type)",
            "CREATE TEMP TABLE x (id int)",
            "CREATE TABLE public.x (id int)",
        ):
            assert _probe(conn, sql) == errors.InsufficientPrivilege.sqlstate, sql


def test_database_level_public_privileges_revoked(pg: Cluster, grants_db: str) -> None:
    with pg.admin(grants_db) as conn:
        (acl,) = conn.execute(  # type: ignore[misc]
            "SELECT datacl::text FROM pg_database WHERE datname = current_database()"
        ).fetchone()
        (schema_acl,) = conn.execute(  # type: ignore[misc]
            "SELECT nspacl::text FROM pg_namespace WHERE nspname = 'public'"
        ).fetchone()
    # PUBLIC entries in an aclitem[] have an empty grantee ("=...").
    assert not any(item.startswith("=") for item in str(acl).strip("{}").split(","))
    assert not any(item.startswith("=") for item in str(schema_acl).strip("{}").split(","))
