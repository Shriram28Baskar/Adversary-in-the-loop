"""The ORM is the single authoritative mapping of the migrated schema (engineering plan P1).

Reflects the migrated database from the catalog and fails if the ORM
diverges on: table/column sets, column types (including domains and enum
types), nullability, identity columns, primary keys, unique constraints,
foreign keys, indexes, enum labels, or the append-only designation.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import psycopg
import pytest
from sqlalchemy import (
    BigInteger,
    Boolean,
    Column,
    DateTime,
    ForeignKeyConstraint,
    Index,
    Integer,
    Numeric,
    PrimaryKeyConstraint,
    SmallInteger,
    Table,
    Text,
    UniqueConstraint,
    Uuid,
)
from sqlalchemy.dialects.postgresql import ARRAY, ENUM, INET, JSONB

from aitl_common.db.models import Base
from aitl_common.db.types import ENUM_LABELS
from tests.pg_harness import Cluster

SIMPLE_TYPES: dict[type[Any], str] = {
    Text: "text",
    Integer: "int4",
    BigInteger: "int8",
    SmallInteger: "int2",
    Boolean: "bool",
    Uuid: "uuid",
    JSONB: "jsonb",
    INET: "inet",
}


def _expected_type(column: Column[Any]) -> tuple[str, int | None, int | None]:
    domain = column.info.get("domain")
    if domain:
        return (str(domain), None, None)
    column_type = column.type
    if isinstance(column_type, ENUM):
        return (str(column_type.name), None, None)
    if isinstance(column_type, ARRAY):
        item = column_type.item_type
        name = item.name if isinstance(item, ENUM) else SIMPLE_TYPES[type(item)]
        return (f"_{name}", None, None)
    if isinstance(column_type, DateTime):
        assert column_type.timezone, f"{column.table}.{column.name} must be timezone-aware"
        return ("timestamptz", None, None)
    if isinstance(column_type, Numeric):
        return ("numeric", column_type.precision, column_type.scale)
    for sa_type, pg_name in SIMPLE_TYPES.items():
        if type(column_type) is sa_type:
            return (pg_name, None, None)
    raise AssertionError(f"unmapped ORM type {column_type!r} on {column.table}.{column.name}")


@pytest.fixture(scope="module")
def catalog(pg: Cluster, migrated_db: str) -> Iterator[psycopg.Connection[tuple[Any, ...]]]:
    with pg.admin(migrated_db) as conn:
        yield conn


def _db_columns(
    conn: psycopg.Connection[tuple[Any, ...]], table: Table
) -> dict[str, tuple[Any, ...]]:
    rows = conn.execute(
        "SELECT column_name, COALESCE(domain_name, udt_name), is_nullable, numeric_precision, "
        "numeric_scale, is_identity FROM information_schema.columns "
        "WHERE table_schema = %s AND table_name = %s",
        (table.schema, table.name),
    ).fetchall()
    return {row[0]: tuple(row[1:]) for row in rows}


def _db_constraints(
    conn: psycopg.Connection[tuple[Any, ...]], table: Table, contype: str
) -> set[tuple[Any, ...]]:
    rows = conn.execute(
        "SELECT c.conname, "
        "ARRAY(SELECT a.attname FROM unnest(c.conkey) WITH ORDINALITY k(attnum, n) "
        "      JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = k.attnum "
        "      ORDER BY k.n), "
        "CASE WHEN c.contype = 'f' THEN c.confrelid::regclass::text END, "
        "ARRAY(SELECT a.attname FROM unnest(c.confkey) WITH ORDINALITY k(attnum, n) "
        "      JOIN pg_attribute a ON a.attrelid = c.confrelid AND a.attnum = k.attnum "
        "      ORDER BY k.n) "
        "FROM pg_constraint c WHERE c.conrelid = %s::regclass AND c.contype = %s",
        (f"{table.schema}.{table.name}", contype),
    ).fetchall()
    return {
        (name, tuple(cols), ref, tuple(ref_cols) if ref else ())
        for name, cols, ref, ref_cols in rows
    }


def _orm_constraints(table: Table, kind: type[Any]) -> set[tuple[Any, ...]]:
    found: set[tuple[Any, ...]] = set()
    for constraint in table.constraints:
        if not isinstance(constraint, kind):
            continue
        if isinstance(constraint, ForeignKeyConstraint):
            ref_table = constraint.elements[0].column.table
            found.add(
                (
                    constraint.name,
                    tuple(constraint.column_keys),
                    f"{ref_table.schema}.{ref_table.name}",
                    tuple(element.column.name for element in constraint.elements),
                )
            )
        else:
            found.add((constraint.name, tuple(c.name for c in constraint.columns), None, ()))
    return found


TABLES = sorted(Base.metadata.tables.values(), key=lambda t: t.fullname)


def test_every_database_table_is_mapped(catalog: psycopg.Connection[tuple[Any, ...]]) -> None:
    rows = catalog.execute(
        "SELECT schemaname || '.' || tablename FROM pg_tables WHERE schemaname IN "
        "('intel_raw', 'intel', 'agent', 'security', 'eval', 'ops')"
    ).fetchall()
    assert {row[0] for row in rows} == set(Base.metadata.tables)


@pytest.mark.parametrize("table", TABLES, ids=lambda t: t.fullname)
def test_columns_types_nullability_identity(
    catalog: psycopg.Connection[tuple[Any, ...]], table: Table
) -> None:
    db_columns = _db_columns(catalog, table)
    assert set(db_columns) == {c.name for c in table.columns}
    for column in table.columns:
        db_type, nullable, precision, scale, identity = db_columns[column.name]
        expected_type, expected_precision, expected_scale = _expected_type(column)
        assert db_type == expected_type, column.name
        assert (nullable == "YES") == bool(column.nullable), column.name
        if expected_type == "numeric":
            assert (precision, scale) == (expected_precision, expected_scale), column.name
        assert (identity == "YES") == (column.identity is not None), column.name


@pytest.mark.parametrize("table", TABLES, ids=lambda t: t.fullname)
def test_keys_and_uniques(catalog: psycopg.Connection[tuple[Any, ...]], table: Table) -> None:
    assert _db_constraints(catalog, table, "p") == _orm_constraints(table, PrimaryKeyConstraint)
    assert _db_constraints(catalog, table, "u") == _orm_constraints(table, UniqueConstraint)
    assert _db_constraints(catalog, table, "f") == _orm_constraints(table, ForeignKeyConstraint)


@pytest.mark.parametrize("table", TABLES, ids=lambda t: t.fullname)
def test_indexes(catalog: psycopg.Connection[tuple[Any, ...]], table: Table) -> None:
    rows = catalog.execute(
        "SELECT i.relname, "
        "ARRAY(SELECT a.attname FROM unnest(x.indkey) WITH ORDINALITY k(attnum, n) "
        "JOIN pg_attribute a ON a.attrelid = x.indrelid AND a.attnum = k.attnum ORDER BY k.n) "
        "FROM pg_index x JOIN pg_class i ON i.oid = x.indexrelid "
        "WHERE x.indrelid = %s::regclass AND NOT EXISTS "
        "(SELECT 1 FROM pg_constraint c WHERE c.conindid = x.indexrelid)",
        (table.fullname,),
    ).fetchall()
    orm = {
        (ix.name, tuple(c.name for c in ix.columns))
        for ix in table.indexes
        if isinstance(ix, Index)
    }
    assert {(name, tuple(cols)) for name, cols in rows} == orm


def test_enum_labels_match(catalog: psycopg.Connection[tuple[Any, ...]]) -> None:
    rows = catalog.execute(
        "SELECT t.typname, array_agg(e.enumlabel ORDER BY e.enumsortorder) FROM pg_type t "
        "JOIN pg_enum e ON e.enumtypid = t.oid JOIN pg_namespace n ON n.oid = t.typnamespace "
        "WHERE n.nspname = 'public' GROUP BY t.typname"
    ).fetchall()
    assert {name: tuple(labels) for name, labels in rows} == ENUM_LABELS


@pytest.mark.parametrize("table", TABLES, ids=lambda t: t.fullname)
def test_append_only_designation_matches_triggers(
    catalog: psycopg.Connection[tuple[Any, ...]], table: Table
) -> None:
    mapper_classes = [m.class_ for m in Base.registry.mappers if m.local_table is table]
    [model] = mapper_classes
    rows = catalog.execute(
        "SELECT tgname FROM pg_trigger WHERE tgrelid = %s::regclass AND NOT tgisinternal",
        (table.fullname,),
    ).fetchall()
    has_append_only_trigger = f"trg_{table.name}_append_only" in {row[0] for row in rows}
    assert has_append_only_trigger == model.APPEND_ONLY
