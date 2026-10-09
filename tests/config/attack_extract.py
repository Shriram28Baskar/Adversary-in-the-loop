"""Build the minimal ATT&CK evidence extract from a local STIX bundle (P5-D9; ADR-025).

Offline tool: it reads a MITRE ATT&CK STIX 2.1 bundle *already on disk*
and never fetches anything. It keeps only the objects that
``attack_mapping`` actually uses (tactics and techniques), plus, for each
sub-technique, its parent's identity. Output is P0 canonical JSON, so the
committed file is byte-for-byte reproducible from the same bundle:

    uv run python -m tests.config.attack_extract BUNDLE.json > \\
        tests/config/data/attack-enterprise-15.1/curated_subset.json

The extract is evidence and validation data only; no runtime code reads it.
"""

from __future__ import annotations

import sys
from collections.abc import Iterable, Mapping
from typing import Any

from aitl_common.canonical_json import dumps

MITRE_SOURCE = "mitre-attack"


def _external_id(obj: Mapping[str, Any]) -> str | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == MITRE_SOURCE:
            value = ref.get("external_id")
            return value if isinstance(value, str) else None
    return None


def _live(objs: Iterable[Mapping[str, Any]]) -> list[Mapping[str, Any]]:
    return [o for o in objs if not o.get("revoked") and not o.get("x_mitre_deprecated")]


def extract(
    bundle: Mapping[str, Any],
    tactic_ids: Iterable[str],
    technique_ids: Iterable[str],
    *,
    source_url: str,
    bundle_sha256: str,
) -> dict[str, Any]:
    objects: list[Mapping[str, Any]] = bundle["objects"]
    (collection,) = [o for o in objects if o["type"] == "x-mitre-collection"]
    tactics = {_external_id(o): o for o in objects if o["type"] == "x-mitre-tactic"}
    shortname = {o["x_mitre_shortname"]: tid for tid, o in tactics.items()}
    patterns: dict[str | None, list[Mapping[str, Any]]] = {}
    for o in objects:
        if o["type"] == "attack-pattern":
            patterns.setdefault(_external_id(o), []).append(o)

    def technique(tid: str) -> dict[str, Any]:
        candidates = patterns.get(tid, [])
        live = _live(candidates)
        if len(live) != 1:
            raise ValueError(f"{tid}: {len(candidates)} objects, {len(live)} live")
        obj = live[0]
        record: dict[str, Any] = {
            "external_id": tid,
            "name": obj["name"],
            "stix_id": obj["id"],
            "is_subtechnique": bool(obj.get("x_mitre_is_subtechnique", False)),
            "tactic_ids": sorted(
                shortname[k["phase_name"]]
                for k in obj.get("kill_chain_phases", [])
                if k.get("kill_chain_name") == MITRE_SOURCE
            ),
            "domains": sorted(obj.get("x_mitre_domains", [])),
            "revoked": bool(obj.get("revoked", False)),
            "deprecated": bool(obj.get("x_mitre_deprecated", False)),
        }
        if record["is_subtechnique"]:
            parent_id = tid.split(".", 1)[0]
            (parent,) = _live(patterns.get(parent_id, []))
            record["parent"] = {"external_id": parent_id, "name": parent["name"]}
        return record

    return {
        "source": {
            "domain": "enterprise-attack",
            "collection_name": collection["name"],
            "version": collection["x_mitre_version"],
            "collection_modified": collection["modified"],
            "stix_spec_version": bundle.get("spec_version", collection.get("spec_version")),
            "source_url": source_url,
            "bundle_sha256": bundle_sha256,
        },
        "tactics": [
            {
                "external_id": tid,
                "name": tactics[tid]["name"],
                "shortname": tactics[tid]["x_mitre_shortname"],
                "stix_id": tactics[tid]["id"],
                "revoked": bool(tactics[tid].get("revoked", False)),
                "deprecated": bool(tactics[tid].get("x_mitre_deprecated", False)),
            }
            for tid in sorted(tactic_ids)
        ],
        "techniques": [technique(tid) for tid in sorted(technique_ids)],
    }


def render(document: Mapping[str, Any]) -> bytes:
    return dumps(document) + b"\n"


if __name__ == "__main__":  # pragma: no cover - maintenance tool
    import hashlib
    import json
    from pathlib import Path

    from aitl_common.config.schemas.attack import CURATED_TACTICS, CURATED_TECHNIQUES

    path = Path(sys.argv[1])
    raw = path.read_bytes()
    sys.stdout.buffer.write(
        render(
            extract(
                json.loads(raw),
                CURATED_TACTICS,
                CURATED_TECHNIQUES,
                source_url=sys.argv[2],
                bundle_sha256=hashlib.sha256(raw).hexdigest(),
            )
        )
    )
