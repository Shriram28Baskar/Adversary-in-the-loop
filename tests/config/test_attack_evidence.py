"""Offline verification of the pinned ATT&CK subset (P5-D9; PRD FR-009; ARCHITECTURE.md ADR-025).

The curated tactics and techniques in ``aitl_common.config.schemas.attack``
and ``attack_mapping_v1`` are checked against a vendored, hash-pinned
extract of the official MITRE ATT&CK Enterprise 15.1 STIX bundle - with no
network access:

- the extract is the pinned bytes, in canonical form, from the pinned release;
- every curated tactic/technique exists there under the same ID and exact
  name, is neither revoked nor deprecated, and belongs to the declared tactic;
- the sub-technique flag agrees with the canonical ID form (``T####.###``)
  and every sub-technique's parent exists; no mapping uses both a parent and
  one of its sub-techniques;
- every tactic/technique the mapping artifact references is in the extract,
  and the extract holds nothing the mapping does not use.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

import pytest

from aitl_common.canonical_json import dumps
from aitl_common.config.bundle import load_config
from aitl_common.config.schemas.attack import (
    CURATED_TACTICS,
    CURATED_TECHNIQUES,
    PINNED_ATTACK_RELEASE,
)
from tests.config.attack_extract import extract, render
from tests.config.helpers import CONFIG_ROOT

EVIDENCE = CONFIG_ROOT.parent / "tests" / "config" / "data" / "attack-enterprise-15.1"
EXTRACT = EVIDENCE / "curated_subset.json"
EXTRACT_SHA256 = "aee56a9d3556cc5f2f537f7e7c5e068129015c5504b7af93c3533443278f972c"
SOURCE_BUNDLE_SHA256 = "a57988bffe402bb3e19d92dbe80a12143e1970b814e013e080f9df2fa5a3f6bc"
CANONICAL_TECHNIQUE = re.compile(r"^T[0-9]{4}(\.[0-9]{3})?$")


def _document() -> dict[str, Any]:
    loaded: dict[str, Any] = json.loads(EXTRACT.read_bytes())
    return loaded


def test_extract_is_the_pinned_canonical_bytes() -> None:
    raw = EXTRACT.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == EXTRACT_SHA256
    assert raw == dumps(json.loads(raw)) + b"\n"  # canonical: reproducible by the extractor


def test_extract_comes_from_the_pinned_release() -> None:
    source = _document()["source"]
    assert (source["domain"], source["version"]) == PINNED_ATTACK_RELEASE
    assert source["bundle_sha256"] == SOURCE_BUNDLE_SHA256
    assert source["source_url"].startswith("https://raw.githubusercontent.com/mitre-attack/")
    assert SOURCE_BUNDLE_SHA256 in (EVIDENCE / "SOURCE.md").read_text()
    assert EXTRACT_SHA256 in (EVIDENCE / "SOURCE.md").read_text()


def test_mapping_artifact_pins_the_same_release() -> None:
    mapping = load_config(CONFIG_ROOT).attack_mappings["attack-mapping-v1"].model
    release = (mapping.attack_release.domain, mapping.attack_release.version)
    assert release == PINNED_ATTACK_RELEASE


def test_every_curated_tactic_exists_live_with_its_exact_name() -> None:
    tactics = {t["external_id"]: t for t in _document()["tactics"]}
    assert set(tactics) == set(CURATED_TACTICS)
    for tactic_id, name in CURATED_TACTICS.items():
        record = tactics[tactic_id]
        assert (record["name"], record["revoked"], record["deprecated"]) == (name, False, False)


@pytest.mark.parametrize("technique_id", sorted(CURATED_TECHNIQUES))
def test_every_curated_technique_exists_live_in_its_tactic(technique_id: str) -> None:
    techniques = {t["external_id"]: t for t in _document()["techniques"]}
    record = techniques[technique_id]
    tactic_id, name = CURATED_TECHNIQUES[technique_id]
    assert record["name"] == name
    assert tactic_id in record["tactic_ids"]
    assert (record["revoked"], record["deprecated"]) == (False, False)
    assert "enterprise-attack" in record["domains"]
    assert CANONICAL_TECHNIQUE.fullmatch(technique_id)
    assert record["is_subtechnique"] is ("." in technique_id)
    if record["is_subtechnique"]:
        assert record["parent"]["external_id"] == technique_id.split(".")[0]


def test_extract_holds_exactly_the_curated_techniques() -> None:
    assert {t["external_id"] for t in _document()["techniques"]} == set(CURATED_TECHNIQUES)


def test_mapping_references_only_verified_objects_and_never_parent_with_child() -> None:
    mapping = load_config(CONFIG_ROOT).attack_mappings["attack-mapping-v1"].model
    techniques = {t["external_id"]: t for t in _document()["techniques"]}
    tactics = {t["external_id"] for t in _document()["tactics"]}
    assert mapping.tactic_ids <= tactics
    assert mapping.technique_ids <= set(techniques)
    for entry in mapping.ttp_map:
        assert entry.tactic_id in tactics
        for technique_id in entry.technique_ids:
            assert entry.tactic_id in techniques[technique_id]["tactic_ids"], entry.label
    parents = {t.split(".")[0] for t in mapping.technique_ids if "." in t}
    assert not parents & mapping.technique_ids  # T1552 never alongside T1552.001


# --- the extractor itself (offline, deterministic) ----------------------------------------------


def _stix(kind: str, ext: str, name: str, **extra: Any) -> dict[str, Any]:
    return {
        "type": kind,
        "id": f"{kind}--{ext}",
        "name": name,
        "external_references": [{"source_name": "mitre-attack", "external_id": ext}],
        **extra,
    }


def _bundle() -> dict[str, Any]:
    phase = {"kill_chain_name": "mitre-attack", "phase_name": "credential-access"}
    return {
        "type": "bundle",
        "spec_version": "2.1",
        "objects": [
            {
                "type": "x-mitre-collection",
                "name": "Enterprise ATT&CK",
                "x_mitre_version": "15.1",
                "modified": "2024-05-02T14:00:00.188Z",
            },
            _stix(
                "x-mitre-tactic",
                "TA0006",
                "Credential Access",
                x_mitre_shortname="credential-access",
            ),
            _stix("attack-pattern", "T1552", "Unsecured Credentials", kill_chain_phases=[phase]),
            _stix(
                "attack-pattern",
                "T1552.001",
                "Credentials In Files",
                kill_chain_phases=[phase],
                x_mitre_is_subtechnique=True,
                x_mitre_domains=["enterprise-attack"],
            ),
            _stix("attack-pattern", "T1552.001", "Old Name", revoked=True),  # revoked twin
        ],
    }


def test_extractor_is_deterministic_and_skips_revoked_objects() -> None:
    args = {"source_url": "file:local", "bundle_sha256": "0" * 64}
    first = render(extract(_bundle(), ["TA0006"], ["T1552.001"], **args))
    again = render(extract(_bundle(), ["TA0006"], ["T1552.001"], **args))
    assert first == again
    (technique,) = json.loads(first)["techniques"]
    assert technique["name"] == "Credentials In Files"
    assert technique["parent"] == {"external_id": "T1552", "name": "Unsecured Credentials"}


def test_extractor_rejects_missing_or_ambiguous_techniques() -> None:
    args = {"source_url": "file:local", "bundle_sha256": "0" * 64}
    with pytest.raises(ValueError, match="T9999"):
        extract(_bundle(), ["TA0006"], ["T9999"], **args)
    ambiguous = _bundle()
    ambiguous["objects"].append(_stix("attack-pattern", "T1552.001", "Dup", kill_chain_phases=[]))
    with pytest.raises(ValueError, match=r"T1552\.001"):
        extract(ambiguous, ["TA0006"], ["T1552.001"], **args)
