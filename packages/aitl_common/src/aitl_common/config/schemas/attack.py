"""ATT&CK mapping artifact (PRD FR-009, FR-010; ARCHITECTURE.md §12, §37.1).

``config/attack/attack_mapping_vN.yaml`` pins one ATT&CK Enterprise release,
lists the curated technique subset, and maps each TTP label to exactly one
tactic and one or more techniques. Labels that are deliberately *not* mapped
(FR-010) are declared explicitly in ``unmapped_labels`` so that a typo in a
TTP rule can never silently become "unmapped".

The curated subset itself is pinned here, in code, from ARCHITECTURE.md §37.1:
a mapping may use only these techniques, with exactly these tactics and names,
under exactly this release. Broadening coverage is a Phase 2 change to the
specification and to this constant, never a YAML-only edit.
"""

from __future__ import annotations

from typing import Annotated, ClassVar, Final, Literal

from pydantic import Field, StringConstraints, model_validator

from aitl_common.config.errors import IssueType
from aitl_common.config.schemas.base import ArtifactModel, ConfigModel, fail, require_unique
from aitl_common.config.vocabulary import AttackMappingVersion, TacticId, TechniqueId, TtpLabel

# The one pinned ATT&CK Enterprise release the curated subset was checked against.
PINNED_ATTACK_RELEASE: Final = ("enterprise-attack", "15.1")

CURATED_TACTICS: Final[dict[str, str]] = {
    "TA0043": "Reconnaissance",
    "TA0006": "Credential Access",
    "TA0007": "Discovery",
    "TA0009": "Collection",
    "TA0010": "Exfiltration",
    "TA0002": "Execution",
    "TA0011": "Command and Control",
}

# technique id -> (tactic id, technique name), ARCHITECTURE.md §37.1.
CURATED_TECHNIQUES: Final[dict[str, tuple[str, str]]] = {
    "T1595": ("TA0043", "Active Scanning"),
    "T1110.001": ("TA0006", "Password Guessing"),
    "T1552.001": ("TA0006", "Credentials In Files"),
    "T1552.004": ("TA0006", "Private Keys"),
    "T1082": ("TA0007", "System Information Discovery"),
    "T1083": ("TA0007", "File and Directory Discovery"),
    "T1033": ("TA0007", "System Owner/User Discovery"),
    "T1057": ("TA0007", "Process Discovery"),
    "T1087.001": ("TA0007", "Local Account"),
    "T1016": ("TA0007", "System Network Configuration Discovery"),
    "T1005": ("TA0009", "Data from Local System"),
    "T1048": ("TA0010", "Exfiltration Over Alternative Protocol"),
    "T1059.004": ("TA0002", "Unix Shell"),
    "T1105": ("TA0011", "Ingress Tool Transfer"),
}

Name = Annotated[str, StringConstraints(min_length=1, max_length=128)]


class AttackRelease(ConfigModel):
    domain: Literal["enterprise-attack"]
    version: Annotated[str, StringConstraints(pattern=r"^[0-9]{1,3}\.[0-9]{1,3}$")]


class Tactic(ConfigModel):
    id: TacticId
    name: Name


class Technique(ConfigModel):
    id: TechniqueId
    tactic_id: TacticId
    name: Name


class TtpMapping(ConfigModel):
    label: TtpLabel
    tactic_id: TacticId
    technique_ids: tuple[TechniqueId, ...] = Field(min_length=1, max_length=8)


class AttackMapping(ArtifactModel):
    ARTIFACT_KIND: ClassVar[str] = "attack_mapping"

    version: AttackMappingVersion
    attack_release: AttackRelease
    tactics: tuple[Tactic, ...] = Field(min_length=1, max_length=14)
    techniques: tuple[Technique, ...] = Field(min_length=8, max_length=15)
    ttp_map: tuple[TtpMapping, ...] = Field(min_length=1, max_length=64)
    unmapped_labels: tuple[TtpLabel, ...] = Field(max_length=64)

    def identity(self) -> tuple[str, str]:
        return ("attack_mapping", self.version)

    @model_validator(mode="after")
    def _check(self) -> AttackMapping:
        release = (self.attack_release.domain, self.attack_release.version)
        if release != PINNED_ATTACK_RELEASE:
            raise fail(
                IssueType.INCONSISTENT,
                f"ATT&CK release {release} is not the pinned release {PINNED_ATTACK_RELEASE}",
                f"{release[0]}:{release[1]}",
            )
        require_unique(self.tactics, lambda t: t.id, "tactic")
        require_unique(self.techniques, lambda t: t.id, "technique")
        for tactic in self.tactics:
            if CURATED_TACTICS.get(tactic.id) != tactic.name:
                raise fail(
                    IssueType.UNSUPPORTED_TECHNIQUE,
                    f"tactic {tactic.id} {tactic.name!r} is not in the curated subset",
                    tactic.id,
                )
        tactic_ids = {t.id for t in self.tactics}
        for technique in self.techniques:
            if CURATED_TECHNIQUES.get(technique.id) != (technique.tactic_id, technique.name):
                raise fail(
                    IssueType.UNSUPPORTED_TECHNIQUE,
                    f"technique {technique.id} ({technique.tactic_id}, {technique.name!r}) "
                    "is not in the curated subset for the pinned release",
                    technique.id,
                )
            if technique.tactic_id not in tactic_ids:
                raise fail(
                    IssueType.UNKNOWN_REFERENCE,
                    f"technique {technique.id} names undeclared tactic {technique.tactic_id}",
                    technique.tactic_id,
                )
        used_tactics = {t.tactic_id for t in self.techniques}
        for tactic_id in sorted(tactic_ids - used_tactics):
            raise fail(IssueType.DEAD_RULE, f"tactic {tactic_id} has no technique", tactic_id)

        by_id = {t.id: t for t in self.techniques}
        require_unique(self.ttp_map, lambda m: m.label, "TTP label")
        for mapping in self.ttp_map:
            if mapping.tactic_id not in tactic_ids:
                raise fail(
                    IssueType.UNKNOWN_REFERENCE,
                    f"label {mapping.label} names undeclared tactic {mapping.tactic_id}",
                    mapping.tactic_id,
                )
            require_unique(mapping.technique_ids, lambda t: t, f"technique in {mapping.label}")
            for technique_id in mapping.technique_ids:
                mapped = by_id.get(technique_id)
                if mapped is None:
                    raise fail(
                        IssueType.UNSUPPORTED_TECHNIQUE,
                        f"label {mapping.label} names technique {technique_id} "
                        "outside the curated subset",
                        technique_id,
                    )
                if mapped.tactic_id != mapping.tactic_id:
                    raise fail(
                        IssueType.INCONSISTENT,
                        f"label {mapping.label}: technique {technique_id} belongs to "
                        f"{mapped.tactic_id}, not {mapping.tactic_id}",
                        technique_id,
                    )
        require_unique(self.unmapped_labels, lambda label: label, "unmapped label")
        overlap = {m.label for m in self.ttp_map} & set(self.unmapped_labels)
        for label in sorted(overlap):
            raise fail(IssueType.INCONSISTENT, f"label {label} is both mapped and unmapped", label)
        return self

    @property
    def mapped_labels(self) -> frozenset[str]:
        return frozenset(m.label for m in self.ttp_map)

    @property
    def tactic_ids(self) -> frozenset[str]:
        return frozenset(t.id for t in self.tactics)

    @property
    def technique_ids(self) -> frozenset[str]:
        return frozenset(t.id for t in self.techniques)
