"""Accepted artifact versions are immutable (P2; PRD FR-044; engineering plan §15).

Every accepted artifact version is pinned here by its canonical content hash.
Editing an accepted version in place - even a whitespace-insensitive semantic
change - fails this test. The only legitimate change is a *new* version
(e.g. ``target_v2.yaml``), which is added below as a new line; an existing
line is never edited or removed. The database registry enforces the same rule
for deployed versions (``hash_mismatch``).
"""

from __future__ import annotations

from aitl_common.config.bundle import load_config
from tests.config.helpers import CONFIG_ROOT

ACCEPTED: dict[tuple[str, str, str], str] = {
    (
        "abstraction_table",
        "abstraction_table",
        "abstraction-table-v1",
    ): "79c69b0a95e4dc5589078f9bb2de77443b3514337d894bcea6995280ba45c6f0",
    (
        "agent_config",
        "assistant_llm",
        "1",
    ): "acf3efd5e74bdb35481f8d2bf16f7f05f2d0082a01fd6dcc5fa74b6367ecddbe",
    (
        "agent_config",
        "assistant_scripted",
        "1",
    ): "404569ea8b68d7a51edb6ac4eaf072ea15bf0da43f20ee2663b58d05ac289cce",
    ("agent_task", "TK-1", "1"): "3b78e22c4b38e09f6279b89eb0d0b7d0ac3b4a28341587919602f5df8a0cf471",
    (
        "attack_mapping",
        "attack_mapping",
        "attack-mapping-v1",
    ): "ff5a94c70ab47fd5b9471f0e6424cd5ee7cef4b556ef2e6e2ee002e2b1810c8e",
    (
        "eval_config",
        "eval_config",
        "eval-v1",
    ): "c36d0061031993507e05ce0f5c2ad975c07328b28275d0174a4b2fed27d584c0",
    (
        "fixture_set",
        "fixture_set",
        "fixture-set-v1",
    ): "4878d5df3a06c736168c60baa96b7ebcdea4516c94857d6a93c95a2adff5d969",
    (
        "phase_rules",
        "phase_rules",
        "phase-rules-v1",
    ): "fd3f4aa80382866967c82f295041a200fa05f08cd93bd92b359c61a61682dd66",
    (
        "policy",
        "baseline-permissive",
        "1",
    ): "3d201db45735e8d0ae96361c1018fd2192b10bb96a47e55379dc25fa7911a845",
    ("policy", "target", "1"): "d65afc8e293d59df19c1dba1053180525d1fece63a96a7faf4cd06f3b2bc6316",
    (
        "scenario_template",
        "T-01",
        "template-library-v1",
    ): "f148f59bd8b652779d2ddd96c0feb1295e69b090426422997420e6b43cba31f2",
    (
        "scenario_template",
        "T-02",
        "template-library-v1",
    ): "ed4fbd59820d7af513837507bd4f011199292b0c28db7b7ca062391310430a69",
    (
        "scenario_template",
        "T-03",
        "template-library-v1",
    ): "3d7befe72043ab4a66c4146508cb7a672ed30f9ab2313515ff71644d6bba6ffd",
    (
        "scripted_plan",
        "T-01",
        "1",
    ): "6c1ba48f07c221641ddfe9ca5a8d480aa6fc5f12010b0cc208dc617244037d7f",
    (
        "scripted_plan",
        "T-02",
        "1",
    ): "1fc6ec3bff07226cf3b80382d866240815a48742325e3cddb2281ebb5ede9563",
    (
        "scripted_plan",
        "T-03",
        "1",
    ): "80e4e663e9c5b9f457bbed70cf71f38fef6f38aca078fd5a076f954fc9540cc4",
    (
        "system_prompt",
        "system",
        "1",
    ): "789e498276f3c867df7e0c3e31cc32034de33a5da96423ad2e9b99de67a2c088",
    (
        "template_library",
        "template_library",
        "template-library-v1",
    ): "e264a953273775592bf47b611a94c8acc853b694ba954daff4a2c1245f84218b",
    (
        "tool_definitions",
        "tool_definitions",
        "tool-definitions-v1",
    ): "fe6ef1822e98c225687498adb1945a192044595c9a2a3054b9d449c8a02d30af",
    (
        "ttp_rules",
        "ttp_rules",
        "ttp-rules-v1",
    ): "4d9f32d464c614c4aefc8aa5a1cf5277b94dc4eb65ea8750a7507a1872cb926d",
}


def test_accepted_versions_are_unchanged() -> None:
    current = {
        (row["kind"], row["id"], row["version"]): row["sha256"]
        for row in load_config(CONFIG_ROOT).inventory()
    }
    changed = {key for key in ACCEPTED if key in current and current[key] != ACCEPTED[key]}
    assert changed == set(), f"accepted versions edited in place (create a new version): {changed}"


def test_accepted_versions_are_never_removed() -> None:
    current = {
        (row["kind"], row["id"], row["version"]) for row in load_config(CONFIG_ROOT).inventory()
    }
    assert set(ACCEPTED) - current == set()


def test_every_artifact_is_accepted() -> None:
    """A new version must be added to ACCEPTED deliberately, in review."""
    current = {
        (row["kind"], row["id"], row["version"]) for row in load_config(CONFIG_ROOT).inventory()
    }
    assert current - set(ACCEPTED) == set()
