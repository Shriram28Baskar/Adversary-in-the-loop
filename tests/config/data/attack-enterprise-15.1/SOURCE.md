# Vendored evidence: MITRE ATT&CK Enterprise 15.1 (curated subset)

`curated_subset.json` is a minimal extract of the official MITRE ATT&CK
Enterprise **15.1** STIX 2.1 bundle. It contains only the objects that
`config/attack/attack_mapping_v1.yaml` uses: 7 tactics and 14 techniques,
plus each sub-technique's parent ID and name. For each object it keeps the
external ID, name, STIX ID, tactic membership, sub-technique flag, domains,
and revoked and deprecated flags (P5-D9; ARCHITECTURE.md ADR-025).

- Source bundle: `https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack-15.1.json`
- Collection: "Enterprise ATT&CK", `x_mitre_version` 15.1, modified `2024-05-02T14:00:00.188Z`
- Source bundle SHA-256: `a57988bffe402bb3e19d92dbe80a12143e1970b814e013e080f9df2fa5a3f6bc` (43,474,692 bytes)
- Extract SHA-256: `aee56a9d3556cc5f2f537f7e7c5e068129015c5504b7af93c3533443278f972c`
- Extraction: `tests/config/attack_extract.py` (offline, P0 canonical JSON), run
  once against the bundle above:

  ```
  uv run python -m tests.config.attack_extract enterprise-attack-15.1.json \
      https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack-15.1.json \
      > tests/config/data/attack-enterprise-15.1/curated_subset.json
  ```

This file is evidence and validation data for `tests/config/test_attack_evidence.py`.
No runtime code reads it, and nothing in the platform fetches ATT&CK data
from the network. The full bundle is deliberately not vendored.

## Attribution (MITRE ATT&CK Terms of Use)

© 2024 The MITRE Corporation. This work is reproduced and distributed with
the permission of The MITRE Corporation. MITRE ATT&CK® and ATT&CK® are
registered trademarks of The MITRE Corporation.
