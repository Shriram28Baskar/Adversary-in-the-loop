# Vendored reference: Cowrie 3.0.15 default configuration

`cowrie.cfg.dist` is the bundled default configuration of Cowrie 3.0.15
(`src/cowrie/data/etc/cowrie.cfg.dist`), copied unmodified from the release
source distribution on PyPI:

- `cowrie-3.0.15.tar.gz`, sha256
  `ef7d0322844e516c173e1886ff3cf28a9ab4f261e50dc3941cbf3d34a96abaf1`.

The pinned container image `cowrie/cowrie:3.0.15` (index digest in
`deploy/versions.env`) is built from the same release; its Dockerfile
(`docker/Dockerfile` in the same tarball) runs Cowrie as UID/GID 999 from
`/cowrie/cowrie-git`, reading the bundled defaults plus `etc/cowrie.cfg`.

It is used only by `tests/security/test_cowrie_config.py` to compute the
effective configuration (defaults + `honeypot/cowrie/etc/cowrie.cfg`). It is
test data, never deployed. Its placeholder credentials (for disabled output
plugins) are upstream examples, not secrets. License: `LICENSE.rst`
(BSD-3-Clause).
