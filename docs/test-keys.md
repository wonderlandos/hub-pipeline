# Test keys

No key file lives here. Every key a local dry run or this repository's CI uses derives from a public name, so anyone can
rebuild it and it protects nothing. `scripts/test-keys.mjs <dir>` writes them when a run needs them; they are labelled
test everywhere they appear. The real keys are secrets of the `sign` and `ca` environments (README at the root) and never
touch a file in git.

- `legacy`: Ed25519 from the seed `[1;32]`, standing in for the legacy key of the 0.12 plugin index (`index.json.sig`).
- `index`: woltrust key material of `test-index`, the TEST Index intermediate of woltrust's TEST authority
  (`woltrust::pki`: seed = SHA-512(`woltrust/testseed/test-index`)[0..32], serial = SHA-512(`woltrust/serial/test-index`)[0..8],
  `0e972272c2e22af3`). Signs `index.json.wsig` and `revoked.json.wsig` in dry runs, with the real woltrust.
- `authors`: the same for `test-authors`, the TEST Authors CA (`2ae32495ac831014`). Issues certificates in dry runs.
- `hub-index-request-alice` (test.sh only): the key of the TEST request `fixtures/request-issue.json`, to sign a file with the
  certificate the test issues.

Their certificates are `fixtures/trust/` (written by `fixtures/gen/run.sh`): `roots/test-root-a.wolcert` and
`intermediates/test-{index,authors}.wolcert`, the same bytes as woltrust's vectors and hubcheck's fixtures. Their subject labels
start with `test`, so woltrust and hubcheck refuse the root unless asked (`--allow-test`, `allow_test`), and `scripts/store.mjs`
allows that only with `HUB_TEST=1` or `DRY_RUN=1`. A file signed by the TEST authority verifies only in a test.
