# Test keys

No key file lives here. `scripts/test-keys.mjs <dir>` derives three throw-away Ed25519 keys from fixed seeds
(`legacy`, `index`, `ca`) when a local dry run or the repository's own CI needs them. They protect nothing, sign
nothing real and are labelled test everywhere they appear. The real keys are secrets of the `sign` and `ca`
environments (README at the root) and never touch a file in git.

- `legacy`: stands in for the legacy Ed25519 key of the 0.12 plugin index (`index.json.sig`).
- `index`: the Ed25519 half of the stand-in for the Index intermediate (`index.json.wsig`, `revoked.json.wsig`).
- `ca`: the Ed25519 half of the stand-in for the Authors CA (`.wolcert` files of the `ca` workflow).

The woltrust stand-in (`scripts/woltrust-stub.mjs`) signs the Ed25519 half for real and puts an unmistakable
placeholder in the second half, so nothing made with these keys can ever verify in woltrust.
