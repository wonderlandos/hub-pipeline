# tools

- `cdn-put`: the upload tool of the WolOS CDN, an unmodified copy of `tools/cdn-put` in
  `wonderlandos/wolos-cdn` (`cdn-put.sha256` pins it; `scripts/test.sh` checks it). The upload token goes to curl
  through a private header file, never on a command line. It is called by `scripts/publish.sh` in the `sign`
  environment only, with the secret `WOLOS_CDN_UPLOAD_TOKEN` as `UPLOAD_TOKEN`.
- `hubcheck.rev`: the commit of `wonderlandos/hub` that `scripts/tool.sh hubcheck` builds `wasm/` `hubcheck` from
  (`f2bce73`, HUB-wasm's native command; check workflow, test.sh). `a0fcf58` before it refused a package with
  `screenshots/` members; `f2bce73` reads the listing from the package (report key `facts`) and has `hubcheck extract`,
  which `check-release.mjs` uses for the icon and screenshots. It is the newest `wasm/` commit; it depends on
  woltrust `0b00c1e` (classes and file certificates) and so does not know the 128-hex certificate ids or the two-root intermediates of `68b5a03`:
  a hub commit that bumps `wasm/Cargo.toml` to woltrust `68b5a03` is needed before the check job can verify files
  signed under the real roots (until then they come out as `community`, never as `pass` with a certificate).
- `woltrust.rev`: the commit of `wonderlandos/wolos` that `scripts/tool.sh woltrust` builds `crates/woltrust` `woltrust` from
  (`68b5a03`, trust phase 4, branch `wave3/trust-core`: SHA-512 certificate ids, both roots on intermediates, `rkdb`
  make/checkpoint/verify, emergency sections, class/origin_cert in certificate bodies; sign and ca workflows, test.sh).
- `woltrust.sha256`, `hubcheck.sha256`: sha256 of the binaries `tool.sh` built from those commits here (rustc 1.99.1,
  x86_64 Linux). `tool.sh` compares and warns when a build differs (another rustc gives other bytes);
  `TOOL_SHA256_STRICT=1` turns the warning into a refusal. Remake them with `sha256sum` after moving a `.rev`.

A `.rev` file holds one line, a 40-digit commit id, or the word `unpinned` (tool.sh then builds nothing and exits 3). To move a
tool: put the new commit id in its `.rev`, run `scripts/test.sh` (and `fixtures/gen/run.sh` plus
`SAMPLE_OUT=fixtures/sample-signed scripts/test.sh` if the formats changed), write the new `.sha256`, update
`tools/woltrust.features`, commit together.

The wolos workspace lists `crates/shell`, a submodule: tool.sh checks out only that one, at the commit the pinned tree records,
from `wonderlandos/wolos-shell` (or from `$WOLTRUST_SRC/crates/shell`), because cargo reads its manifest to load the workspace.
