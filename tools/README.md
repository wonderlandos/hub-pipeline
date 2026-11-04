# tools

- `cdn-put`: the upload tool of the WolOS CDN, an unmodified copy of `tools/cdn-put` in
  `wonderlandos/wolos-cdn` (`cdn-put.sha256` pins it; `scripts/test.sh` checks it). The upload token goes to curl
  through a private header file, never on a command line. It is called by `scripts/publish.sh` in the `sign`
  environment only, with the secret `WOLOS_CDN_UPLOAD_TOKEN` as `UPLOAD_TOKEN`.
- `hubcheck.rev`: the commit of `wonderlandos/hub` that `scripts/tool.sh hubcheck` builds `wasm/` `hubcheck` from
  (`7c752c9`, HUB-wasm's native command; check workflow, test.sh).
- `woltrust.rev`: the commit of `wonderlandos/wolos` that `scripts/tool.sh woltrust` builds `crates/woltrust` `woltrust` from
  (`fe64176`, branch `wave3/trust-core`; sign and ca workflows, test.sh).

A `.rev` file holds one line, a 40-digit commit id, or the word `unpinned` (tool.sh then builds nothing and exits 3). To move a
tool: put the new commit id in its `.rev`, run `scripts/test.sh` (and `fixtures/gen/run.sh` plus
`SAMPLE_OUT=fixtures/sample-signed scripts/test.sh` if the formats changed), commit together.

The wolos workspace lists `crates/shell`, a submodule: tool.sh checks out only that one, at the commit the pinned tree records,
from `wonderlandos/wolos-shell` (or from `$WOLTRUST_SRC/crates/shell`), because cargo reads its manifest to load the workspace.
