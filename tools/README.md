# tools

- `cdn-put`: the upload tool of the WolOS CDN, an unmodified copy of `tools/cdn-put` in
  `wonderlandos/wolos-cdn` (`cdn-put.sha256` pins it; `scripts/test.sh` checks it). The upload token goes to curl
  through a private header file, never on a command line. It is called by `scripts/publish.sh` in the `sign`
  environment only, with the secret `WOLOS_CDN_UPLOAD_TOKEN` as `UPLOAD_TOKEN`.
- `hubcheck.rev`: the commit of `wonderlandos/hub` that the `check` workflow builds `hubcheck` from.
- `woltrust.rev`: the commit of the woltrust crate the `sign` and `ca` workflows build `woltrust` from.

A `.rev` file holds one line, a 40-digit commit id, or the word `unpinned` while the tool does not exist yet. A
workflow that is not a dry run stops on `unpinned`.
