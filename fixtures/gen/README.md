# fixtures/gen

`run.sh` rewrites the binary fixtures from the TEST authority of woltrust at the commit of `tools/woltrust.rev`:
`fixtures/assets/{alice.notes-1.0.wol, alice.weather-1.2.wolplug, examplelabs.notes-sync-0.3.wolext, mallory.tool-1.0.wol}`,
`fixtures/trust/` and `fixtures/request-issue.json`. It copies `hub_index_fixtures.rs` into `crates/woltrust/examples/` of a fresh
clone at that commit and runs it there with `--locked`, so it uses nothing but woltrust and its own locked dependencies. Every byte is
deterministic (public seeds, fixed tar headers); `dave.swapped-2.0.wol` is not touched (its size never matches, so no checker sees it).

```
fixtures/gen/run.sh                         clone wonderlandos/wolos
WOLTRUST_SRC=~/wolos fixtures/gen/run.sh    clone a local repository instead (its commits only)
```

After a change: `SAMPLE_OUT=fixtures/sample-signed scripts/test.sh`, and update sizes and sha256 in `fixtures/{pending,export,github}.json`.
