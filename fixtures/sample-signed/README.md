# TEST sample

What `SAMPLE_OUT=fixtures/sample-signed scripts/test.sh` produced from `fixtures/` at the fixed time 1793750400: the files
`sign.yml` would publish, signed by the real woltrust (`tools/woltrust.rev`) with the TEST Index intermediate of woltrust
(`0e972272c2e22af3`, `docs/test-keys.md`). `index.json.sig` is a real Ed25519 signature by the test `legacy` key
(`legacy-test-key.pub.hex`). The signatures are deterministic, so `scripts/test.sh` checks that a fresh run makes these exact bytes.

They verify, and only in a test:

```
woltrust verify --purpose index --wsig index.json.wsig --roots ../trust/roots --intermediates ../trust/intermediates \
    --list revoked.json --allow-test --now 1793750400 index.json        -> trust wolos, exit 0
```

Without `--allow-test` the TEST root does not count. Never publish these files.
