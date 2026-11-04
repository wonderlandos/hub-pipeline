# TEST sample

What `SAMPLE_OUT=fixtures/sample-signed scripts/test.sh` produced from `fixtures/` at the fixed time 1793750400:
the files `sign.yml` would publish, signed with throw-away TEST keys. `index.json.sig` is a real Ed25519 signature by the
test `legacy` key (`legacy-test-key.pub.hex`); the `.wsig` files carry a real Ed25519 half and an unmistakable
placeholder as the second half, so they parse everywhere and verify nowhere. Never publish these files.
