# WolOS Hub index

The signed index of the WolOS Hub and its public log: every index that was ever signed, every check verdict,
every certificate and every revocation. Built and signed by GitHub Actions in this repository, nowhere else. Design:
ADR 0047 (the Hub), ADR 0046 (author certificates). Licence GPL-2.0-or-later.

Nothing is hosted here but metadata. Release files stay GitHub release assets, pinned by sha256.

## The public log

```
signed/                     the last publication: index.json, index.json.sig, index.json.wsig, revoked.json, revoked.json.wsig
                            (git history of this folder = every index ever signed, append-only; commits come from the sign workflow)
verdicts/<id>/<version>.json   one check verdict per release (verdict, findings, sha256, size, run, workflow sha)
certs/<serial>.wolcert      every author certificate the Authors CA issued
certs/intermediates/        intermediate certificates to carry in index.json (newer than the image's trust store)
requests/*.json             open certificate requests; requests/done/ the handled ones
revocations.json            the entries of the revocation list (appended by the ca workflow, never edited by hand)
schema/                     index.schema.json (I3), revoked.schema.json, request.schema.json
scripts/  tools/  fixtures/  compat/  docs/    the pipeline code, pinned tools, test data, 0.12 compatibility tests
.github/workflows/          check.yml  sign.yml  ca.yml  ci.yml
```

Clients read the CDN, not this repository: `https://cdn.wolos.org/plugins/{index.json,index.json.sig,index.json.wsig,revoked.json,revoked.json.wsig}`.
This repository is the log and the mirror (ADR 0047, option C): the same bytes, with history.

## How a release gets listed

1. An author registers a listing on hub.wolos.org (signed in with GitHub, CLA accepted) and publishes a GitHub release with the file as an asset.
2. The GitHub App's release webhook reaches the Worker, which records the release as `pending` (tag, commit, asset URL, size).
3. **check** (every 15 minutes): `fetch` asks `GET /api/pipeline/pending`; `scan` downloads each file from its own
   `github.com/<repo>/releases/download/<tag>/<asset>` URL (https only, 1 GiB at most), compares the size the Worker recorded, computes
   the sha256 and runs the native `hubcheck`; `report` posts `POST /api/pipeline/verdicts` and writes `verdicts/<id>/<version>.json`.
   A file that cannot be fetched, is too large, or that hubcheck did not finish on is `not-checked`, never `pass`. A file whose size
   is not the one GitHub listed is `block`. The Worker pins the first sha256: a different file behind the same tag is blocked there too.
4. **sign** (every hour, and whenever a revocation is made): `GET /api/pipeline/export`; every entry new since the last signed index is
   checked against GitHub itself (`verify-owners.mjs`: the repository by numeric id, its owner id, a published release at the tag whose asset has
   this URL and size), so a taken-over Worker cannot attach a release to someone else's id; then `build-revoked.mjs`, `build-index.mjs`
   (schema and rules, deterministic bytes), signing, upload to the CDN under `plugins/`, and the commit to `signed/`. If nothing changed the
   signed copy is left alone until it is a day old (the index expires in 7 days and is re-signed at least daily).
5. The OS fetches the index, shows the listing, downloads the asset from GitHub and checks size and sha256 itself.

An entry that breaks a rule of `schema/index.schema.json` is left out with a warning in the run, never repaired. An index that would lose more
than half of a real one is not signed without a person saying `force`.

## How a revocation propagates

1. A moderator or the CA operator writes `requests/<name>.json` (`action: revoke`, serial, reason, approvers; `abuse` needs two different people).
2. They start **ca** (manual; environment `ca` needs a reviewer to approve the run). It checks the request against the schema, refuses a serial that
   was not issued here, appends `{serial, at, reason}` to `revocations.json`, moves the request to `requests/done/`, commits, and starts **sign**.
3. **sign** builds `revoked.json` (format 1, serial grows, `expires` = issued + 7 days, the exact shape woltrust reads), signs it with the Index
   intermediate (label `wolos/revocation/1`), and points the index at it (`revoked: {url, sha256, serial}`). Upload order: revoked.json and its
   .wsig first, index.json last.
4. Online machines take the new list with the next index refresh, within the hour; an offline machine keeps the last one it saw (fresh until `expires`,
   stale up to 30 days after, then verified files count as unsigned). `key-compromise` and `abuse` void every signature of that certificate,
   whenever made; `superseded` and `ceased` keep what the index saw before `at`. Revoking an intermediate or a root is not done here: only a
   root-signed list may (offline ceremony).

## What each environment holds

Secret values live only in the repository's Environment settings. This repository contains names, never values.

| Environment | Used by | Secrets | Variables | Rules |
|---|---|---|---|---|
| none | `ci.yml`, job `scan` of `check.yml` | none | none | `scan` has no `id-token`, no write right, no environment: it opens untrusted files and has nothing to lose |
| `check` | jobs `fetch` and `report` of `check.yml` | none | none | OIDC only (audience `hub.wolos.org`); the Worker accepts this workflow file on `main` with environment `check`; it can read pending and post verdicts, not export |
| `sign` | `sign.yml` | `WOLOS_INDEX_SIGNING_KEY` (Index intermediate), `WOLOS_LEGACY_INDEX_KEY` (legacy Ed25519 PEM), `WOLOS_CDN_UPLOAD_TOKEN` | `INDEX_CERT_SERIAL`, optional `CDN_BASE` | deployment branch `main` only; OIDC token can export, not post; parses no release file |
| `ca` | `ca.yml` | `WOLOS_AUTHORS_CA_KEY` (Authors CA intermediate) | `AUTHORS_CA_SERIAL` | required reviewers (a second person), deployment branch `main` only |

Repository variable `HUB_PIPELINE_ENABLED=true` switches the schedules on (check and sign do nothing on a schedule until it is set). The roots
are never here: they are offline and sign only intermediates.

Set up once: branch protection on `main` with the Actions bot allowed to push `signed/`, `verdicts/`, `certs/`, `revocations.json`, `requests/`
(no other path, no force-push); CODEOWNERS on `.github/`, `scripts/`, `tools/`, `schema/`; "Require approval for all outside collaborators".
The workflows pin every third-party action by commit id; `tools/*.rev` pin the tools.

## Tooling contract (what the workflows call)

`hubcheck` (HUB-wasm, `wonderlandos/hub` `wasm/bin/hubcheck`, pinned in `tools/hubcheck.rev`; `unpinned` stops the job):
`hubcheck --json --kind app|plugin|extension --id ID --version V [--host APP] [--previous-version P] FILE` prints
`{"verdict","findings":[{"rule","sentence","evidence"}]}` and may add `"trust"` and `"cert":{"serial"}` (the I7 outcome of the trust crate); exit 0 only when it decided.

`woltrust` (the woltrust crate of wolos has the library and `woltrust-vectors` today, no signing command; pinned in `tools/woltrust.rev`):
- `woltrust sign --purpose index|revocation|package|plugin|extension --cert SERIAL (--key-env NAME | --key-file F) FILE` prints the `.wsig` (`{"cert","ed25519","second"}`) over `label || 0x00 || SHA-512(FILE)`;
- `woltrust issue --body BODY.json [--proof PROOF.json] (--key-env NAME | --key-file F)` prints the `.wolcert` whose `body` is exactly the bytes of BODY.json (`ca.mjs` refuses an answer whose body differs).

`scripts/woltrust-stub.mjs` and `scripts/hubcheck-stub.sh` follow the same command lines for dry runs; the stub's second half is a placeholder that can never verify, and every non-dry run refuses the stubs.

## Running it locally

```
scripts/test.sh                 everything below, no secret, no network (needs node 20+, openssl, curl)
node scripts/validate.mjs index fixtures/sample-signed/index.json
SAMPLE_OUT=fixtures/sample-signed scripts/test.sh     remake the TEST sample
```

`test.sh` runs a mock Worker on 127.0.0.1 (it keeps the check/sign token separation), the check scripts over `fixtures/assets` (an app that passes, a plugin that
passes, an extension that is flagged, a blocked file, a file that is gone, a file whose size changed), the sign scripts with test keys
derived from fixed seeds (`docs/test-keys.md`), the ca script with a test CA, and over 30 negative cases (a bad URL, an id outside the owner's namespace, a
tampered index, an owner taken over, an index that lost most of its entries, ...). In GitHub, `sign.yml` and `ca.yml` start as dry runs (the default of `dry_run`).

## Checked against the 0.12 reader

The format is today's plugin index plus new keys; the 0.12 parser has no `deny_unknown_fields`, so it ignores them and drops an entry that breaks its own
rules (a plugin with no `kinds`, for example, as the Worker's export has today; 0.12 also requires the
index key on the file, so it lists only plugins WolOS signed itself). `scripts/legacy-check.mjs` ports the reader to Node for every run of `test.sh`. The real Rust reader was run on the sample:
`compat/wopkg_hubindex.rs` copied to `crates/wopkg/tests/` of a wolos checkout, `HUBINDEX_SAMPLE=<this repo>/fixtures/sample-signed cargo test -p wopkg --test <name>`
(`plugins::verify` accepts the signature and keeps `alice.weather`; a changed byte is refused). `compat/woltrust_hubindex.rs` does the same for `woltrust::revoked::parse` and `Wsig::parse`.
