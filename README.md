# WolOS Hub pipeline (private)

The code and process of the WolOS Hub index: the check, sign and ca workflows, their scripts, the pinned tools, the test
fixtures and the 0.12 compatibility tests. It builds and signs the index, issues and revokes author certificates, and
writes every published result to the public log, **wonderlandos/hub-log**. Design: ADR 0047 (the Hub), ADR 0046 (author
certificates). Licence GPL-2.0-or-later.

## Why this repository is private, and what moved

Lead decision 2026-11-04 03:37Z: close the parts of the hub that only the hub runs, to cut the attack surface (no public map
of the identity checks, the key handling, the request flow or the workflow conditions to probe). The public contract stays
public: hub-log carries everything that is published and signed, and the JSON schemas; `wonderlandos/hub` keeps the site,
the `hubcheck` crate (`wasm/`) and the legal texts; woltrust is public in `wonderlandos/wolos`.

`wonderlandos/hub-index` was split in two, with history (`git filter-repo`):

| here, private (wonderlandos/hub-pipeline) | public (wonderlandos/hub-log) |
|---|---|
| `.github/workflows/` (check, sign, ca, ci), `scripts/`, `tools/`, `fixtures/`, `compat/`, `docs/`, `requests/` (hand-written requests), this README | `signed/`, `verdicts/`, `certs/` (roots, intermediates, author certificates and their records), `revocations.json` |
| `schema/` (a copy; every sign and ca run stops if it differs from hub-log's) | `schema/` (the public contract), a README on how to verify with woltrust |

No workflow writes to this repository: each job checks this repository out read-only, checks hub-log out at `log/`, and
`scripts/commit-log.sh` pushes only `signed/`, `verdicts/`, `certs/` and `revocations.json` there, with the job environment's
deploy key (secret `HUB_LOG_DEPLOY_KEY`). Request files are never published any more: the ca job keeps the request it handled
as a run artifact of this repository (90 days), and the Worker keeps its record; hub-log has the certificate, its record
(`certs/<serial>.json`, with `request_id`, tier and approvers) and `revocations.json`.

## The layout

```
here (hub-pipeline)
scripts/  tools/  fixtures/  compat/  docs/    the pipeline code, pinned tools, test data (fixtures/trust: the TEST authority), 0.12 compatibility tests
.github/workflows/          check.yml  sign.yml  ca.yml  ci.yml
requests/<name>.json        hand-written requests (a revocation, an operator's issue), reviewed into main
schema/                     copy of hub-log's schema/

log/ in every job = wonderlandos/hub-log
signed/                     the last publication: index.json, index.json.sig, index.json.wsig, revoked.json, revoked.json.wsig,
                            revoked.rkdb (the revocation database), revoked.checkpoint.json (its checkpoint), intermediates.json
                            (JSON array of certs/intermediates/*.wolcert), emergency.rkdr (while one is in force), release.json.wsig
                            (git history of this folder = every index ever signed, append-only; commits come from the sign workflow)
revoked.checkpoint.json     the checkpoint again at the root: crates/core/src/cdn.rs RKDB_CHECKPOINTS reads it there and on the CDN
verdicts/<id>/<version>.json   one check verdict per release (verdict, findings, sha256, size, run, workflow sha)
pictures/<sha256>.<png|webp>   the icons and screenshots hubcheck extract found in passed packages (re-checked by hash, size and header; sign.yml puts them on the CDN as plugins/pictures/)
certs/<serial>.wolcert      every author certificate the Authors CA issued; certs/<serial>.json its record (tier, request_id, ...)
certs/roots/                the public root certificates (the ones the image pins), for hubcheck and the sign job's self-check
certs/intermediates/        intermediate certificates to carry in index.json (newer than the image's trust store)
revocations.json            the entries of the revocation list (appended by the ca workflow, never edited by hand)
schema/                     index.schema.json (I3), revoked.schema.json, request.schema.json
```

Clients read the CDN, not a repository: `https://cdn.wolos.org/plugins/{index.json,index.json.sig,index.json.wsig,revoked.json,revoked.json.wsig,revoked.rkdb,revoked.checkpoint.json,intermediates.json,emergency.rkdr}`
(crates/core/src/trust.rs `REVOKED_PATH`, `RKDB_PATH`, `EMERGENCY_PATH`, `INTERMEDIATES_PATH`; cdn.rs `RKDB_CHECKPOINTS`) and
`https://cdn.wolos.org/latest/release.json.wsig` beside the release manifest. hub-log is the log and the mirror (ADR 0047, option C): the same bytes, with history.

## Trust phase 4 (woltrust 68b5a03)

- A certificate id is SHA-512 over its public keys (128 hex, rule "IDS"); `ca.mjs` derives it (`lib.mjs keyId`) and `woltrust issue`
  refuses any other. The same keys always give the same id, so a second certificate for the same keys is refused (a revoked key
  stays revoked: new keys). 16-hex serials remain for the TEST authority and for release statements; `lib.mjs SERIAL` is the one
  pattern every script and schema uses.
- The real roots and intermediates live in hub-log `certs/roots` and `certs/intermediates` (`root-a-<id>`, `root-b-<id>`,
  `authors-ca-`, `packages-ca-`, `index-`, `witness-a-`, `witness-b-`); every intermediate carries both roots' signatures. The
  sign job verifies against them (`SIGN_ROOTS`, `SIGN_INTERMEDIATES`); the variables `INDEX_CERT_SERIAL` and `AUTHORS_CA_SERIAL`
  hold the 128-hex ids.
- `sign-files.sh` makes `revoked.rkdb` (`woltrust rkdb make`, chained to `log/signed/revoked.rkdb`: serial + 1, no entry lost,
  checked with `rkdb delta`), `revoked.checkpoint.json` (`rkdb checkpoint`), `intermediates.json`, carries `emergency.rkdr` inside
  the database when hub-log `signed/emergency.rkdr` exists (made offline with `woltrust emergency`, committed by hand), and signs a
  release manifest (`sign.yml` input `release_manifest`, an https URL) as `release.json.wsig` with label `wolos/index/1` (what
  `wol_core::update::check` reads). `revoked.json` is valid 24 hours (`rkdb::LIFETIME`), re-signed hourly.
- The proof of possession covers login, name, organisation and namespaces too (`woltrust::request::Claimed`): `ca.mjs` refuses a
  request whose signed claims are not what GitHub shows, before anything is signed. Bodies carry `class` and, for trusted,
  `origin_cert` (`tools/woltrust.features`: `class`, `withdrawn-version`; `statements` stays off: the 68b5a03 command line has no
  `--purpose release`).
- Revocations the hub approved (HUB-worker-3): `ca.yml` dispatched with a `v-...` id fetches a revoke request
  (`GET /api/pipeline/requests/v-...`, schema `id`, `note`), appends it, and reports `POST /api/pipeline/revocations
  {request_id, serial}` (`api.mjs revoked`). Issue requests for trusted carry `origin_cert`, checked against the subject's active
  origin certificate.
- hubcheck is at `3af340f` (`wonderlandos/hub` `wasm/`: `f2bce73`'s listing facts and `hubcheck extract`, built on woltrust `b8bbd2d`, the same
  trust phase 4 as `tools/woltrust.rev`): it reads 128-hex ids and two-root intermediates, so files signed under the real roots verify.

## How a release gets listed

1. An author registers a listing on hub.wolos.org (signed in with GitHub, CLA accepted) and publishes a GitHub release with the file as an asset.
2. The GitHub App's release webhook reaches the Worker, which records the release as `pending` (tag, commit, asset URL, size).
3. **check** (every 15 minutes): `fetch` asks `GET /api/pipeline/pending`; `scan` downloads each file from its own
   `github.com/<repo>/releases/download/<tag>/<asset>` URL (https only, 1 GiB at most), compares the size the Worker recorded, computes
   the sha256 and runs the native `hubcheck` against the trust store (`certs/roots`, `certs/intermediates`, `signed/revoked.json`); `report` posts `POST /api/pipeline/verdicts` and writes `verdicts/<id>/<version>.json`.
   A file that cannot be fetched, is too large, or that hubcheck did not finish on is `not-checked`, never `pass`. A file whose size
   is not the one GitHub listed is `block`. The Worker pins the first sha256: a different file behind the same tag is blocked there too.
4. **sign** (every hour, and whenever a revocation is made): `GET /api/pipeline/export`; every entry new since the last signed index is
   checked against GitHub itself (`verify-owners.mjs`: the repository by numeric id, its owner id, a published release at the tag whose asset has
   this URL and size), so a taken-over Worker cannot attach a release to someone else's id; then `build-revoked.mjs`, `build-index.mjs`
   (schema and rules, deterministic bytes), signing (then `woltrust verify` of both signatures against `certs/roots`: what does not
   verify is not uploaded), upload to the CDN under `plugins/`, and the commit to `signed/`. If nothing changed the
   signed copy is left alone until it is a day old (the index expires in 7 days and is re-signed at least daily).
5. The OS fetches the index, shows the listing, downloads the asset from GitHub and checks size and sha256 itself.

An entry that breaks a rule of `schema/index.schema.json` is left out with a warning in the run, never repaired. An index that would lose more
than half of a real one is not signed without a person saying `force`.

## How a revocation propagates

1. A moderator or the CA operator writes `requests/<name>.json` (`action: revoke`, serial, reason, approvers; `abuse` needs two different people).
2. The file reaches `main` through a reviewed pull request; they start **ca** with `request=requests/<name>.json`. It checks the request
   against the schema, refuses a serial that was not issued here, appends `{serial, at, reason}` to hub-log `revocations.json`, commits it there, and starts **sign**. Remove the request file in a later pull request.
3. **sign** builds `revoked.json` (format 1, serial grows, `expires` = issued + 7 days, the exact shape woltrust reads), signs it with the Index
   intermediate (label `wolos/revocation/1`), and points the index at it (`revoked: {url, sha256, serial}`). Upload order: revoked.json and its
   .wsig first, index.json last.
4. Online machines take the new list with the next index refresh, within the hour; an offline machine keeps the last one it saw (fresh until `expires`,
   stale up to 30 days after, then verified files count as unsigned). `key-compromise` and `abuse` void every signature of that certificate,
   whenever made; `superseded` and `ceased` keep what the index saw before `at`. Revoking an intermediate or a root is not done here: only a
   root-signed list may (offline ceremony).

## How a certificate is issued

There are two tiers of author certificate (lead decision 2026-11-04), for persons and for organisations (a company too):

| tier | says | issued when | index shows its files as |
|---|---|---|---|
| `origin` | who made the file and from which repository | automatically, once the person or organisation has accepted the CLA (`cla_accepted_at`) | `origin` |
| `trusted` | a developer or organisation the hub vetted | automatically, once an admin approves in the admin panel (`approved_by` in `CA_APPROVERS`) | `trusted` |

An account may hold one active certificate of each tier. Revoking a trusted certificate with reason `superseded` downgrades: the
index then shows the files it signed as `origin` (`build-index.mjs --certs certs --revocations revocations.json`). `key-compromise` and
`abuse` revoke as before: woltrust withdraws every signature of that certificate on every client. The tier is recorded next to the
certificate in `certs/<serial>.json`
(`{serial, tier, kind, github_id, login, request_id, issued_at, approved_by+approved_at | cla_accepted_at}`). A certificate without that
record (issued before the tiers) counts as trusted. TRUST-core-4 puts the tier into the signed body too (`"class":"origin"|"trusted"`,
a trusted certificate carrying `"origin_cert"`, the serial of the subject's origin certificate, so an origin certificate comes first);
`ca.mjs` writes those keys once `tools/woltrust.features` lists `class` (woltrust `fe64176` refuses unknown body keys).

Issuing needs no person in GitHub.

1. The author runs `wol cert request` (woltrust `request::Request`): keys made on their machine, the public halves (Ed25519, ML-DSA-65,
   and the encryption keys X25519 and ML-KEM-768) and a proof of possession, sent to the Worker (`POST /api/certs/requests`).
2. For `origin`, the Worker checks its record that the CLA was accepted and adds `cla_accepted_at`. For `trusted`, a hub admin approves
   in the admin panel; the Worker refuses an admin approving their own request and adds `approved_by` (the admin's GitHub login) and
   `approved_at`. Then it stores the request as the file below and starts the ca workflow through the GitHub API:
   `POST /repos/wonderlandos/hub-pipeline/actions/workflows/ca.yml/dispatches` with `{"ref":"main","inputs":{"request_id":"<id>","dry_run":"false"}}`,
   using the hub GitHub App's installation token (on this repository it has `actions: write` and nothing else).
3. **ca** asks the Worker for the request with its OIDC token: `GET /api/pipeline/requests/<id>` (the Worker accepts `ca.yml` on `main`,
   environment `ca`, audience `hub.wolos.org`, and answers only an approved request that has no certificate yet; the body is the request
   file itself). It writes `requests/<id>.json`, checks it against `schema/request.schema.json`, for `trusted` checks that every
   `approved_by` login is in the variable `CA_APPROVERS`, builds the certificate body (`ca.mjs certBody`: keys including x25519 and ml-kem-768, `subject.org`,
   `verified_at`), and `woltrust issue --proof` checks the proof again and signs exactly that body. `ca.mjs` checks the Ed25519 half
   against the Authors CA certificate in hub-log `certs/intermediates/` before anything is written.
4. It commits `certs/<serial>.wolcert` and `certs/<serial>.json` to hub-log (the public log), keeps the request as a run artifact here, then tells the Worker:
   `POST /api/pipeline/certs` with `{"request_id","serial","tier","cert"}` (`cert` = the exact `.wolcert` text). The Worker shows the
   certificate to the author, who adds it with `wol cert add`.

What a certificate says comes from two places only (audit-1 H2): what the requester signed (github_id, kind, keys: the
proof covers them; TRUST-core-4 extends the proof to namespaces, login, name and org) and what GitHub says about that github_id,
asked by the ca job itself with its own read-only token (`scripts/github-identity.mjs`): the login and display name
(`GET /user/{id}`, `/organizations/{id}`), a person's organisation only when GitHub shows the membership publicly, and for an
organisation that `requested_by` is an owner (`GET /orgs/{org}/memberships/{login}`, needs `CA_GITHUB_TOKEN` with members:read; without
it organisation certificates are refused). A login in the request that is not GitHub's is refused; the name is GitHub's (a name with
bidi or format characters becomes the login). The namespace is exactly `<login>.` (lowercase) for persons and organisations, never a
reserved name or a look-alike of one (`validate.mjs` `RESERVED_NAMES`, `skeleton`), and never the same as or a look-alike of another
account's active certificate. The Worker's fields (approved_by, cla_accepted_at, verified_at, months) decide only whether the job runs.
A revocation uses the job's clock (the request's `at` is ignored) and every approver must be in `CA_APPROVERS` (abuse: two).

A second dispatch for the same id stops at once (a hub-log `certs/<serial>.json` has that `request_id`); one GitHub account has one active certificate
per kind and tier (revoke the old one, reason `superseded`, first). A request file the CA operator writes by hand needs the same
`cla_accepted_at` or `approved_by`; it reaches `main` through a reviewed pull request and is issued with `request=requests/<name>.json`.

Why a dispatch with the id and not a pull request from the Worker's bot: the workflow that holds the CA key then only ever runs code
from `main` (a workflow dispatch on `ref: main`, environment `ca` limited to `main`), never code or files from a pull request; the
Worker needs only `actions: write`, so a taken-over Worker can start a run but cannot push a request, a script or a workflow
(a bot that opens and merges pull requests needs `contents: write` and a way around review); no branch protection exception is
needed; and the approval stays where it was given and authenticated (the admin's hub session), fetched by an OIDC-authenticated job,
with the certificate and its record (request id, tier, approvers) committed together to hub-log.

The request file (`schema/request.schema.json`, action `issue`), as the Worker writes it:

```
{
  "format": 1, "action": "issue",
  "id": "r-0001",                                          the Worker's request id; the file is requests/<id>.json
  "kind": "person" | "org",                               covered by the proof
  "tier": "origin" | "trusted",                            named tier because kind is taken
  "subject": { "github_id": 1001, "login": "alice", "name": "Alice Example",
               "org": { "github_id": 2002, "login": "examplelabs" } },   person only, optional: GitHub membership the hub saw
  "requested_by": { "github_id": 1003, "login": "bob" },  organisations: an owner (checked with GitHub); persons: absent or themselves
  "namespaces": ["alice."],                                 exactly ["<login>."], lowercase
  "keys": { "ed25519": b64url(32), "ml-dsa-65": b64url(1952),
            "x25519": b64url(32), "ml-kem-768": b64url(1184) },          the encryption pair both or none
  "proof": { "ed25519": b64url(64), "second": b64url },    label wolos/request/1 over "{github_id}\n{kind}\n{ed25519}\n{ml-dsa-65}\n{slh}\n{x25519}\n{ml-kem-768}\n"
  "months": 12, "requested_at": 1793700000,
  "verified_at": 1793710000,                                when the hub last verified the account (certificate verified_at)
  "approved_by": ["carol-ca"], "approved_at": 1793740000,  trusted: required, never the subject
  "cla_accepted_at": 1793690000                            origin: required
}
```

`fixtures/request-issue.json` (trusted) and `fixtures/request-origin.json` (origin) have real keys and a real proof (TEST, `fixtures/gen/`).

## Release statements

Every listed version gets its own signed release statement (lead decision 2026-11-04; shape by TRUST-core-4, chat 7293):

```
signed/statements/<id>/<version>.wsig   = plugins/statements/<id>/<version>.wsig on the CDN
{"format":1, "body":b64url(body), "cert":"<Index intermediate serial>", "sig":{"ed25519","second"}}    label wolos/release/1
body {"format":1, "serial", "sha256", "id", "version", "kind":"package|plugin|extension", "origin"?:{"repo","tag","commit"},
      "verdict", "findings":<count>, "checked_at", "cert"?:"<author certificate serial>"}
```

The statement serial is the first 8 bytes of SHA-256(`wolos/release/1` 0x00 id 0x00 version 0x00 sha256), so re-signing the same
file keeps it (`scripts/statements.mjs`). `build-index.mjs --statements DIR --statements-url URL` writes each body and points the
entry at its statement (`statement: {url, serial}`); `sign-files.sh` signs the statements first (`woltrust sign --purpose release`),
then the index; `publish.sh` uploads them before everything else. Withdrawing one version: a revoke request with the statement serial
and reason `withdrawn-version` (`ca.mjs revoke --index signed/index.json` refuses a serial that is not a listed version's); the next
sign run marks the entry `withdrawn: true` and puts the serial on `revoked.json`. The author's certificate is untouched.

Until the pinned woltrust has the release purpose and the new reason, `tools/woltrust.features` is empty: sign.yml builds no
statements, `revoked.json` leaves `withdrawn-version` entries out (an unknown reason would make woltrust refuse the whole list;
they wait in `revocations.json`, and the index already marks the version withdrawn), and `sign-files.sh` refuses to sign an index that
points at statements it cannot sign. Moving `tools/woltrust.rev` to TRUST-core-4's commit and adding `class`, `statements`,
`withdrawn-version` to `tools/woltrust.features` switches all three on.

## What each environment holds

Secret values live only in the repository's Environment settings. This repository contains names, never values.

| Environment | Used by | Secrets | Variables | Rules |
|---|---|---|---|---|
| none | `ci.yml`, job `scan` of `check.yml` | none | none | `scan` has no `id-token`, no write right, no environment: it opens untrusted files and has nothing to lose |
| `check` | jobs `fetch` and `report` of `check.yml` | `HUB_LOG_DEPLOY_KEY` (report pushes `verdicts/` to hub-log) | none | OIDC only (audience `hub.wolos.org`); the Worker accepts this workflow file on `main` with environment `check`; it can read pending and post verdicts, not export |
| `sign` | `sign.yml` | `WOLOS_INDEX_SIGNING_KEY` (Index intermediate), `WOLOS_KEY_PASSPHRASE` (when that key is a locked `.wolkey`), `WOLOS_LEGACY_INDEX_KEY` (legacy Ed25519 PEM), `WOLOS_CDN_UPLOAD_TOKEN`, `HUB_LOG_DEPLOY_KEY` | `INDEX_CERT_SERIAL`, optional `CDN_BASE` | deployment branch `main` only; OIDC token can export, not post; parses no release file; tools built from source in the job, no cache |
| `ca` | `ca.yml` | `WOLOS_AUTHORS_CA_KEY` (Authors CA intermediate), `WOLOS_KEY_PASSPHRASE` (when locked), `HUB_LOG_DEPLOY_KEY`, optional `CA_GITHUB_TOKEN` (members:read) | `AUTHORS_CA_SERIAL`, `CA_APPROVERS` (admin logins, comma separated) | deployment branch `main` only; no required reviewers (origin needs the CLA only; for trusted the second person is the approving admin, see "How a certificate is issued"); OIDC token reads approved requests and reports certificates; tools built from source, no cache |

`WOLOS_KEY_PASSPHRASE` is one secret name in both environments, as `woltrust init` prints it (`ci/passphrase`); woltrust reads it only when
the key secret is a locked `.wolkey` (`--passphrase-env WOLOS_KEY_PASSPHRASE`). `HUB_LOG_DEPLOY_KEY` is one secret name in the three
environments with three different values: three write deploy keys of hub-log (`hub-pipeline check`, `hub-pipeline sign`, `hub-pipeline ca`), so
one can be removed without the others. Before the first real run, hub-log `certs/roots/` and
`certs/intermediates/` get the public certificates `woltrust init` wrote (`public/roots`, `public/intermediates`): the sign job verifies what it
signed against them, and hubcheck checks release signatures against them.

Repository variable `HUB_PIPELINE_ENABLED=true` switches the schedules on (check and sign do nothing on a schedule until it is set). The roots
are never here: they are offline and sign only intermediates.

Set up once: here, branch protection on `main` (pull request with a review, no force-push, no deletion; no bypass for any bot: no
workflow writes here); CODEOWNERS on `.github/`, `scripts/`, `tools/`, `schema/`. On hub-log, a ruleset on `main` (no force-push, no
deletion, changes only by push from the three deploy keys, which are its only bypass actors), Actions switched off, and
`commit-log.sh` refuses any path but `signed/`, `verdicts/`, `certs/`, `revocations.json` and any checkout whose origin is not
`wonderlandos/hub-log`.
The workflows pin every third-party action by commit id; `tools/*.rev` pin the tools.

## Tooling contract (what the workflows call)

Both tools are built from the commit in `tools/<name>.rev` by `scripts/tool.sh <name>` (a fresh clone at that commit, `cargo build --release
--locked`; the binary is cached in `~/.cache/hub-pipeline-tools/<name>-<rev>/bin`, in actions/cache for `ci.yml` and the scan job, never for the
jobs that hold secrets). There are no stand-ins: dry runs and `scripts/test.sh` run the same binaries with the TEST authority.

`hubcheck` (HUB-wasm, `wonderlandos/hub` `wasm/`, `tools/hubcheck.rev` = `3af340f`, `tools/hubcheck.sha256` the binary built here; zstd plugins and extensions are read by default), called by `check-release.mjs`:
`hubcheck inspect app|plugin|extension FILE --store store.json --now UNIX [--first-seen UNIX]` prints one line of I7 JSON,
`{"verdict":"pass|flag|block|not-checked","findings":[{"rule","sentence","evidence"}],"trust":"wolos|trusted|origin|verified|community|withdrawn|invalid","cert"?:{"serial","subject","level"},"origin"?,"file"?:{"id","version"?},"facts"?:{"name","summary","description"?,"icon"?,"screenshots","categories","homepage"?,"licence"?}}`,
exit 0 whenever it printed a report. The verdict is hubcheck's; `check-release.mjs` adds only what hubcheck cannot know (download, the size
GitHub listed, the 120-second limit, and a block when `file.id` or `file.version` is not the listing's) and turns anything else (no binary, no store, a non-zero exit, output that is not a report, a timeout)
into `not-checked`. `store.json` is `scripts/store.mjs` (`{"roots":[...],"intermediates":[...],"allow_test":false,"revoked":[{"list","wsig"}]}`).

Listing facts and pictures (the store page's name, summary, description, icon and screenshots come from the package, never from a form):
for a `pass` or `flag`, `check-release.mjs --pictures DIR` keeps hubcheck's `facts` in the shape of the Worker's `metaOf`
(`scripts/facts.mjs`: name 80, summary 200 on one line, description 4000, icon and at most 8 screenshots as `{path, mime, w, h, size, sha256}`;
a field the Worker would refuse is left out, not the verdict) and runs `hubcheck extract FILE --out SCRATCH --kind KIND`, which writes the pictures as
`<sha256>.<png|webp>`. A picture reference stays in the verdict only when those exact bytes (hash, size, type, pixel size) are there; the `scan` job uploads
them as artifact `pictures`. The `report` job (`verdicts.mjs clean --pictures --pictures-out log/pictures`) re-checks each one and commits it to
hub-log `pictures/<sha256>.<ext>`. The `sign` job (`pictures.mjs stage`) takes the pictures the Worker's export names (`icon.file`, `screenshots[].file`)
from there, checks them again, and `publish.sh` uploads them first of all to `https://cdn.wolos.org/plugins/pictures/<sha256>.<ext>`. A file that is not
a listed picture name is refused; a picture that is missing or changed is left out and named in the log. No image ever goes through the Worker.
The signed index names them: `pictures.mjs stage` runs before `build-index.mjs --pictures work/out/pictures`, and each entry carries
`description` (the package's text, 1 to 4000 characters, no control character but tab and line breaks), `icon` (one file name
`<sha256>.<png|webp>`, the extension from the picture's type) and `screenshots` (1 to 8 such names), only for pictures whose exact bytes are in that folder (hash, size, type, pixel size checked again); a bad one is left out
with a notice, never the entry. A client reads a picture at `https://cdn.wolos.org/plugins/pictures/<file>`, the name exactly as the index gives it. The CDN gives its type
from the name (wolos-cdn `bucket.rs` `serve`, tower-http `ServeFile`: `.png` image/png, `.webp` image/webp, always `nosniff`; `cdn-put` uploads
parts as `application/octet-stream` and has no type of its own), and `publish.sh` reads each picture back and stops, before `index.json`
goes up, when it is served with another type (`scripts/mock-cdn.mjs` stands in for the CDN in `test.sh`).

`woltrust` (the woltrust crate of wolos, `src/bin/woltrust.rs`, `tools/woltrust.rev` = `b8bbd2d` (the rewritten `68b5a03`, same woltrust), `tools/woltrust.sha256`, branch `wave3/trust-core`):
- `woltrust sign --purpose index|revocation --cert SERIAL --key-env NAME --passphrase-env WOLOS_KEY_PASSPHRASE FILE` prints the `.wsig`
  (`{"cert","ed25519","second"}`) over `label || 0x00 || SHA-512(FILE)` (`sign-files.sh`);
- `woltrust verify --purpose P --wsig F --roots DIR --intermediates DIR --list revoked.json [--chain F] [--id ID] [--allow-test] [--now N] FILE`
  prints the I7 report, exit 0 only for trust `wolos` or `verified` (`sign-files.sh` checks both files before upload; `test.sh`);
- `woltrust issue --body BODY.json --proof PROOF.json --key-env NAME --passphrase-env WOLOS_KEY_PASSPHRASE` checks the proof of possession
  against the body and prints the `.wolcert` whose `body` is exactly the bytes of BODY.json (`ca.mjs` refuses an answer whose body differs,
  or whose Ed25519 half is not the CA's);
- `woltrust revoke --source revocations.json [--previous revoked.json] [--now N]` makes the same list as `build-revoked.mjs` (`test.sh` compares them);
- `woltrust rkdb make --source revoked.json [--previous revoked.rkdb] [--root-section emergency.rkdr] [--now N] --cert ID KEY`,
  `rkdb checkpoint FILE`, `rkdb verify --roots DIR --intermediates DIR [--floor N] [--allow-test] FILE`, `rkdb delta OLD NEW`
  (`sign-files.sh`, `test.sh`).
- `tools/woltrust.features` lists what the pinned woltrust can do beyond `fe64176` (`class`, `statements`, `withdrawn-version`; at
  `68b5a03`: `class` and `withdrawn-version`); the scripts read it and leave out what woltrust would refuse.

Exit codes: 0 done, 1 refused (the reason on stderr), 2 a wrong command line. Key material comes from the environment or a file, never
an argument.

## Running it locally

```
scripts/test.sh                 everything below, no secret (needs node 20+, openssl, curl, git, cargo; the first run builds the two tools)
WOLTRUST_SRC=~/wolos HUBCHECK_SRC=~/hub scripts/test.sh     build the tools from local clones (only their commits are used)
WOLTRUST_BIN=... HUBCHECK_BIN=... scripts/test.sh            use binaries you built from the pinned commits
node scripts/validate.mjs index fixtures/sample-signed/index.json
SAMPLE_OUT=fixtures/sample-signed scripts/test.sh     remake the TEST sample
fixtures/gen/run.sh             remake the binary fixtures (assets, fixtures/trust, request-issue.json) from woltrust's TEST authority
```

`test.sh` runs a mock Worker on 127.0.0.1 (it keeps the check/sign/ca token separation) and the real tools: hubcheck over `fixtures/assets`
(an app signed by the TEST person alice that passes, a plugin by alice and an extension by the TEST organisation examplelabs that are
flagged because they are plain tar, an app changed after packing that is blocked, a file that is gone, a file whose size changed: six
verdicts with trust and cert), the sign scripts with the TEST Index intermediate (`docs/test-keys.md`) and `woltrust verify` of what they
signed, the committed sample compared byte for byte, the ca path from the Worker's request to a certificate of each tier (a trusted one a file then
verifies with and that its revocation withdraws, an origin one issued on the CLA alone; the index showing trusted, origin, and the
superseded downgrade; release statement bodies and references, a withdrawn version), and about 60 negative cases (a bad URL, an id outside the owner's namespace, a tampered
index, an owner taken over, an index that lost most of its entries, a checker that fails or hangs, a forged proof, an approver who is not a
CA approver, the wrong CA key, ...). In GitHub, `sign.yml` and `ca.yml` start as dry runs (the default of `dry_run`).

## Checked against the 0.12 reader

The format is today's plugin index plus new keys; the 0.12 parser has no `deny_unknown_fields`, so it ignores them and drops an entry that breaks its own
rules (a plugin with no `kinds`, for example, as the Worker's export has today; 0.12 also requires the
index key on the file, so it lists only plugins WolOS signed itself). `scripts/legacy-check.mjs` ports the reader to Node for every run of `test.sh`. The real Rust reader was run on the sample:
`compat/wopkg_hubindex.rs` copied to `crates/wopkg/tests/` of a wolos checkout, `HUBINDEX_SAMPLE=<this repo>/fixtures/sample-signed cargo test -p wopkg --test <name>`
(`plugins::verify` accepts the signature and keeps `alice.weather`; a changed byte is refused). `compat/woltrust_hubindex.rs` does the same for
`woltrust::revoked::parse`, `Wsig::parse` and `woltrust::verify` (`HUBINDEX_TRUST=<this repo>/fixtures/trust`: the sample index is WolOS's
with the TEST root allowed, a changed byte is invalid, and without `allow_test` it is not trusted). Both pass at `fe64176`.
