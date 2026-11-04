// SPDX-License-Identifier: GPL-2.0-or-later
//! The binary fixtures of hub-pipeline (formerly hub-index). Run by `fixtures/gen/run.sh` as an example of the woltrust crate at the
//! commit of `tools/woltrust.rev` (so it builds with that commit's own Cargo.lock and nothing else).
//!
//! - `assets/*`: real release files for `check-release.mjs` and the pinned `hubcheck`, in the formats hubcheck
//!   reads (a `.wol` of format 2; plugin and extension as one folder in a tar, not compressed): an app signed by
//!   the TEST person alice, a plugin signed by alice, an extension signed by the TEST organisation examplelabs,
//!   and an app whose payload was changed after packing. `dave.swapped-2.0.wol` is left alone: its size differs
//!   from the Worker's, so it never reaches the checker.
//! - `trust/roots/test-root-a.wolcert`, `trust/intermediates/test-{index,authors}.wolcert`: the TEST authority
//!   of woltrust (subject labels `test-...`, refused by every store unless `allow_test`).
//! - `request-issue.json` (tier trusted, approved by an admin), `request-origin.json` (tier origin, CLA accepted) and
//!   `request-org.json` (organisation examplelabs, origin, asked by its owner bob):
//!   issue requests with real keys (signing and encryption) and a real proof of possession, as the hub Worker writes them.
//!
//! Deterministic: the seeds are public names (`woltrust::pki::seed`), the tar headers fixed.
use sha2::{Digest, Sha256};
use std::path::Path;
use woltrust::Purpose;
use woltrust::make;
use woltrust::pki::{Ident, Pki};

const BLOCK: usize = 512;
const PNG: &[u8] = b"\x89PNG\r\n\x1a\nxxxx";

fn write(dir: &Path, name: &str, bytes: &[u8]) {
    let p = dir.join(name);
    std::fs::create_dir_all(p.parent().expect("a parent")).expect("mkdir");
    std::fs::write(&p, bytes).expect("write");
    println!("{name}: {} bytes, sha256 {}", bytes.len(), hex(&Sha256::digest(bytes)));
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// ustar bytes of plain files (mode 0644, root, mtime 0): the same bytes as hubcheck's `tar::build`.
fn tar(members: &[(&str, &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    for (name, data) in members {
        let mut h = [0u8; BLOCK];
        h[..name.len()].copy_from_slice(name.as_bytes());
        for (at, v) in [(100, "0000644"), (108, "0000000"), (116, "0000000")] {
            h[at..at + 7].copy_from_slice(v.as_bytes());
        }
        h[124..135].copy_from_slice(format!("{:011o}", data.len()).as_bytes());
        h[136..147].copy_from_slice(b"00000000000");
        h[156] = b'0';
        h[257..263].copy_from_slice(b"ustar\0");
        h[263..265].copy_from_slice(b"00");
        h[148..156].copy_from_slice(b"        ");
        let sum: u32 = h.iter().map(|b| u32::from(*b)).sum();
        h[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
        out.extend_from_slice(&h);
        out.extend_from_slice(data);
        out.resize(out.len().div_ceil(BLOCK) * BLOCK, 0);
    }
    out.resize(out.len() + 2 * BLOCK, 0);
    out
}

/// The `SHA256` member: BSD lines sorted by member name.
fn sums(members: &[(&str, &[u8])]) -> String {
    let mut lines: Vec<String> = members.iter().map(|(n, b)| format!("SHA256 ({n}) = {}\n", hex(&Sha256::digest(b)))).collect();
    lines.sort();
    lines.concat()
}

/// `members` + `SHA256` (+ `CHAIN`, `SHA256.wsig` when `signer` is given) as a tar.
fn pack(members: &[(&str, &[u8])], signer: Option<(&Ident, &Ident)>, purpose: Purpose) -> Vec<u8> {
    let man = sums(members);
    let mut all: Vec<(&str, &[u8])> = members.to_vec();
    all.push(("SHA256", man.as_bytes()));
    let signed = signer.map(|(leaf, ca)| (Pki::chain(&[leaf, ca]), make::wsig(&leaf.body.serial, &leaf.secret, purpose, man.as_bytes())));
    if let Some((chain, wsig)) = &signed {
        all.push(("CHAIN", chain));
        all.push(("SHA256.wsig", wsig));
    }
    tar(&all)
}

fn info(id: &str, version: &str) -> String {
    format!(
        r#"{{"id":"{id}","version":"{version}","name":"Notes","summary":"Quick notes","categories":["Work"],"capabilities":["files"],"package":"notes","targets":[{{"abi":"linux","arch":"amd64","entry":"bin/notes"}}]}}"#
    )
}

fn wol(id: &str, signer: Option<(&Ident, &Ident)>) -> Vec<u8> {
    let info = info(id, "1.0");
    pack(&[("Info.json", info.as_bytes()), ("icon.png", PNG), ("payload.pkg", b"pkg payload bytes")], signer, Purpose::Package)
}

fn folder(id: &str, files: &[(&str, &[u8])], signer: Option<(&Ident, &Ident)>, purpose: Purpose) -> Vec<u8> {
    let named: Vec<(String, &[u8])> = files.iter().map(|(p, b)| (format!("{id}/{p}"), *b)).collect();
    let members: Vec<(&str, &[u8])> = named.iter().map(|(n, b)| (n.as_str(), *b)).collect();
    pack(&members, signer, purpose)
}

/// A request for alice with the key material of the public name `seed`, of `tier`.
fn request(seed: &str, id: &str, tier: &str) -> Vec<u8> {
    let km = woltrust::key::KeyMaterial::new(woltrust::pki::seed(seed), false);
    let keys = km.keys_text();
    let org = seed.ends_with("-org");
    let (gid, kind) = if org { (2002, woltrust::cert::Kind::Org) } else { (1001, woltrust::cert::Kind::Person) };
    let proof = woltrust::request::prove(&km.secret(), gid, kind, &keys);
    let mut k = serde_json::Map::new();
    k.insert("ed25519".into(), keys.ed25519.clone().into());
    k.insert("ml-dsa-65".into(), keys.ml_dsa_65.clone().expect("ml-dsa").into());
    k.insert("x25519".into(), keys.x25519.clone().expect("x25519").into());
    k.insert("ml-kem-768".into(), keys.ml_kem_768.clone().expect("ml-kem").into());
    let mut req = serde_json::json!({
        "format": 1,
        "action": "issue",
        "id": id,
        "kind": "person",
        "tier": tier,
        "subject": { "github_id": 1001, "login": "alice", "name": "Alice Example", "org": { "github_id": 2002, "login": "examplelabs" } },
        "namespaces": ["alice."],
        "keys": k,
        "proof": { "ed25519": proof.ed25519, "second": proof.second },
        "months": 12,
        "requested_at": 1793700000u64,
        "verified_at": 1793710000u64
    });
    let o = req.as_object_mut().expect("object");
    if org {
        o.insert("kind".into(), serde_json::json!("org"));
        o.insert("subject".into(), serde_json::json!({ "github_id": 2002, "login": "examplelabs", "name": "Example Labs" }));
        o.insert("namespaces".into(), serde_json::json!(["examplelabs."]));
        o.insert("requested_by".into(), serde_json::json!({ "github_id": 1003, "login": "bob" }));
    }
    if tier == "trusted" {
        o.insert("approved_by".into(), serde_json::json!(["carol-ca"]));
        o.insert("approved_at".into(), serde_json::json!(1793740000u64));
    } else {
        o.insert("cla_accepted_at".into(), serde_json::json!(1793690000u64));
    }
    let mut text = serde_json::to_string_pretty(&req).expect("json");
    text.push('\n');
    text.into_bytes()
}

fn main() {
    let out = std::env::args().nth(1).expect("usage: hub-index-fixtures <fixtures dir>");
    let dir = Path::new(&out);
    let pki = Pki::new();
    let alice = Some((&pki.alice, &pki.authors));
    let org = Some((&pki.org, &pki.authors));

    write(dir, "assets/alice.notes-1.0.wol", &wol("alice.notes", alice));
    let toml = "schema = 1\nid = \"alice.weather\"\nname = \"Weather\"\nversion = \"1.2\"\nlicense = \"MIT\"\ndescription = \"Forecast in the menu bar\"\nmin_wolos = \"0.13\"\npermissions = [\"http\"]\n\n[[widget]]\nid = \"card\"\nscript = \"card.lua\"\nsizes = [\"small\"]\n";
    let lua = "local r = wol.http_get('https://example.org/w')\nreturn wol.widget { render = function() return wol.text(r) end }\n";
    write(dir, "assets/alice.weather-1.2.wolplug", &folder("alice.weather", &[("plugin.toml", toml.as_bytes()), ("card.lua", lua.as_bytes())], alice, Purpose::Plugin));
    let ext = "schema = 1\nid = \"examplelabs.notes-sync\"\nname = \"Notes Sync\"\nversion = \"0.3\"\nlicense = \"Apache-2.0\"\ndescription = \"Sync Notes with a folder you choose\"\nmin_wolos = \"0.13\"\nhost = \"alice.notes\"\n";
    let readme = "Notes Sync keeps the notes of Notes in a folder you choose.\n";
    write(
        dir,
        "assets/examplelabs.notes-sync-0.3.wolext",
        &folder("examplelabs.notes-sync", &[("extension.toml", ext.as_bytes()), ("README.txt", readme.as_bytes())], org, Purpose::Extension),
    );
    // Packed, then one byte of the payload changed: the SHA256 list no longer matches (rule file/hash, block).
    let mut tampered = wol("mallory.tool", None);
    let at = tampered.windows(17).position(|w| w == b"pkg payload bytes").expect("payload");
    tampered[at] = b'P';
    write(dir, "assets/mallory.tool-1.0.wol", &tampered);

    write(dir, "trust/roots/test-root-a.wolcert", &pki.root_a.file);
    write(dir, "trust/intermediates/test-index.wolcert", &pki.index.file);
    write(dir, "trust/intermediates/test-authors.wolcert", &pki.authors.file);

    // Issue requests with real keys and proof (person alice, GitHub id 1001), as the Worker writes them: a trusted one
    // an admin approved, and an origin one issued on the CLA alone (lead decision 2026-11-04: two tiers).
    write(dir, "request-issue.json", &request("hub-index-request-alice", "r-0001", "trusted"));
    write(dir, "request-origin.json", &request("hub-index-request-alice-origin", "r-0002", "origin"));
    // An organisation's origin request, asked by bob (an owner of examplelabs in fixtures/github.json).
    write(dir, "request-org.json", &request("hub-index-request-examplelabs-org", "r-0003", "origin"));
}
