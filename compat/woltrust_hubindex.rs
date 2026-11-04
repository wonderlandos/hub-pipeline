// SPDX-License-Identifier: BSD-2-Clause
// woltrust's own readers and verifier against a hub-pipeline sample. Copy to crates/woltrust/tests/ in a wolos checkout,
// run with HUBINDEX_SAMPLE=<hub-pipeline>/fixtures/sample-signed HUBINDEX_TRUST=<hub-pipeline>/fixtures/trust, delete (see README).
use std::{env, fs};
use woltrust::{Input, Purpose, Store, Trust};

const NOW: u64 = 1_793_750_400; // the fixed time of scripts/test.sh

fn certs(dir: &str) -> Vec<Vec<u8>> {
    let mut names: Vec<_> = fs::read_dir(dir).unwrap().flatten().map(|e| e.path()).filter(|p| p.extension().is_some_and(|x| x == "wolcert")).collect();
    names.sort();
    names.iter().map(|p| fs::read(p).unwrap()).collect()
}

#[test]
fn hub_index_sample_revocation_list_and_wsig_parse_and_verify() {
    let dir = env::var("HUBINDEX_SAMPLE").unwrap();
    let trust = env::var("HUBINDEX_TRUST").unwrap();
    let list = fs::read(format!("{dir}/revoked.json")).unwrap();
    let list_sig = fs::read(format!("{dir}/revoked.json.wsig")).unwrap();
    let l = woltrust::revoked::parse(&list).expect("revoked.json");
    assert_eq!(l.entries.len(), 1);
    for f in ["index.json.wsig", "revoked.json.wsig"] {
        woltrust::Wsig::parse(&fs::read(format!("{dir}/{f}")).unwrap()).expect(f);
    }
    let roots = certs(&format!("{trust}/roots"));
    let inter = certs(&format!("{trust}/intermediates"));
    let store = Store::load(&roots, &inter, &[(list.clone(), list_sig)], NOW, true);
    let index = fs::read(format!("{dir}/index.json")).unwrap();
    let wsig = fs::read(format!("{dir}/index.json.wsig")).unwrap();
    let input = |content: &[u8]| -> Trust {
        woltrust::verify(&store, &Input { purpose: Purpose::Index, content, app_id: None, wsig: Some(&wsig), chain: None, first_seen: None, now: NOW }).trust
    };
    assert_eq!(input(&index), Trust::Wolos, "the sample index verifies as WolOS's");
    let mut changed = index.clone();
    changed[10] ^= 1;
    assert_eq!(input(&changed), Trust::Invalid, "a changed byte is refused");
    let refused = Store::load(&roots, &inter, &[(list, fs::read(format!("{dir}/revoked.json.wsig")).unwrap())], NOW, false);
    let out = woltrust::verify(&refused, &Input { purpose: Purpose::Index, content: &index, app_id: None, wsig: Some(&wsig), chain: None, first_seen: None, now: NOW });
    assert_ne!(out.trust, Trust::Wolos, "the TEST root never counts outside a test");
}
