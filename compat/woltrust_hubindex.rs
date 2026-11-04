// SPDX-License-Identifier: BSD-2-Clause
// woltrust's own readers against a hub-index sample. Copy to crates/woltrust/tests/ in a wolos checkout, run, delete (see README).
use std::{env, fs};
#[test]
fn hub_index_sample_revocation_list_and_wsig_parse() {
    let dir = env::var("HUBINDEX_SAMPLE").unwrap();
    let l = woltrust::revoked::parse(&fs::read(format!("{dir}/revoked.json")).unwrap()).expect("revoked.json");
    assert_eq!(l.entries.len(), 1);
    for f in ["index.json.wsig", "revoked.json.wsig"] {
        woltrust::Wsig::parse(&fs::read(format!("{dir}/{f}")).unwrap()).expect(f);
    }
}
