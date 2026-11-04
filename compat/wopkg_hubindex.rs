// SPDX-License-Identifier: GPL-2.0-or-later
// The unchanged 0.12 plugin index reader (wopkg::index::plugins::verify) against a hub-index sample. Copy to crates/wopkg/tests/ in a wolos checkout, run, delete (see README, "Checked against the 0.12 reader").
use std::{env, fs};
#[test]
fn hub_index_sample_parses_in_012() {
    let dir = env::var("HUBINDEX_SAMPLE").expect("HUBINDEX_SAMPLE");
    let text = fs::read(format!("{dir}/index.json")).unwrap();
    let sig = fs::read(format!("{dir}/index.json.sig")).unwrap();
    let hex = fs::read_to_string(format!("{dir}/legacy-test-key.pub.hex")).unwrap();
    let hex = hex.trim();
    let mut key = [0u8; 32];
    for i in 0..32 { key[i] = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap(); }
    let idx = wopkg::index::plugins::verify(&text, Some(&sig), &[key]).expect("verify");
    let ids: Vec<_> = idx.plugins.iter().map(|e| e.id.as_str()).collect();
    println!("kept plugins: {ids:?}");
    assert_eq!(ids, ["alice.weather"]);
    let mut bad = text.clone();
    bad[30] ^= 1;
    assert!(wopkg::index::plugins::verify(&bad, Some(&sig), &[key]).is_err());
}
