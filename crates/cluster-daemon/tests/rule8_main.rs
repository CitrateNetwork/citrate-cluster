//! Rule 8 tripwire for the cluster daemon binary: no `.unwrap()` / `.expect(` in `src/main.rs`.
//! Every startup failure returns a reason (fail closed) instead of panicking, so citrate-core has
//! something to show the member.

#[test]
fn main_rs_has_no_unwrap_or_expect() {
    let src = include_str!("../src/main.rs");
    let unwrap = [".unwrap", "()"].concat();
    let expect = [".expect", "("].concat();
    let hits: Vec<(usize, &str)> = src
        .lines()
        .enumerate()
        .filter(|(_, l)| !l.trim_start().starts_with("//"))
        .filter(|(_, l)| l.contains(&unwrap) || l.contains(&expect))
        .map(|(i, l)| (i + 1, l.trim()))
        .collect();
    assert!(
        hits.is_empty(),
        "Rule 8: unwrap/expect in cluster-daemon main.rs: {hits:?}"
    );
}
