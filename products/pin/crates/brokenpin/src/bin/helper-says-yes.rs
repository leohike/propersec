//! Test-only: a `properpin-helper` that answers yes to everything, so the lock screen unlocks
//! whatever is typed. It reads its input first, as the real one does.

fn main() {
    let _ = std::io::copy(&mut std::io::stdin(), &mut std::io::sink());
}
