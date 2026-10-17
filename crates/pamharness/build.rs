// Link libpam by its runtime name: hosts without pam-devel have no libpam.so symlink to find.
fn main() {
    println!("cargo::rustc-link-lib=dylib:+verbatim=libpam.so.0");
}
