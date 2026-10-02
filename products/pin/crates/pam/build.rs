fn main() {
    // Link libpam by its runtime name: hosts without pam-devel have no libpam.so symlink to find.
    println!("cargo::rustc-link-lib=dylib:+verbatim=libpam.so.0");
    // Never unmap the module. libpam dlcloses it at every pam_end, but Rust's standard library (and
    // crates using it) register thread-local destructors that glibc runs at thread exit. Unmapped,
    // they segfault the lock screen (rust-lang/rust#91979, reproduced here on Fedora 44). The
    // load/unload test in tests/stack.rs crashes without this flag.
    println!("cargo::rustc-cdylib-link-arg=-Wl,-z,nodelete");
}
