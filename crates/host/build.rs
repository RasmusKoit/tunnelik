fn main() {
    // The package's "Plugin" app runs in an app container, which Windows only allows for
    // executables linked as such.
    if std::env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("msvc") {
        println!("cargo:rustc-link-arg-bins=/APPCONTAINER");
    }
}
