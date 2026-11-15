fn main() {
    println!("cargo:rerun-if-changed=icons/icon.ico");
    println!("cargo:rerun-if-changed=capabilities/default.json");
    // Library test executables do not receive Tauri's bin-only resource manifest.
    // MockRuntime still links TaskDialogIndirect, which requires Common Controls v6.
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows")
        && std::env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("msvc") {
        println!("cargo:rustc-link-arg=/MANIFEST:EMBED");
        println!("cargo:rustc-link-arg=/MANIFESTDEPENDENCY:type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'");
        // The application binary already embeds the full Tauri resource manifest.
        println!("cargo:rustc-link-arg-bins=/MANIFEST:NO");
    }
    tauri_build::build()
}
