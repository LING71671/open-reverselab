fn main() {
    println!("cargo:rerun-if-changed=icons/icon.ico");
    println!("cargo:rerun-if-changed=capabilities/default.json");
    tauri_build::build()
}
