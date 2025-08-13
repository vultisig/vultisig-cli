use std::env;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    
    // Get the build target directory
    let out_dir = env::var("OUT_DIR").unwrap();
    let profile = env::var("PROFILE").unwrap();
    
    // Set up paths
    let wallet_core_root = PathBuf::from("../wallet-core");
    let build_dir = PathBuf::from(&out_dir).join("wallet-core-build");
    
    // Only build if wallet-core directory exists
    if !wallet_core_root.exists() {
        println!("cargo:warning=wallet-core directory not found, skipping build");
        return;
    }
    
    // Create build directory
    std::fs::create_dir_all(&build_dir).expect("Failed to create build directory");
    
    // Configure CMake build
    let mut cmake_config = cmake::Config::new(&wallet_core_root);
    
    cmake_config
        .define("CMAKE_BUILD_TYPE", if profile == "debug" { "Debug" } else { "Release" })
        .define("CMAKE_POSITION_INDEPENDENT_CODE", "ON")
        .define("BUILD_SHARED_LIBS", "OFF")
        .define("TW_BUILD_EXAMPLES", "OFF")
        .define("TW_BUILD_TESTS", "OFF")
        .define("TW_ENABLE_PVS_STUDIO", "OFF")
        .define("TW_ENABLE_CLANG_TIDY", "OFF");
    
    // Platform-specific configuration
    if cfg!(target_os = "macos") {
        cmake_config.define("CMAKE_OSX_DEPLOYMENT_TARGET", "10.14");
    }
    
    // Build wallet-core
    let wallet_core_install = cmake_config.build();
    
    // Link against the built library
    println!("cargo:rustc-link-search=native={}/lib", wallet_core_install.display());
    println!("cargo:rustc-link-lib=static=TrustWalletCore");
    
    // Platform-specific system libraries
    if cfg!(target_os = "macos") {
        println!("cargo:rustc-link-lib=framework=Foundation");
        println!("cargo:rustc-link-lib=framework=Security");
        println!("cargo:rustc-link-lib=c++");
    } else if cfg!(target_os = "linux") {
        println!("cargo:rustc-link-lib=pthread");
        println!("cargo:rustc-link-lib=dl");
        println!("cargo:rustc-link-lib=stdc++");
    }
    
    // Generate FFI bindings using bindgen
    if std::env::var("DOCS_RS").is_err() {  // Skip bindgen on docs.rs
        generate_bindings(&wallet_core_install);
    }
}

fn generate_bindings(wallet_core_install: &PathBuf) {
    let bindings = bindgen::Builder::default()
        // Core wallet-core headers
        .header(format!("{}/include/TrustWalletCore/TWAnyAddress.h", wallet_core_install.display()))
        .header(format!("{}/include/TrustWalletCore/TWHDWallet.h", wallet_core_install.display()))
        .header(format!("{}/include/TrustWalletCore/TWPrivateKey.h", wallet_core_install.display()))
        .header(format!("{}/include/TrustWalletCore/TWPublicKey.h", wallet_core_install.display()))
        .header(format!("{}/include/TrustWalletCore/TWDerivationPath.h", wallet_core_install.display()))
        .header(format!("{}/include/TrustWalletCore/TWCoinType.h", wallet_core_install.display()))
        .header(format!("{}/include/TrustWalletCore/TWString.h", wallet_core_install.display()))
        .header(format!("{}/include/TrustWalletCore/TWData.h", wallet_core_install.display()))
        
        // Address-related headers
        .header(format!("{}/include/TrustWalletCore/TWBitcoinAddress.h", wallet_core_install.display()))
        .header(format!("{}/include/TrustWalletCore/TWSegwitAddress.h", wallet_core_install.display()))
        .header(format!("{}/include/TrustWalletCore/TWSolanaAddress.h", wallet_core_install.display()))
        
        // Parsing configuration
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .generate_comments(false)
        .layout_tests(false)
        .derive_default(true)
        .derive_debug(true)
        
        // Only include TW* prefixed items
        .allowlist_function("TW.*")
        .allowlist_type("TW.*")
        .allowlist_var("TW.*")
        
        // Blocklist problematic items
        .blocklist_item(".*_bindgen_ty_.*")
        
        .generate()
        .expect("Unable to generate wallet-core bindings");
    
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap()).join("wallet_core_bindings.rs");
    bindings
        .write_to_file(out_path)
        .expect("Couldn't write wallet-core bindings");
}