use std::env;

fn main() {

    let rustc_link_lib = match env::var("LIBCAP_LIB_NAME") {
        Ok(name) => name, // alternative name for libcap
        Err(_) => String::from("cap"),
    };

    let rustc_link_type = match env::var("LIBCAP_LIB_TYPE") {
        Ok(mode) => mode, // static, framework, dylib
        Err(_) => String::from("dylib"),
    };

    println!("cargo:rustc-link-lib={}={}",
             rustc_link_type,
             rustc_link_lib);

    match env::var("LIBCAP_LIB_PATH") {
        Ok(rustc_link_search) => println!("cargo:rustc-link-search=native={}", rustc_link_search),
        Err(_) => {} // fallback to LD_LIBRARY_PATH
    };
}
