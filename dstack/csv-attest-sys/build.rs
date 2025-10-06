use std::env;
use std::path::PathBuf;

fn main() {
    // 告诉 cargo 重新构建如果这些文件发生变化
    println!("cargo:rerun-if-changed=csrc/csv_attest.c");
    println!("cargo:rerun-if-changed=csrc/csv_attest.h");

    // 查找 OpenSSL/GmSSL 库
    let openssl = pkg_config::Config::new()
        .probe("openssl")
        .or_else(|_| pkg_config::Config::new().probe("gmssl"))
        .or_else(|_| pkg_config::Config::new().probe("libssl"));

    match openssl {
        Ok(lib) => {
            for include_path in lib.include_paths {
                println!("cargo:rustc-link-search=native={}", include_path.display());
            }
        }
        Err(_) => {
            // 尝试默认路径
            println!("cargo:rustc-link-search=native=/opt/gmssl/lib");
            println!("cargo:rustc-link-search=native=/usr/lib");
            println!("cargo:rustc-link-search=native=/usr/local/lib");
        }
    }

    // 编译 C 代码
    cc::Build::new()
        .file("csrc/csv_attest.c")
        .include("csrc")
        .include("/opt/gmssl/include")
        .include("/usr/include")
        .include("/usr/local/include")
        .flag("-m64")
        .flag("-mrdrnd")
        .define("LOG_ON", None)
        .compile("csv_attest");

    // 链接 OpenSSL/GmSSL 库
    println!("cargo:rustc-link-lib=crypto");
    println!("cargo:rustc-link-lib=ssl");

    // 生成绑定
    let bindings = bindgen::Builder::default()
        .header("csrc/csv_attest.h")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .generate()
        .expect("Unable to generate bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
