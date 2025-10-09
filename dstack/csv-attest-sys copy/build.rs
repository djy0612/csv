use std::env;
use std::path::PathBuf;

fn main() {
    // 告诉 cargo 重新构建如果这些文件发生变化
    println!("cargo:rerun-if-changed=csrc/csv_attest.c");
    println!("cargo:rerun-if-changed=csrc/csv_attest.h");

    // 调试信息：打印所有相关的环境变量
    println!("cargo:warning=DEBUG: Checking environment variables...");
    for env_var in ["RECIPE_SYSROOT_NATIVE", "STAGING_DIR_NATIVE", "STAGING_BINDIR_NATIVE", "PKG_CONFIG_SYSROOT_DIR", "WORKDIR", "TMPDIR"] {
        if let Ok(value) = env::var(env_var) {
            println!("cargo:warning=DEBUG: {} = {}", env_var, value);
        } else {
            println!("cargo:warning=DEBUG: {} not set", env_var);
        }
    }
    
    // 打印当前工作目录
    if let Ok(current_dir) = env::current_dir() {
        println!("cargo:warning=DEBUG: Current directory = {}", current_dir.display());
    }

    let mut build = cc::Build::new();
    build.file("csrc/csv_attest.c")
          .include("csrc")
          .flag("-m64")
          .flag("-mrdrnd")
          .flag("-Wno-deprecated-declarations")
          .define("LOG_ON", None);
    
    // 首先尝试添加 recipe-sysroot-native 的包含路径
    let work_dir = env::var("WORKDIR").unwrap_or_default();
    if !work_dir.is_empty() {
        let native_sysroot = format!("{}/recipe-sysroot-native", work_dir);
        let include_path = format!("{}/usr/include", native_sysroot);
        println!("cargo:warning=Adding include path: {}", include_path);
        build.include(&include_path);
    }
    
    // 在交叉编译环境中，直接使用环境变量路径
    let mut found_sysroot = false;
    
    // 强制设置正确的 sysroot 路径 - 优先检查 WORKDIR
    let work_dir = env::var("WORKDIR").unwrap_or_default();
    if !work_dir.is_empty() {
        let native_sysroot = format!("{}/recipe-sysroot-native", work_dir);
        let include_path = format!("{}/usr/include", native_sysroot);
        println!("cargo:warning=FORCE: Using WORKDIR-based native sysroot: {}", native_sysroot);
        println!("cargo:warning=FORCE: Include path: {}", include_path);
        build.include(&include_path);
        
        // 同时添加 GMSSL 路径（如果存在）
        if std::path::Path::new("/opt/gmssl/include").exists() {
            println!("cargo:warning=FORCE: Adding GMSSL include path: /opt/gmssl/include");
            build.include("/opt/gmssl/include");
        }
        
        println!("cargo:rustc-link-search=native={}/usr/lib", native_sysroot);
        println!("cargo:rustc-link-search=native=/opt/gmssl/lib");
        println!("cargo:rustc-link-lib=crypto");
        println!("cargo:rustc-link-lib=ssl");
        found_sysroot = true;
    }
    
    // 如果 WORKDIR 方法失败，尝试从当前工作目录推断
    if !found_sysroot {
        if let Ok(current_dir) = env::current_dir() {
            let current_str = current_dir.to_string_lossy();
            if current_str.contains("/work/") && current_str.contains("/dstack-guest/") {
                // 从当前目录构建 native sysroot 路径 - 需要回到工作目录根
                let work_root = current_str.split("/dstack/").next().unwrap_or(&current_str);
                let native_sysroot = format!("{}/recipe-sysroot-native", work_root);
                let include_path = format!("{}/usr/include", native_sysroot);
                println!("cargo:warning=FORCE: Using current-dir-based native sysroot: {}", native_sysroot);
                println!("cargo:warning=FORCE: Include path: {}", include_path);
                build.include(&include_path);
                
                // 同时添加 GMSSL 路径（如果存在）
                if std::path::Path::new("/opt/gmssl/include").exists() {
                    println!("cargo:warning=FORCE: Adding GMSSL include path: /opt/gmssl/include");
                    build.include("/opt/gmssl/include");
                }
                
                println!("cargo:rustc-link-search=native={}/usr/lib", native_sysroot);
                println!("cargo:rustc-link-search=native=/opt/gmssl/lib");
                println!("cargo:rustc-link-lib=crypto");
                println!("cargo:rustc-link-lib=ssl");
                found_sysroot = true;
            }
        }
    }
    
    // 尝试多个可能的环境变量
    for env_var in ["RECIPE_SYSROOT_NATIVE", "STAGING_DIR_NATIVE", "STAGING_BINDIR_NATIVE"] {
            if let Ok(sysroot) = env::var(env_var) {
                let include_path = format!("{}/usr/include", sysroot);
                println!("cargo:warning=Using {}: {}", env_var, sysroot);
                println!("cargo:warning=Include path: {}", include_path);
                build.include(&include_path);
                
                // 同时添加 GMSSL 路径（如果存在）
                if std::path::Path::new("/opt/gmssl/include").exists() {
                    println!("cargo:warning=Adding GMSSL include path: /opt/gmssl/include");
                    build.include("/opt/gmssl/include");
                }
                
                println!("cargo:rustc-link-search=native={}/usr/lib", sysroot);
                println!("cargo:rustc-link-search=native=/opt/gmssl/lib");
                println!("cargo:rustc-link-lib=crypto");
                println!("cargo:rustc-link-lib=ssl");
                found_sysroot = true;
                break;
            }
    }
    
    // 在 bitbake 环境中，还需要检查 PKG_CONFIG_SYSROOT_DIR
    if !found_sysroot {
        if let Ok(pkg_config_sysroot) = env::var("PKG_CONFIG_SYSROOT_DIR") {
            let include_path = format!("{}/usr/include", pkg_config_sysroot);
            println!("cargo:warning=Using PKG_CONFIG_SYSROOT_DIR: {}", pkg_config_sysroot);
            println!("cargo:warning=Include path: {}", include_path);
            build.include(&include_path);
            
            // 同时添加 GMSSL 路径（如果存在）
            if std::path::Path::new("/opt/gmssl/include").exists() {
                println!("cargo:warning=Adding GMSSL include path: /opt/gmssl/include");
                build.include("/opt/gmssl/include");
            }
            
            println!("cargo:rustc-link-search=native={}/usr/lib", pkg_config_sysroot);
            println!("cargo:rustc-link-search=native=/opt/gmssl/lib");
            println!("cargo:rustc-link-lib=crypto");
            println!("cargo:rustc-link-lib=ssl");
            found_sysroot = true;
        }
    }
    
    // 如果还是没有找到，尝试从当前工作目录推断
    if !found_sysroot {
        if let Ok(current_dir) = env::current_dir() {
            let current_str = current_dir.to_string_lossy();
            if current_str.contains("/work/") && current_str.contains("/dstack-guest/") {
                // 从当前目录构建 native sysroot 路径 - 需要回到工作目录根
                let work_root = current_str.split("/dstack/").next().unwrap_or(&current_str);
                let native_sysroot = format!("{}/recipe-sysroot-native", work_root);
                let include_path = format!("{}/usr/include", native_sysroot);
                println!("cargo:warning=Using inferred sysroot from current dir: {}", native_sysroot);
                println!("cargo:warning=Include path: {}", include_path);
                build.include(&include_path);
                
                // 同时添加 GMSSL 路径（如果存在）
                if std::path::Path::new("/opt/gmssl/include").exists() {
                    println!("cargo:warning=Adding GMSSL include path: /opt/gmssl/include");
                    build.include("/opt/gmssl/include");
                }
                
                println!("cargo:rustc-link-search=native={}/usr/lib", native_sysroot);
                println!("cargo:rustc-link-search=native=/opt/gmssl/lib");
                println!("cargo:rustc-link-lib=crypto");
                println!("cargo:rustc-link-lib=ssl");
                found_sysroot = true;
            }
        }
    }
    
    if !found_sysroot {
        // 回退到默认路径（仅用于本地构建）
        println!("cargo:warning=No sysroot found, using fallback path");
        build.include("/opt/gmssl/include");
        println!("cargo:rustc-link-search=native=/opt/gmssl/lib");
        println!("cargo:rustc-link-lib=crypto");
        println!("cargo:rustc-link-lib=ssl");
    }

    build.compile("csv_attest");

    // 生成绑定 - 使用系统默认编译器
    let mut bindgen_builder = bindgen::Builder::default()
        .header("csrc/csv_attest.h")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()));
    
    // 在 bitbake 环境中添加正确的头文件路径
    if found_sysroot {
        // 使用找到的 sysroot 路径
        for env_var in ["RECIPE_SYSROOT_NATIVE", "STAGING_DIR_NATIVE", "STAGING_BINDIR_NATIVE"] {
            if let Ok(sysroot) = env::var(env_var) {
                bindgen_builder = bindgen_builder
                    .clang_arg(format!("-I{}/usr/include", sysroot))
                    .clang_arg(format!("-I{}/usr/include/x86_64-linux-gnu", sysroot))
                    .clang_arg(format!("-I{}/usr/lib/x86_64-poky-linux/gcc/x86_64-poky-linux/13.3.0/include", sysroot));
                break;
            }
        }
        
        // 也检查 PKG_CONFIG_SYSROOT_DIR
        if let Ok(pkg_config_sysroot) = env::var("PKG_CONFIG_SYSROOT_DIR") {
            bindgen_builder = bindgen_builder
                .clang_arg(format!("-I{}/usr/include", pkg_config_sysroot))
                .clang_arg(format!("-I{}/usr/include/x86_64-linux-gnu", pkg_config_sysroot));
        }
        
        // 添加系统头文件路径
        if let Ok(current_dir) = env::current_dir() {
            let current_str = current_dir.to_string_lossy();
            if current_str.contains("/work/") && current_str.contains("/dstack-guest/") {
                let work_root = current_str.split("/dstack/").next().unwrap_or(&current_str);
                let native_sysroot = format!("{}/recipe-sysroot-native", work_root);
                bindgen_builder = bindgen_builder
                    .clang_arg(format!("-I{}/usr/include", native_sysroot))
                    .clang_arg(format!("-I{}/usr/include/x86_64-linux-gnu", native_sysroot))
                    .clang_arg(format!("-I{}/usr/lib/x86_64-poky-linux/gcc/x86_64-poky-linux/13.3.0/include", native_sysroot));
            }
        }
    } else {
        // 本地构建时的默认路径
        bindgen_builder = bindgen_builder
            .clang_arg("-I/usr/include")
            .clang_arg("-I/usr/include/x86_64-linux-gnu");
    }
    
    let bindings = bindgen_builder
        .generate()
        .expect("Unable to generate bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
