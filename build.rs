
extern crate rustc_version;
extern crate cc;

use std::path::Path;

use rustc_version::{version, version_meta, Channel};

const FFI_SRC_DIR: &str = "src/ffi";

//TODO: Replace the wrapper C file with a pure Rust impl in `ffi::cookie::`
fn build_cookie_wrapper(floc: impl AsRef<Path>)
{
    let mut builder = cc::Build::new();
    // --std=c99 -W -Wall -Werror -pedantic -O3 -flto
    builder.flag("--std=c99")
	.flag("-W")
	.flag("-Wall")
	.flag_if_supported("-Wextra")
	.flag("-Werror")
	.flag("-pedantic")
	.flag("-fno-strict-aliasing")
        .include("include/")
	.opt_level(3)
	// .flag_if_supported("-flto") //XXX: For some reason, this makes static linking the library fail.

 	// Not sure if we want these two. We can check the codegen later.
	//.pic(false)
	//.use_plt(false)
	
	.file(Path::new(FFI_SRC_DIR).join(floc))
	.compile("wrapper");
}

fn main() {
    // Assert we haven't travelled back in time
    assert!(version().unwrap().major >= 1);

    // Set cfg flags depending on release channel
    match version_meta().unwrap().channel {
        Channel::Stable => {
            println!("cargo:rustc-cfg=stable");
        }
        Channel::Beta => {
            println!("cargo:rustc-cfg=beta");
        }
        Channel::Nightly => {
            println!("cargo:rustc-cfg=nightly");
        }
        Channel::Dev => {
            println!("cargo:rustc-cfg=dev");
        }
    }

    build_cookie_wrapper("wrapper.c");

//println!("cargo:rustc-link-lib={}", link);
}
