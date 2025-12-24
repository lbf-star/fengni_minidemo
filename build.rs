use std::path::Path;

fn main() {
    println!("cargo:rerun-if-changed=whisper.proto");
    
    let out_dir = std::env::var("OUT_DIR").unwrap();
    let out_path = Path::new(&out_dir);
    
    // 明确指定输出目录
    prost_build::Config::new()
        .out_dir(out_path)
        .compile_protos(&["whisper.proto"], &["."])
        .unwrap();
}