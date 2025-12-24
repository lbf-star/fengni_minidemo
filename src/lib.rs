//! Silent Speaker - 实时通信系统核心库

/// Protobuf 消息定义（由 build.rs 生成）
pub mod whisper {
    include!(concat!(env!("OUT_DIR"), "/whisper.rs"));
}

/// 重新导出常用类型
pub use whisper::*;

/// 库版本信息
pub const VERSION: &str = env!("CARGO_PKG_VERSION");