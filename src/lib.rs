//! Silent Speaker - 实时通信系统核心库

/// Protobuf 消息定义（由 build.rs 生成）
pub mod whisper {
    include!(concat!(env!("OUT_DIR"), "/whisper.rs"));
}

/// FEC（前向纠错）模块
pub mod fec;

/// 流管理模块  
pub mod stream;

/// 关键信令发送器
pub mod critical_sender;

/// 重新导出常用类型
pub use whisper::*;
pub use fec::FECEncoder;
pub use stream::{StreamPool, StreamScheduler};
pub use critical_sender::CriticalSender;

/// 库版本信息
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

// 日志系统
pub mod logging;