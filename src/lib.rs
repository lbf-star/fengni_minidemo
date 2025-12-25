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

/// 新增：消息分帧工具模块
pub mod framing;
/// 动态分帧模块 (Phase 3)
pub mod dynamic_framing;

/// 重新导出常用类型
pub use whisper::*;
pub use fec::FECEncoder;
pub use stream::{
    StreamPool, 
    StreamScheduler, 
    UnifiedStreamManager,
    PoolStats, 
    SchedulerStats,
    ManagerStats
};
pub use critical_sender::CriticalSender;
pub use framing::{frame_message, parse_framed_message, FramingError}; // 新增导出

/// 库版本信息
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// 默认会话基础种子 (Phase 3+)
pub const SESSION_BASE_SEED: [u8; 32] = [0x42; 32];

// 日志系统
pub mod logging;