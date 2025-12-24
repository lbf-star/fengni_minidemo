use tracing_subscriber::fmt;

/// 初始化 tracing 日志系统（控制台输出）
pub fn init() {
    fmt::init(); // 默认配置，输出到 stderr
    tracing::info!("日志系统初始化完成");
}