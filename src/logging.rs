use tracing_subscriber::{fmt, EnvFilter, prelude::*};

/// 初始化 tracing 日志系统
/// 生产环境建议通过 RUST_LOG 环境变量控制
pub fn init() {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info"));

    tracing_subscriber::registry()
        .with(filter)
        .with(fmt::layer())
        .init();

    tracing::info!("日志系统初始化完成 (VERSION: {})", env!("CARGO_PKG_VERSION"));
}