//! FEC（前向纠错）模块

mod encoder;
mod reassembler;
mod frame;

// 重新导出
pub use encoder::FECEncoder;
pub use reassembler::{FECReassembler, RecoveredMessage, ReassemblerStats};
pub use frame::create_fec_frame;