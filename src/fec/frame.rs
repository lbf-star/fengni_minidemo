use twox_hash::XxHash64;
use std::hash::Hasher;
use crate::whisper::{FecFrame, BlockType};

/// 计算FEC帧的xxHash64哈希值
/// 注意：计算时排除xxhash64字段本身
pub fn calculate_frame_hash(frame: &FecFrame) -> u64 {
    let mut hasher = XxHash64::with_seed(0);
    
    // 按字段顺序哈希（与protobuf编码顺序一致）
    hasher.write(&frame.session_id);
    hasher.write(&frame.block_index.to_le_bytes());
    hasher.write(&frame.k.to_le_bytes());
    hasher.write(&frame.m.to_le_bytes());
    hasher.write(&frame.payload);
    hasher.write(&[frame.block_type() as u8]);
    
    // 注意：不包含frame.xxhash64字段
    
    hasher.finish()
}

/// 验证FEC帧的完整性
pub fn validate_frame(frame: &FecFrame) -> bool {
    let expected_hash = calculate_frame_hash(frame);
    expected_hash == frame.xxhash64
}

/// 创建新的FEC帧（自动计算哈希）
pub fn create_fec_frame(
    session_id: [u8; 16],
    block_index: u32,
    k: u32,
    m: u32,
    payload: Vec<u8>,
    block_type: BlockType,
) -> FecFrame {
    let mut frame = FecFrame {
        session_id: session_id.to_vec(),
        block_index,
        k,
        m,
        payload,
        xxhash64: 0, // 临时占位
        block_type: block_type as i32,
        version: 1,
    };
    
    // 计算并设置哈希
    frame.xxhash64 = calculate_frame_hash(&frame);
    frame
}