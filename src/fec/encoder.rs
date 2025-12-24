use reed_solomon_erasure::galois_8::ReedSolomon;
use uuid::Uuid;
use crate::whisper::{FecFrame, BlockType};

/// FEC编码器：将数据分割为k个块，生成m个冗余块
pub struct FECEncoder {
    rs: ReedSolomon,
    k: usize,
    m: usize,
    block_size: usize,
}

impl FECEncoder {
    /// 创建新的FEC编码器
    /// - k: 原始数据块数（建议4-8）
    /// - m: 冗余块数（建议2-4）
    pub fn new(k: usize, m: usize) -> Result<Self, String> {
        if k == 0 || m == 0 {
            return Err("k和m必须大于0".to_string());
        }
        
        let rs = ReedSolomon::new(k, m)
            .map_err(|e| format!("ReedSolomon初始化失败: {}", e))?;
        
        // 计算推荐的块大小（可根据实际数据调整）
        let block_size = 1024; // 1KB，可调整
        
        Ok(Self { rs, k, m, block_size })
    }
    
    /// 编码数据，返回FEC帧列表和会话ID
    pub fn encode(&self, data: &[u8]) -> Result<(Vec<FecFrame>, Uuid), String> {
        // 1. 生成会话ID
        let session_id = Uuid::new_v4();
        
        // 2. 分割数据为k个等长块（最后一块填充）
        let blocks = self.split_into_blocks(data);
        
        // 3. 生成冗余块
        let mut parity = vec![vec![0u8; self.block_size]; self.m];
        // 创建所有块的向量（数据块 + 校验块）
        let mut all_shards = blocks.clone();
        all_shards.extend(parity.clone());

        // 调用encode（只接受一个参数）
        self.rs.encode(&mut all_shards)
        .map_err(|e| format!("FEC编码失败: {}", e))?;
        
        // 4. 创建FEC帧
        let mut frames = Vec::with_capacity(self.k + self.m);
        
        // 原始数据块
        for (i, block) in blocks.into_iter().enumerate() {
            frames.push(crate::fec::frame::create_fec_frame(
                *session_id.as_bytes(),
                i as u32,
                self.k as u32,
                self.m as u32,
                block,
                BlockType::Original,
            ));
        }
        
        // 冗余块
        for (i, block) in parity.into_iter().enumerate() {
            frames.push(crate::fec::frame::create_fec_frame(
                *session_id.as_bytes(),
                (self.k + i) as u32,
                self.k as u32,
                self.m as u32,
                block,
                BlockType::Redundant,
            ));
        }
        
        Ok((frames, session_id))
    }
    
    /// 从任意k个块恢复原始数据
    pub fn decode(&self, frames: &[FecFrame]) -> Result<Vec<u8>, String> {
        // 实现解码逻辑（稍后补充）
        unimplemented!("FEC解码功能待实现")
    }
    
    /// 分割数据为块
    fn split_into_blocks(&self, data: &[u8]) -> Vec<Vec<u8>> {
        let total_blocks = self.k;
        let mut blocks = vec![vec![0u8; self.block_size]; total_blocks];
        
        for (i, chunk) in data.chunks(self.block_size).enumerate() {
            if i >= total_blocks {
                break;
            }
            blocks[i][..chunk.len()].copy_from_slice(chunk);
        }
        
        blocks
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fec::frame::validate_frame;
    
    #[test]
    fn test_fec_encoder_basic() {
        let encoder = FECEncoder::new(4, 2).unwrap();
        let test_data = b"Test data for FEC encoding verification.";
        
        let (frames, session_id) = encoder.encode(test_data).unwrap();
        
        // 验证帧数量
        assert_eq!(frames.len(), 6); // 4个数据块 + 2个冗余块
        
        // 验证会话ID一致性
        for frame in &frames {
            assert_eq!(frame.session_id, session_id.as_bytes().to_vec());
            assert_eq!(frame.k, 4);
            assert_eq!(frame.m, 2);
            
            // 验证哈希
            assert!(validate_frame(frame));
        }
        
        println!("FEC编码测试通过: {}个帧，会话ID: {}", 
                 frames.len(), session_id);
    }
}