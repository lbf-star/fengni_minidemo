use reed_solomon_erasure::galois_8::ReedSolomon;
use uuid::Uuid;
use crate::whisper::{FecFrame, BlockType};
use tracing::info;

/// FEC编码器：将数据分割为k个块，生成m个冗余块（最小填充方案）
pub struct FECEncoder {
    rs: ReedSolomon,
    k: usize,
    m: usize,
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
        
        Ok(Self { rs, k, m })
    }
    
    /// 编码数据，返回FEC帧列表和会话ID（最小填充方案）
    pub fn encode(&self, data: &[u8]) -> Result<(Vec<FecFrame>, Uuid), String> {
        // 1. 生成会话ID
        let session_id = Uuid::new_v4();
        
        // 2. 准备数据：添加4字节长度前缀
        let mut framed_data = Vec::with_capacity(data.len() + 4);
        framed_data.extend_from_slice(&(data.len() as u32).to_le_bytes());
        framed_data.extend_from_slice(data);
        
        // 3. 计算最小块大小（64字节对齐）
        let total_data_blocks = self.k;
        let total_size = framed_data.len();
        
        // 计算最小块大小：总大小/k，向上取整，然后64字节对齐
        let min_block_size = (total_size + total_data_blocks - 1) / total_data_blocks;
        let block_size = ((min_block_size + 63) / 64) * 64; // 64字节对齐
        
        info!("FEC编码: 原始数据{}字节, 添加长度前缀后{}字节, 块大小: {}字节, k={}, m={}",
            data.len(), total_size, block_size, self.k, self.m);
        
        // 4. 分割数据为k个等长块（填充0）
        let blocks = self.split_into_blocks(&framed_data, block_size);
        
        // 5. 生成冗余块
        let mut all_shards = blocks.clone();
        let mut parity = vec![vec![0u8; block_size]; self.m];
        all_shards.extend(parity.clone());
        
        // RS编码
        self.rs.encode(&mut all_shards)
            .map_err(|e| format!("FEC编码失败: {}", e))?;
        
        // 提取生成的冗余块
        for i in 0..self.m {
            parity[i] = all_shards[self.k + i].clone();
        }
        
        // 6. 创建FEC帧
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
        
        info!("FEC会话 {}: 生成 {} 个帧 ({}原始 + {}冗余)",
            session_id, frames.len(), self.k, self.m);
        
        Ok((frames, session_id))
    }
    
    /// 分割数据为等长块（最小填充）
    fn split_into_blocks(&self, data: &[u8], block_size: usize) -> Vec<Vec<u8>> {
        let total_blocks = self.k;
        let mut blocks = vec![vec![0u8; block_size]; total_blocks];
        
        // 复制数据到各个块
        for (block_index, block) in blocks.iter_mut().enumerate() {
            let start = block_index * block_size;
            let end = std::cmp::min(start + block_size, data.len());
            
            if start < data.len() {
                let len_to_copy = end - start;
                block[0..len_to_copy].copy_from_slice(&data[start..end]);
                
                // 填充部分保持为0（这是安全的，因为接收方知道实际数据长度）
            }
        }
        
        blocks
    }
    
    /// 从任意k个块恢复原始数据（仅API，实际解码在reassembler中）
    pub fn decode(&self, frames: &[FecFrame]) -> Result<Vec<u8>, String> {
        // 注意：实际解码逻辑在reassembler.rs中
        // 这里只提供接口兼容性
        unimplemented!("FEC解码应在reassembler中完成")
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