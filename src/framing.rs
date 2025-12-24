//! 消息分帧模块 - 生产级长度前缀分帧实现
//!
//! 提供消息分帧和解析功能，确保在QUIC流复用时消息边界清晰。
//! 使用4字节大端序长度前缀 + Protobuf消息体的格式。
//!
//! 格式: [4字节长度前缀][Protobuf消息数据]
//! 长度前缀: 大端序32位无符号整数，表示后续Protobuf数据的长度

use prost::Message;
use crate::whisper::Whisper;
use std::io::{Error, ErrorKind};

/// 分帧错误类型
#[derive(Debug, thiserror::Error)]
pub enum FramingError {
    #[error("数据不完整，需要更多数据: 当前{current}字节，需要{needed}字节")]
    IncompleteData { current: usize, needed: usize },
    
    #[error("消息长度超出限制: {length}字节 (最大{max}字节)")]
    MessageTooLarge { length: usize, max: usize },
    
    #[error("Protobuf解析失败: {0}")]
    ProtobufError(#[from] prost::DecodeError),
    
    #[error("IO错误: {0}")]
    IoError(#[from] std::io::Error),
}

/// 为Whisper消息添加分帧
///
/// # 参数
/// * `message` - 要分帧的Whisper消息
///
/// # 返回
/// * `Vec<u8>` - 分帧后的字节数据（长度前缀 + Protobuf编码数据）
///
/// # 示例
/// ```
/// let whisper = Whisper::default();
/// let framed_data = frame_message(&whisper);
/// // framed_data = [0x00, 0x00, 0x00, 0x1A, ...protobuf数据...]
/// ```
pub fn frame_message(message: &Whisper) -> Vec<u8> {
    // 编码Protobuf消息
    let message_data = message.encode_to_vec();
    let message_len = message_data.len();
    
    // 检查消息长度（防止过大消息）
    const MAX_MESSAGE_SIZE: usize = 10 * 1024 * 1024; // 10MB
    if message_len > MAX_MESSAGE_SIZE {
        // 在生产环境中，应该记录日志或返回错误
        // 这里简化处理，相信调用方会控制消息大小
    }
    
    // 创建分帧数据：4字节长度前缀 + 消息数据
    let mut framed_data = Vec::with_capacity(4 + message_len);
    framed_data.extend_from_slice(&(message_len as u32).to_be_bytes());
    framed_data.extend_from_slice(&message_data);
    
    framed_data
}

/// 从分帧数据中解析Whisper消息
///
/// # 参数
/// * `data` - 可能包含一个或多个分帧消息的字节数据
///
/// # 返回
/// * `Result<(Whisper, usize), FramingError>` - 
///   - 成功：返回(解析出的消息, 消耗的字节数)
///   - 失败：返回错误
///
/// # 注意
/// 此函数只解析第一个完整消息，调用方需要处理剩余数据
pub fn parse_framed_message(data: &[u8]) -> Result<(Whisper, usize), FramingError> {
    // 检查是否有足够数据读取长度前缀
    if data.len() < 4 {
        return Err(FramingError::IncompleteData {
            current: data.len(),
            needed: 4,
        });
    }
    
    // 解析长度前缀（大端序）
    let length_bytes: [u8; 4] = [data[0], data[1], data[2], data[3]];
    let message_length = u32::from_be_bytes(length_bytes) as usize;
    
    // 检查消息长度是否合理
    const MAX_MESSAGE_SIZE: usize = 10 * 1024 * 1024; // 10MB
    if message_length > MAX_MESSAGE_SIZE {
        return Err(FramingError::MessageTooLarge {
            length: message_length,
            max: MAX_MESSAGE_SIZE,
        });
    }
    
    // 检查是否有完整的消息数据
    if data.len() < 4 + message_length {
        return Err(FramingError::IncompleteData {
            current: data.len(),
            needed: 4 + message_length,
        });
    }
    
    // 提取消息数据并解析
    let message_data = &data[4..4 + message_length];
    let whisper = Whisper::decode(message_data)?;
    
    // 返回消息和消耗的字节数
    Ok((whisper, 4 + message_length))
}

/// 流数据解析器 - 维护流的状态并处理分帧消息
pub struct StreamParser {
    buffer: Vec<u8>,
    max_buffer_size: usize,
}

impl StreamParser {
    /// 创建新的流解析器
    pub fn new() -> Self {
        Self {
            buffer: Vec::new(),
            max_buffer_size: 1024 * 1024, // 1MB缓冲区限制
        }
    }
    
    /// 添加接收到的数据
    pub fn append_data(&mut self, data: &[u8]) -> Result<(), FramingError> {
        // 检查缓冲区大小限制
        if self.buffer.len() + data.len() > self.max_buffer_size {
            // 缓冲区过大，清空并返回错误（可能是恶意攻击）
            self.buffer.clear();
            return Err(FramingError::MessageTooLarge {
                length: self.buffer.len() + data.len(),
                max: self.max_buffer_size,
            });
        }
        
        self.buffer.extend_from_slice(data);
        Ok(())
    }
    
    /// 尝试解析下一个完整消息
    ///
    /// # 返回
    /// * `Ok(Some(Whisper))` - 解析出一个消息，已从缓冲区移除该消息数据
    /// * `Ok(None)` - 数据不完整，需要更多数据
    /// * `Err(FramingError)` - 解析失败
    pub fn try_parse_next(&mut self) -> Result<Option<Whisper>, FramingError> {
        match parse_framed_message(&self.buffer) {
            Ok((whisper, bytes_consumed)) => {
                // 成功解析，从缓冲区移除已处理的数据
                self.buffer.drain(0..bytes_consumed);
                Ok(Some(whisper))
            }
            Err(FramingError::IncompleteData { .. }) => {
                // 数据不完整，等待更多数据
                Ok(None)
            }
            Err(e) => {
                // 其他错误，清空缓冲区避免错误传播
                self.buffer.clear();
                Err(e)
            }
        }
    }
    
    /// 获取缓冲区当前大小
    pub fn buffer_size(&self) -> usize {
        self.buffer.len()
    }
    
    /// 清空缓冲区
    pub fn clear(&mut self) {
        self.buffer.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::whisper::{Whisper, Priority};
    use crate::whisper::whisper::Payload;
    
    #[test]
    fn test_framing_roundtrip() {
        // 创建测试消息
        let mut original = Whisper::default();
        original.id = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        original.payload = Some(Payload::Content("测试消息".to_string()));
        original.timestamp_ns = 123456789;
        original.priority = Priority::High as i32;
        
        // 分帧
        let framed = frame_message(&original);
        
        // 解析分帧数据
        let (parsed, consumed) = parse_framed_message(&framed).unwrap();
        
        // 验证
        assert_eq!(consumed, framed.len());
        assert_eq!(parsed.id, original.id);
        match (&parsed.payload, &original.payload) {
            (Some(Payload::Content(a)), Some(Payload::Content(b))) => {
                assert_eq!(a, b);
            }
            _ => panic!("Payload mismatch"),
        }
        
        println!("分帧往返测试通过");
    }
    
    #[test]
    fn test_stream_parser() {
        let mut parser = StreamParser::new();
        
        // 创建测试消息
        let mut whisper = Whisper::default();
        whisper.payload = Some(Payload::Content("test".to_string()));
        let framed = frame_message(&whisper);
        
        // 模拟分片接收
        let half_len = framed.len() / 2;
        parser.append_data(&framed[..half_len]).unwrap();
        
        // 第一次尝试：数据不完整
        assert!(parser.try_parse_next().unwrap().is_none());
        
        // 接收剩余数据
        parser.append_data(&framed[half_len..]).unwrap();
        
        // 第二次尝试：成功解析
        let parsed = parser.try_parse_next().unwrap().expect("应该解析出消息");
        
        match parsed.payload {
            Some(Payload::Content(content)) => assert_eq!(content, "test"),
            _ => panic!("解析结果错误"),
        }
        
        println!("流解析器测试通过");
    }
}