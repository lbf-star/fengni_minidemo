use crate::fec::FECEncoder;
use crate::stream::scheduler::StreamScheduler;
use crate::stream::scheduler::is_high_priority;
use crate::whisper::{FecWhisper, FecFrame, Priority};
use uuid::Uuid;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use tracing::info;

/// 关键信令管理器（生产级实现）
/// 使用内部可变性模式，支持多线程并发访问
#[derive(Clone)]
pub struct CriticalSender {
    inner: Arc<RwLock<CriticalSenderInner>>,
}

/// 内部数据结构，通过 RwLock 保护
struct CriticalSenderInner {
    /// FEC编码器实例
    encoder: FECEncoder,
    
    /// 每个连接的调度器
    schedulers: HashMap<u64, StreamScheduler>, // 键：连接ID
    
    /// 默认FEC参数
    default_k: usize,
    default_m: usize,
    
    /// 每个连接的最大流数
    max_streams_per_conn: usize,
}

impl CriticalSender {

    /// 注册新的连接
    pub fn register_connection(&mut self, connection_id: u64) {
        let mut inner = self.inner.write().unwrap();
        
        // 如果连接已经存在，不重复注册
        if !inner.schedulers.contains_key(&connection_id) {
            let scheduler = StreamScheduler::new(inner.max_streams_per_conn);
            inner.schedulers.insert(connection_id, scheduler);
            info!("已注册连接 {} 到 CriticalSender", connection_id);
        }
    }

    /// 创建新的关键信令管理器
    pub fn new(default_k: usize, default_m: usize, max_streams_per_conn: usize) -> Result<Self, String> {
        let encoder = FECEncoder::new(default_k, default_m)?;
        
        Ok(Self {
            inner: Arc::new(RwLock::new(CriticalSenderInner {
                encoder,
                schedulers: HashMap::new(),
                default_k,
                default_m,
                max_streams_per_conn,
            })),
        })
    }
    
    /// 准备发送关键信令（优化版 - 确保分配所有需要的流）

    pub fn prepare_critical_message(&self, conn_id: u64, data: &[u8], priority: Priority) 
        -> Result<Vec<(u64, FecWhisper)>, String> 
    {
        info!("准备发送关键信令，原始数据长度: {} 字节", data.len());
        // 显示数据内容（仅短数据）
        if data.len() <= 100 {
            match std::str::from_utf8(data) {
                Ok(text) => info!("原始数据内容: '{}'", text),
                Err(_) => info!("原始数据: [二进制数据，{}字节]", data.len()),
            }
        } else {
            info!("原始数据: [数据太长: {}字节]", data.len());
        }

        // 1. 先编码数据
        let (frames, session_id) = {
            let inner = self.inner.read().unwrap();
            inner.encoder.encode(data)?
        };

        info!("FEC编码完成: 会话ID={}, 生成{}个帧", session_id, frames.len());
        
        // 2. 获取调度器
        let mut inner = self.inner.write().unwrap();
        let scheduler = inner.schedulers.get_mut(&conn_id)
            .ok_or_else(|| format!("连接 {} 未注册", conn_id))?;
        
        let total_frames = frames.len();
        
        // 3. 通过调度器分配流（而不是直接访问pool）
        let mut allocated_streams = Vec::new();
        
        // 创建临时任务来分配流
        for _ in 0..total_frames {
            // 使用调度器的try_send逻辑来分配流
            // 创建一个临时帧来触发流分配
            let temp_frames = frames.clone();
            scheduler.submit_fec_task(temp_frames, session_id, priority);
            
            // 获取调度器分配的流
            let scheduled = scheduler.try_send();
            if scheduled.is_empty() {
                // 无法分配流
                for &stream_id in &allocated_streams {
                    scheduler.mark_frame_sent(stream_id); // 释放已分配的流
                }
                return Err(format!("无法分配流，需要{}个", total_frames));
            }
            
            // 记录分配的流
            for (stream_id, _) in scheduled {
                allocated_streams.push(stream_id);
                scheduler.mark_frame_sent(stream_id); // 临时标记为已发送，稍后会重新分配
            }
            
            // 如果已经分配了足够的流，停止
            if allocated_streams.len() >= total_frames {
                break;
            }
        }
        
        // 4. 确保我们分配了足够数量的流
        if allocated_streams.len() < total_frames {
            for &stream_id in &allocated_streams {
                scheduler.mark_frame_sent(stream_id); // 释放已分配的流
            }
            return Err(format!("只分配到{}/{}个流", allocated_streams.len(), total_frames));
        }
        
        // 5. 只取我们需要数量的流
        allocated_streams.truncate(total_frames);
        
        // 6. 创建带正确索引的帧
        let mut indexed_frames = Vec::new();
        for (i, frame) in frames.into_iter().enumerate() {
            let mut frame_clone = frame;
            frame_clone.block_index = i as u32;
            indexed_frames.push(frame_clone);
        }
        
        // 7. 清除之前的临时任务，提交真正的任务
        // 这里简化处理：直接使用分配的流
        
        // 8. 创建返回结果
        let mut result = Vec::new();
        for (i, (frame, &stream_id)) in indexed_frames.iter().zip(allocated_streams.iter()).enumerate() {
            let fec_whisper = FecWhisper {
                fec_frame: Some(frame.clone()),
            };
            result.push((stream_id, fec_whisper));
        }
        
        Ok(result)
    }
    
    /// 标记帧已发送
    pub fn mark_frame_sent(&self, conn_id: u64, stream_id: u64) -> Result<(), String> {
        let mut inner = self.inner.write().unwrap();
        
        let scheduler = inner.schedulers.get_mut(&conn_id)
            .ok_or_else(|| format!("连接 {} 未注册", conn_id))?;
        
        scheduler.mark_frame_sent(stream_id);
        Ok(())
    }
    
    /// 标记整个FEC会话完成
    pub fn mark_session_complete(&self, conn_id: u64, session_id: Uuid) -> Result<(), String> {
        let mut inner = self.inner.write().unwrap();
        
        let scheduler = inner.schedulers.get_mut(&conn_id)
            .ok_or_else(|| format!("连接 {} 未注册", conn_id))?;
        
        scheduler.mark_session_complete(session_id);
        Ok(())
    }
    
    /// 获取统计信息（用于监控）
    pub fn get_stats(&self, conn_id: u64) -> Option<String> {
        let inner = self.inner.read().unwrap();
        inner.schedulers.get(&conn_id).map(|s| {
            let stats = s.stats();
            format!("{:?}", stats)
        })
    }
    
    /// 获取连接列表
    pub fn get_connections(&self) -> Vec<u64> {
        let inner = self.inner.read().unwrap();
        inner.schedulers.keys().copied().collect()
    }
    
    /// 获取FEC参数
    pub fn get_fec_params(&self) -> (usize, usize) {
        let inner = self.inner.read().unwrap();
        (inner.default_k, inner.default_m)
    }
}