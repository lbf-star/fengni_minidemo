use crate::fec::FECEncoder;
use crate::stream::StreamScheduler;
use crate::whisper::{FecWhisper, FecFrame, Priority};
use uuid::Uuid;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

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
    
    /// 为新连接注册
    pub fn register_connection(&self, conn_id: u64) {
        let max_streams = {
            // 先获取只读引用读取参数
            let inner = self.inner.read().unwrap();
            inner.max_streams_per_conn
        };
        
        // 然后获取写引用插入调度器
        let mut inner = self.inner.write().unwrap();
        inner.schedulers.insert(
            conn_id,
            StreamScheduler::new(max_streams)
        );
    }
    
    /// 移除连接
    pub fn remove_connection(&self, conn_id: u64) {
        let mut inner = self.inner.write().unwrap();
        inner.schedulers.remove(&conn_id);
    }
    
    /// 准备发送关键信令
    pub fn prepare_critical_message(&self, conn_id: u64, data: &[u8], priority: Priority) 
        -> Result<Vec<(u64, FecWhisper)>, String> 
    {
        // 1. 先编码数据（需要 encoder）
        let (frames, session_id) = {
            let inner = self.inner.read().unwrap();
            inner.encoder.encode(data)?
        };
        
        // 2. 提交给调度器并获取发送列表
        let frames_to_send = {
            let mut inner = self.inner.write().unwrap();
            let scheduler = inner.schedulers.get_mut(&conn_id)
                .ok_or_else(|| format!("连接 {} 未注册", conn_id))?;
            
            scheduler.submit_fec_task(frames.clone(), session_id, priority);
            scheduler.try_send()
        };
        
        // 3. 转换为FECWhisper消息
        let mut result = Vec::new();
        for (stream_id, frame) in frames_to_send {
            let fec_whisper = FecWhisper {
                fec_frame: Some(frame),
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