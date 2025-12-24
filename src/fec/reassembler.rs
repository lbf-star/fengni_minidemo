//! FEC接收端重组器
//!
//! 采用组合设计模式，分离会话管理和解码逻辑
//! 解决Rust借用检查器问题，同时保持高性能

use crate::whisper::FecFrame;
use reed_solomon_erasure::galois_8::ReedSolomon;
use std::collections::{HashMap, VecDeque};
use std::time::{Instant, Duration};
use uuid::Uuid;
use tracing::{debug, info};

// ============ 数据结构定义 ============

/// FEC会话状态（不可变状态）
#[derive(Debug, Clone)]
pub enum SessionState {
    /// 正在收集数据块
    Collecting {
        received_blocks: HashMap<u32, Vec<u8>>,
        received_count: usize,
        start_time: Instant,
    },
    /// 正在解码
    Decoding,
    /// 已完成
    Completed {
        original_data: Vec<u8>,
        recovery_time: Instant,
    },
    /// 已失败
    Failed {
        reason: String,
        failure_time: Instant,
    },
}

/// 会话管理器 - 只负责状态管理
#[derive(Debug)]
struct SessionManager {
    /// 活跃的FEC会话
    sessions: HashMap<Uuid, SessionState>,
    
    /// 会话超时时间
    session_timeout: Duration,
    
    /// 会话清理超时时间（完成后保留的时间）
    session_cleanup_timeout: Duration,
    
    /// 统计信息
    stats: ReassemblerStats,
}

/// 恢复的消息
#[derive(Debug, Clone)]
pub struct RecoveredMessage {
    pub session_id: Uuid,
    pub original_data: Vec<u8>,
    pub recovery_time: Instant,
    pub blocks_used: usize,
    pub blocks_total: usize,
}

/// 统计信息
#[derive(Debug, Default, Clone)]
pub struct ReassemblerStats {
    pub total_sessions: usize,
    pub successful_recoveries: usize,
    pub failed_recoveries: usize,
    pub pending_sessions: usize,
    pub average_recovery_time_ms: f64,
}

/// FEC重组器 - 主结构（组合模式）
pub struct FECReassembler {
    /// 会话管理器
    session_manager: SessionManager,
    
    /// 等待处理的消息队列
    pending_messages: VecDeque<RecoveredMessage>,
    
    /// FEC参数
    k: usize,
    m: usize,
}

/// 会话操作指令（避免借用冲突）
#[derive(Debug)]
enum SessionOperation {
    /// 无需操作
    NoOp,
    /// 需要解码
    DecodeRequired {
        session_id: Uuid,
        blocks: HashMap<u32, Vec<u8>>,
        received_count: usize,
        start_time: Instant,
        k: usize,
        m: usize,
    },
}

// ============ SessionManager 实现 ============

impl SessionManager {
    /// 创建新的会话管理器
    fn new(session_timeout: Duration) -> Self {
        Self {
            sessions: HashMap::new(),
            session_timeout,
            session_cleanup_timeout: Duration::from_secs(300), // 5分钟后清理已完成/失败的会话
            stats: ReassemblerStats::default(),
        }
    }
    
    /// 处理新帧（返回操作指令）
    fn process_new_frame(
        &mut self,
        session_id: Uuid,
        frame: &FecFrame,
    ) -> SessionOperation {
        match self.sessions.remove(&session_id) {
            // 会话已存在
            Some(state) => {
                let (new_state, operation) = self.handle_existing_session(session_id, state, frame);
                self.sessions.insert(session_id, new_state);
                operation
            }
            // 新会话
            None => self.handle_new_session(session_id, frame),
        }
    }
    
    /// 处理已存在的会话
    fn handle_existing_session(
        &mut self,
        session_id: Uuid,
        state: SessionState,
        frame: &FecFrame,
    ) -> (SessionState, SessionOperation) {
        match state {
            SessionState::Collecting { mut received_blocks, mut received_count, start_time } => {
                // 检查重复块
                if received_blocks.contains_key(&frame.block_index) {
                    debug!("FEC会话 {}: 收到重复块 {}", session_id, frame.block_index);
                    return (
                        SessionState::Collecting { 
                            received_blocks, 
                            received_count, 
                            start_time 
                        }, 
                        SessionOperation::NoOp
                    );
                }
                
                // 存储新块
                received_blocks.insert(frame.block_index, frame.payload.clone());
                received_count += 1;
                
                debug!(
                    "FEC会话 {}: 收到块 {} ({}/{})", 
                    session_id, 
                    frame.block_index, 
                    received_count, 
                    frame.k as usize
                );
                
                // 检查是否足够解码
                if received_count >= frame.k as usize {
                    debug!("FEC会话 {}: 收到足够块，需要解码", session_id);
                    
                    let blocks_copy = received_blocks.clone();
                    
                    (
                        SessionState::Decoding, // 新状态
                        SessionOperation::DecodeRequired {
                            session_id,
                            blocks: blocks_copy,
                            received_count,
                            start_time,
                            k: frame.k as usize,
                            m: frame.m as usize,
                        }
                    )
                } else {
                    (
                        SessionState::Collecting { 
                            received_blocks, 
                            received_count, 
                            start_time 
                        },
                        SessionOperation::NoOp
                    )
                }
            }
            
            SessionState::Completed { original_data, recovery_time } => {
                debug!(
                    "FEC会话 {}: 已完成会话收到块，数据已恢复: {}字节", 
                    session_id, 
                    original_data.len()
                );
                (
                    SessionState::Completed { 
                        original_data, 
                        recovery_time 
                    }, 
                    SessionOperation::NoOp
                )
            }
            
            SessionState::Failed { reason, failure_time } => {
                debug!(
                    "FEC会话 {}: 失败会话收到块，原因: {}", 
                    session_id, 
                    reason
                );
                (
                    SessionState::Failed { 
                        reason, 
                        failure_time 
                    }, 
                    SessionOperation::NoOp
                )
            }
            
            SessionState::Decoding => {
                debug!("FEC会话 {}: 正在解码中，忽略新块", session_id);
                (SessionState::Decoding, SessionOperation::NoOp)
            }
        }
    }
    
    /// 处理新会话
    fn handle_new_session(&mut self, session_id: Uuid, frame: &FecFrame) -> SessionOperation {
        debug!("FEC会话 {}: 开始新会话 (k={}, m={})", 
            session_id, frame.k, frame.m);
        
        // 初始化块集合
        let mut received_blocks = HashMap::new();
        received_blocks.insert(frame.block_index, frame.payload.clone());
        
        // 记录开始时间
        let start_time = Instant::now();
        
        // 插入新会话
        self.sessions.insert(
            session_id,
            SessionState::Collecting {
                received_blocks,
                received_count: 1,
                start_time,
            },
        );
        
        debug!("FEC会话 {}: 收到第一个块 {}", session_id, frame.block_index);
        
        self.stats.total_sessions += 1;
        self.stats.pending_sessions += 1;
        
        SessionOperation::NoOp
    }
    
    /// 更新会话状态为已完成
    fn mark_session_completed(
        &mut self,
        session_id: Uuid,
        original_data: Vec<u8>,
        recovery_time: Instant,
    ) {
        if let Some(state) = self.sessions.get_mut(&session_id) {
            *state = SessionState::Completed {
                original_data,
                recovery_time,
            };
            self.stats.successful_recoveries += 1;
            self.stats.pending_sessions -= 1;
        }
    }
    
    /// 更新会话状态为失败
    fn mark_session_failed(
        &mut self,
        session_id: Uuid,
        reason: String,
    ) {
        if let Some(state) = self.sessions.get_mut(&session_id) {
            *state = SessionState::Failed {
                reason,
                failure_time: Instant::now(),
            };
            self.stats.failed_recoveries += 1;
            self.stats.pending_sessions -= 1;
        }
    }
    
    /// 恢复会话为收集状态
    fn restore_to_collecting(
        &mut self,
        session_id: Uuid,
        blocks: HashMap<u32, Vec<u8>>,
        received_count: usize,
        start_time: Instant,
    ) {
        if let Some(state) = self.sessions.get_mut(&session_id) {
            *state = SessionState::Collecting {
                received_blocks: blocks,
                received_count,
                start_time,
            };
        }
    }
    
    /// 清理超时会话
    fn cleanup_timeout_sessions(&mut self) {
        let now = Instant::now();
        let mut to_remove = Vec::new();
        
        for (session_id, state) in &self.sessions {
            match state {
                SessionState::Collecting { start_time, .. } => {
                    if now.duration_since(*start_time) > self.session_timeout {
                        debug!("FEC会话 {}: 超时清理", session_id);
                        to_remove.push(*session_id);
                        self.stats.failed_recoveries += 1;
                        self.stats.pending_sessions -= 1;
                    }
                }
                SessionState::Failed { failure_time, .. } => {
                    if now.duration_since(*failure_time) > self.session_cleanup_timeout {
                        to_remove.push(*session_id);
                    }
                }
                SessionState::Completed { recovery_time, .. } => {
                    if now.duration_since(*recovery_time) > self.session_cleanup_timeout {
                        to_remove.push(*session_id);
                    }
                }
                _ => {}
            }
        }
        
        for session_id in to_remove {
            self.sessions.remove(&session_id);
        }
    }
    
    /// 获取统计信息
    fn get_stats(&self) -> &ReassemblerStats {
        &self.stats
    }
    
    /// 更新平均恢复时间
    fn update_average_recovery_time(&mut self, new_time_ms: f64) {
        let total_recoveries = self.stats.successful_recoveries as f64;
        if total_recoveries <= 1.0 {
            self.stats.average_recovery_time_ms = new_time_ms;
        } else {
            let alpha = 0.1; // 平滑因子
            self.stats.average_recovery_time_ms = 
                alpha * new_time_ms + (1.0 - alpha) * self.stats.average_recovery_time_ms;
        }
    }
}

// ============ FECReassembler 实现 ============

impl FECReassembler {
    /// 创建新的FEC重组器
    pub fn new(k: usize, m: usize) -> Self {
        Self {
            session_manager: SessionManager::new(Duration::from_secs(30)),
            pending_messages: VecDeque::new(),
            k,
            m,
        }
    }
    
    /// 处理接收到的FEC帧（主入口）
    pub fn process_fec_frame(&mut self, frame: &FecFrame) -> Result<Option<RecoveredMessage>, String> {
        let session_id = Uuid::from_slice(&frame.session_id)
            .map_err(|e| format!("无效的session_id: {}", e))?;
        
        // 步骤1：会话管理（收集块，检查状态）
        let operation = self.session_manager.process_new_frame(session_id, frame);
        
        // 步骤2：根据操作指令执行相应操作
        match operation {
            SessionOperation::NoOp => Ok(None),
            
            SessionOperation::DecodeRequired { 
                session_id, 
                blocks, 
                received_count, 
                start_time,
                k,
                m,
            } => {
                // 执行解码
                self.perform_decoding(
                    session_id, 
                    &blocks, 
                    received_count, 
                    start_time,
                    k,
                    m,
                    frame,
                )
            }
        }
    }
    
    /// 执行FEC解码
    fn perform_decoding(
        &mut self,
        session_id: Uuid,
        blocks: &HashMap<u32, Vec<u8>>,
        received_count: usize,
        start_time: Instant,
        k: usize,
        m: usize,
        frame: &FecFrame,
    ) -> Result<Option<RecoveredMessage>, String> {
        // 调用静态解码方法
        match Self::decode_fec_data(session_id, blocks, k, m) {
            Ok(original_data) => {
                // 解码成功
                let recovery_time = Instant::now();
                let recovery_duration = recovery_time.duration_since(start_time);
                
                // 更新统计
                self.session_manager.update_average_recovery_time(recovery_duration.as_millis() as f64);
                
                // 创建恢复的消息
                let message = RecoveredMessage {
                    session_id,
                    original_data: original_data.clone(),
                    recovery_time,
                    blocks_used: received_count,
                    blocks_total: (frame.k + frame.m) as usize,
                };
                
                // 更新会话状态
                self.session_manager.mark_session_completed(
                    session_id, 
                    original_data, 
                    recovery_time,
                );
                
                // 添加到待处理队列
                self.pending_messages.push_back(message.clone());
                
                debug!("FEC会话 {}: 成功恢复 {} 字节原始数据", 
                    session_id, message.original_data.len());
                
                Ok(Some(message))
            }
            Err(e) => {
                // 解码失败
                debug!("FEC会话 {}: 解码失败: {}", session_id, e);
                
                // 检查是否超时
                if Instant::now().duration_since(start_time) > self.session_manager.session_timeout {
                    // 超时失败
                    self.session_manager.mark_session_failed(
                        session_id, 
                        format!("超时: {}", e),
                    );
                    Err(format!("FEC会话 {} 解码超时: {}", session_id, e))
                } else {
                    // 未超时，恢复为收集状态
                    self.session_manager.restore_to_collecting(
                        session_id,
                        blocks.clone(),
                        received_count,
                        start_time,
                    );
                    Ok(None)
                }
            }
        }
    }
    
    /// 静态解码方法（无状态，避免借用冲突）
    fn decode_fec_data(
        session_id: Uuid,
        received_blocks: &HashMap<u32, Vec<u8>>,
        k: usize,
        m: usize,
    ) -> Result<Vec<u8>, String> {
        // 创建Reed-Solomon编解码器
        let rs = ReedSolomon::new(k, m)
            .map_err(|e| format!("创建ReedSolomon失败: {}", e))?;
        
        // 准备数据片
        let total_shards = k + m;
        let mut shards: Vec<Option<Vec<u8>>> = vec![None; total_shards];
        
        // 填充数据
        for (&index, data) in received_blocks {
            if (index as usize) < total_shards {
                shards[index as usize] = Some(data.clone());
            } else {
                return Err(format!("无效块索引: {}", index));
            }
        }
        
        // 检查数据量
        let total_received = shards.iter().filter(|s| s.is_some()).count();
        if total_received < k {
            return Err(format!("数据不足: {}/{}", total_received, k));
        }
        
        // 解码
        rs.reconstruct(&mut shards)
            .map_err(|e| format!("ReedSolomon恢复失败: {}", e))?;
        
        // 组合数据
        let mut original_data = Vec::new();
        for i in 0..k {
            if let Some(shard) = &shards[i] {
                original_data.extend_from_slice(shard);
            } else {
                return Err(format!("恢复后数据片{}缺失", i));
            }
        }
        
        if original_data.is_empty() {
            return Err("恢复的数据为空".to_string());
        }
        
        Ok(original_data)
    }
    
    /// 清理超时会话
    pub fn cleanup_timeout_sessions(&mut self) {
        self.session_manager.cleanup_timeout_sessions();
    }
    
    /// 获取统计信息
    pub fn get_stats(&self) -> &ReassemblerStats {
        self.session_manager.get_stats()
    }
    
    /// 从队列中获取下一个恢复的消息
    pub fn next_recovered_message(&mut self) -> Option<RecoveredMessage> {
        self.pending_messages.pop_front()
    }
    
    /// 获取待处理消息数量
    pub fn pending_message_count(&self) -> usize {
        self.pending_messages.len()
    }
    
    /// 设置会话超时时间
    pub fn set_session_timeout(&mut self, timeout: Duration) {
        self.session_manager.session_timeout = timeout;
    }
    
    /// 设置会话清理超时时间（完成后保留的时间）
    pub fn set_session_cleanup_timeout(&mut self, timeout: Duration) {
        self.session_manager.session_cleanup_timeout = timeout;
    }
}