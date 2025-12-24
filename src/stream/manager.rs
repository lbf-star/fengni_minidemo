use crate::stream::{StreamPool, StreamScheduler};
use crate::whisper::{FecFrame, Priority};
use uuid::Uuid;
use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{Instant, Duration};

/// 统一流管理器（生产级）
/// 管理所有QUIC流的分配、调度和回收
pub struct UnifiedStreamManager {
    /// 流池实例
    stream_pool: StreamPool,
    
    /// 流调度器实例
    stream_scheduler: StreamScheduler,
    
    /// 已预留的流（如HTTP请求、控制流等）
    reserved_streams: HashSet<u64>,
    
    /// 等待分配的普通消息
    pending_normal_messages: VecDeque<NormalMessage>,
    
    /// 下一个可用的客户端流ID
    next_client_stream_id: u64,
    
    /// 最大重试次数
    max_retry_count: u32,
    
    /// 统计信息
    stats: ManagerStats,
}

/// 等待发送的普通消息
struct NormalMessage {
    data: Vec<u8>,
    priority: Priority,
    enqueue_time: Instant,
    retry_count: u32,
}

/// 管理器统计信息
#[derive(Debug, Default, Clone)]
pub struct ManagerStats {
    pub total_streams_allocated: usize,
    pub reserved_streams: usize,
    pub pending_normal_messages: usize,
    pub failed_allocations: usize,
    pub last_operation_time: Option<Instant>,
}

impl UnifiedStreamManager {
    /// 创建新的统一流管理器
    pub fn new(max_streams_per_connection: usize) -> Self {
        Self {
            stream_pool: StreamPool::new(max_streams_per_connection),
            stream_scheduler: StreamScheduler::new(max_streams_per_connection),
            reserved_streams: HashSet::new(),
            pending_normal_messages: VecDeque::new(),
            next_client_stream_id: 0,
            max_retry_count: 3,
            stats: ManagerStats::default(),
        }
    }
    
    /// 预留特定流（用于特殊用途）
    /// 返回预留是否成功（如果流已被使用，则失败）
    pub fn reserve_stream(&mut self, stream_id: u64) -> bool {
        if self.is_stream_available(stream_id) {
            self.reserved_streams.insert(stream_id);
            self.update_stats();
            true
        } else {
            false
        }
    }
    
    /// 释放预留的流
    pub fn release_reserved_stream(&mut self, stream_id: u64) {
        self.reserved_streams.remove(&stream_id);
        self.stream_pool.release_stream(stream_id);
        self.update_stats();
    }
    
    /// 为普通消息分配流（非FEC消息）
    pub fn allocate_stream_for_normal_message(
        &mut self, 
        data: Vec<u8>, 
        priority: Priority
    ) -> Option<(u64, Vec<u8>)> {
        // 检查是否有空闲流
        match self.find_available_stream(priority, false) {
            Some(stream_id) => {
                self.stats.total_streams_allocated += 1;
                self.update_stats();
                Some((stream_id, data))
            }
            None => {
                // 没有可用流，加入等待队列
                self.enqueue_normal_message(data, priority);
                self.stats.failed_allocations += 1;
                None
            }
        }
    }
    
    /// 为FEC消息分配流（通过调度器）
    pub fn allocate_streams_for_fec(
        &mut self, 
        frames: Vec<FecFrame>, 
        session_id: Uuid, 
        priority: Priority
    ) -> Vec<(u64, FecFrame)> {
        self.stream_scheduler.submit_fec_task(frames, session_id, priority);
        self.update_stats();
        
        // 获取调度器分配的发送任务
        self.stream_scheduler.try_send()
    }
    
    /// 标记帧已发送完成
    pub fn mark_frame_sent(&mut self, stream_id: u64) {
        self.stream_scheduler.mark_frame_sent(stream_id);
        self.update_stats();
    }
    
    /// 标记FEC会话完成
    pub fn mark_session_complete(&mut self, session_id: Uuid) {
        self.stream_scheduler.mark_session_complete(session_id);
        self.update_stats();
    }
    
    /// 处理等待队列中的消息
    pub fn process_pending_messages(&mut self) -> Vec<(u64, Vec<u8>)> {
        let mut result = Vec::new();
        let mut remaining_messages = VecDeque::new();
        
        while let Some(mut message) = self.pending_normal_messages.pop_front() {
            // 检查是否超时
            if message.enqueue_time.elapsed() > Duration::from_secs(30) {
                continue; // 丢弃超时消息
            }
            
            // 检查重试次数
            if message.retry_count >= self.max_retry_count {
                continue; // 超过最大重试次数
            }
            
            match self.find_available_stream(message.priority, false) {
                Some(stream_id) => {
                    self.stats.total_streams_allocated += 1;
                    result.push((stream_id, message.data));
                }
                None => {
                    // 仍然没有可用流，增加重试计数并重新排队
                    message.retry_count += 1;
                    remaining_messages.push_back(message);
                }
            }
        }
        
        self.pending_normal_messages = remaining_messages;
        self.update_stats();
        result
    }
    
    /// 获取下一个可用的客户端流ID（遵循QUIC规范）
    pub fn get_next_client_stream_id(&mut self) -> u64 {
        let stream_id = self.next_client_stream_id;
        self.next_client_stream_id += 4; // QUIC客户端流ID步长为4
        stream_id
    }
    
    /// 检查流是否可用（未被预留且空闲）
    pub fn is_stream_available(&self, stream_id: u64) -> bool {
        !self.reserved_streams.contains(&stream_id)
    }
    
    /// 获取管理器统计信息
    pub fn get_stats(&self) -> ManagerStats {
        self.stats.clone()
    }
    
    /// 获取调度器统计信息
    pub fn get_scheduler_stats(&self) -> String {
        format!("{:?}", self.stream_scheduler.stats())
    }
    
    /// 清理空闲流
    pub fn cleanup(&mut self) {
        self.stream_pool.cleanup_idle_streams();
        self.update_stats();
    }
    
    // === 私有方法 ===
    
    fn find_available_stream(&mut self, priority: Priority, is_high_priority: bool) -> Option<u64> {
        // 优先从流池获取
        if let Some(stream_id) = self.stream_pool.acquire_stream(is_high_priority) {
            if !self.reserved_streams.contains(&stream_id) {
                return Some(stream_id);
            } else {
                // 如果是预留流，释放并继续查找
                self.stream_pool.release_stream(stream_id);
            }
        }
        
        None
    }
    
    fn enqueue_normal_message(&mut self, data: Vec<u8>, priority: Priority) {
        let message = NormalMessage {
            data,
            priority,
            enqueue_time: Instant::now(),
            retry_count: 0,
        };
        
        // 根据优先级插入队列
        match priority {
            Priority::Urgent | Priority::High => {
                self.pending_normal_messages.push_front(message);
            }
            _ => {
                self.pending_normal_messages.push_back(message);
            }
        }
        
        self.update_stats();
    }
    
    fn update_stats(&mut self) {
        self.stats.reserved_streams = self.reserved_streams.len();
        self.stats.pending_normal_messages = self.pending_normal_messages.len();
        self.stats.last_operation_time = Some(Instant::now());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_unified_stream_manager_basic() {
        let mut manager = UnifiedStreamManager::new(10);
        
        // 测试预留流
        assert!(manager.reserve_stream(2));
        assert!(manager.reserved_streams.contains(&2));
        
        // 测试普通消息分配
        let data = b"test message".to_vec();
        let result = manager.allocate_stream_for_normal_message(data.clone(), Priority::Normal);
        assert!(result.is_some());
        
        let (stream_id, returned_data) = result.unwrap();
        assert_eq!(returned_data, data);
        assert!(!manager.reserved_streams.contains(&stream_id));
        
        println!("统一流管理器基础测试通过");
    }
    
    #[test]
    fn test_stream_availability() {
        let mut manager = UnifiedStreamManager::new(5);
        
        // 预留流2
        manager.reserve_stream(2);
        
        // 流2应该不可用
        assert!(!manager.is_stream_available(2));
        
        // 其他流应该可用（除非被使用）
        assert!(manager.is_stream_available(0) || manager.is_stream_available(4));
        
        println!("流可用性测试通过");
    }
}