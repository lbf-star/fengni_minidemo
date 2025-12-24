use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{Instant, Duration};

/// 流状态
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamState {
    Free,           // 空闲，可用
    HighPriority,   // 高优先级在用（可抢占低优先级）
    LowPriority,    // 低优先级在用（可被抢占）
    Closing,        // 正在关闭
}

/// 流池：管理单个连接的QUIC流资源
pub struct StreamPool {
    /// 所有流的状态
    stream_states: HashMap<u64, StreamState>,
    
    /// 空闲流队列（快速获取）
    free_streams: VecDeque<u64>,
    
    /// 高优先级在用流
    high_priority_streams: HashSet<u64>,
    
    /// 低优先级在用流
    low_priority_streams: HashSet<u64>,
    
    /// 流创建计数器
    next_stream_id: u64,
    
    /// 每个连接的最大流数
    max_streams: usize,
    
    /// 流空闲超时时间
    idle_timeout: Duration,
    
    /// 上次活动时间记录
    last_activity: HashMap<u64, Instant>,
}

impl StreamPool {
    /// 创建新的流池
    pub fn new(max_streams: usize) -> Self {
        Self {
            stream_states: HashMap::new(),
            free_streams: VecDeque::new(),
            high_priority_streams: HashSet::new(),
            low_priority_streams: HashSet::new(),
            next_stream_id: 0,
            max_streams,
            idle_timeout: Duration::from_secs(30),
            last_activity: HashMap::new(),
        }
    }
    
    /// 获取一个流用于发送数据
    /// - is_high_priority: 是否为高优先级数据
    /// - 返回: Some(stream_id) 或 None（如果达到限制且无法抢占）
    pub fn acquire_stream(&mut self, is_high_priority: bool) -> Option<u64> {
        // 1. 优先使用空闲流
        if let Some(stream_id) = self.free_streams.pop_front() {
            self.mark_stream_used(stream_id, is_high_priority);
            self.update_activity(stream_id);
            return Some(stream_id);
        }
        
        // 2. 如果还有配额，创建新流
        if self.stream_states.len() < self.max_streams {
            let stream_id = self.next_stream_id;
            self.next_stream_id += 4;
            self.stream_states.insert(stream_id, StreamState::Free);
            self.mark_stream_used(stream_id, is_high_priority);
            self.update_activity(stream_id);
            return Some(stream_id);
        }
        
        // 3. 高优先级数据可抢占低优先级流
        if is_high_priority && !self.low_priority_streams.is_empty() {
            // 抢占最近最少使用的低优先级流
            let stream_id = self.find_stream_to_preempt();
            if let Some(stream_id) = stream_id {
                self.preempt_stream(stream_id);
                self.update_activity(stream_id);
                return Some(stream_id);
            }
        }
        
        // 4. 无法获取流
        None
    }
    
    /// 释放流（数据发送完成）
    pub fn release_stream(&mut self, stream_id: u64) {
        if let Some(state) = self.stream_states.get_mut(&stream_id) {
            match *state {
                StreamState::HighPriority => {
                    self.high_priority_streams.remove(&stream_id);
                }
                StreamState::LowPriority => {
                    self.low_priority_streams.remove(&stream_id);
                }
                _ => return,
            }
            
            *state = StreamState::Free;
            self.free_streams.push_back(stream_id);
            self.update_activity(stream_id);
        }
    }
    
    /// 关闭流（永久移除）
    pub fn close_stream(&mut self, stream_id: u64) {
        self.stream_states.remove(&stream_id);
        self.free_streams.retain(|&id| id != stream_id);
        self.high_priority_streams.remove(&stream_id);
        self.low_priority_streams.remove(&stream_id);
        self.last_activity.remove(&stream_id);
    }
    
    /// 清理空闲超时的流
    pub fn cleanup_idle_streams(&mut self) {
        let now = Instant::now();
        let mut to_remove = Vec::new();
        
        for (&stream_id, &last_active) in &self.last_activity {
            if now.duration_since(last_active) > self.idle_timeout {
                if let Some(state) = self.stream_states.get(&stream_id) {
                    if *state == StreamState::Free {
                        to_remove.push(stream_id);
                    }
                }
            }
        }
        
        for stream_id in to_remove {
            self.close_stream(stream_id);
        }
    }
    
    /// 获取统计信息
    pub fn stats(&self) -> PoolStats {
        PoolStats {
            total_streams: self.stream_states.len(),
            free_streams: self.free_streams.len(),
            high_priority_streams: self.high_priority_streams.len(),
            low_priority_streams: self.low_priority_streams.len(),
            max_streams: self.max_streams,
        }
    }
    
    // === 私有方法 ===
    
    fn mark_stream_used(&mut self, stream_id: u64, is_high_priority: bool) {
        let state = if is_high_priority {
            StreamState::HighPriority
        } else {
            StreamState::LowPriority
        };
        
        self.stream_states.insert(stream_id, state);
        
        if is_high_priority {
            self.high_priority_streams.insert(stream_id);
        } else {
            self.low_priority_streams.insert(stream_id);
        }
    }
    
    fn find_stream_to_preempt(&self) -> Option<u64> {
        // 简单的LRU策略：找最久未活动的低优先级流
        self.low_priority_streams.iter()
            .min_by_key(|&&id| self.last_activity.get(&id).copied())
            .copied()
    }
    
    fn preempt_stream(&mut self, stream_id: u64) {
        // 标记流为高优先级
        self.stream_states.insert(stream_id, StreamState::HighPriority);
        self.low_priority_streams.remove(&stream_id);
        self.high_priority_streams.insert(stream_id);
        
        // TODO: 通知应用层数据被抢占，需要重新排队
    }
    
    fn update_activity(&mut self, stream_id: u64) {
        self.last_activity.insert(stream_id, Instant::now());
    }
}

/// 流池统计信息
#[derive(Debug, Clone)]
pub struct PoolStats {
    pub total_streams: usize,
    pub free_streams: usize,
    pub high_priority_streams: usize,
    pub low_priority_streams: usize,
    pub max_streams: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_stream_pool_basic() {
        let mut pool = StreamPool::new(10);
        
        // 获取流
        let stream1 = pool.acquire_stream(true).unwrap();
        let stream2 = pool.acquire_stream(false).unwrap();
        
        assert_ne!(stream1, stream2);
        
        // 验证状态
        assert_eq!(pool.stats().total_streams, 2);
        assert_eq!(pool.stats().free_streams, 0);
        assert_eq!(pool.stats().high_priority_streams, 1);
        assert_eq!(pool.stats().low_priority_streams, 1);
        
        // 释放流
        pool.release_stream(stream1);
        assert_eq!(pool.stats().free_streams, 1);
        
        // 再次获取应该得到空闲流
        let stream3 = pool.acquire_stream(false).unwrap();
        assert_eq!(stream3, stream1); // 应该是刚才释放的流
        
        println!("流池基础测试通过");
    }
    
    #[test]
    fn test_stream_preemption() {
        let mut pool = StreamPool::new(2); // 限制2个流
        
        // 占用两个低优先级流
        let low1 = pool.acquire_stream(false).unwrap();
        let low2 = pool.acquire_stream(false).unwrap();
        
        // 尝试获取高优先级流（应该触发抢占）
        let high = pool.acquire_stream(true);
        assert!(high.is_some());
        
        // 应该有一个低优先级流被抢占
        assert_eq!(pool.stats().low_priority_streams, 1);
        assert_eq!(pool.stats().high_priority_streams, 1);
        
        println!("流抢占测试通过");
    }
}