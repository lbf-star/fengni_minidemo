use std::collections::{HashMap, VecDeque};
use std::time::{Instant, Duration};
use uuid::Uuid;
use crate::whisper::{FecFrame, FecWhisper, Priority};
use crate::stream::pool::{StreamPool, PoolStats};

/// 等待发送的FEC任务
pub struct FECTask {
    pub frames: Vec<FecFrame>,
    pub session_id: Uuid,
    pub priority: Priority,
    pub enqueue_time: Instant,
}

/// 流调度器：管理FEC任务的发送和流分配
pub struct StreamScheduler {
    /// 流池
    pool: StreamPool,
    
    /// 等待队列：按优先级分组
    pending_tasks: HashMap<Priority, VecDeque<FECTask>>,
    
    /// 进行中的FEC会话
    active_sessions: HashMap<Uuid, ActiveSession>,
    
    /// 防饥饿计数器
    starvation_counter: HashMap<Priority, usize>,
    
    /// 最大等待时间（防饥饿）
    max_wait_time: Duration,
    
    /// 最后优先级提升时间
    last_priority_boost: Instant,
}

/// 活跃的FEC会话状态
struct ActiveSession {
    /// 已发送的帧数
    sent_frames: usize,
    
    /// 需要发送的总帧数
    total_frames: usize,
    
    /// 使用的流ID
    assigned_streams: Vec<u64>,
    
    /// 开始时间
    start_time: Instant,
}

impl StreamScheduler {
    /// 创建新的调度器
    pub fn new(max_streams_per_connection: usize) -> Self {
        Self {
            pool: StreamPool::new(max_streams_per_connection),
            pending_tasks: {
                let mut map = HashMap::new();
                // 初始化所有优先级队列
                for prio in [Priority::Low, Priority::Normal, Priority::High, Priority::Urgent] {
                    map.insert(prio, VecDeque::new());
                }
                map
            },
            active_sessions: HashMap::new(),
            starvation_counter: HashMap::new(),
            max_wait_time: Duration::from_secs(10),
            last_priority_boost: Instant::now(),
        }
    }
    
    /// 提交FEC任务等待发送
    pub fn submit_fec_task(&mut self, frames: Vec<FecFrame>, session_id: Uuid, priority: Priority) {
        let task = FECTask {
            frames,
            session_id,
            priority,
            enqueue_time: Instant::now(),
        };
        
        self.pending_tasks
            .entry(priority)
            .or_insert_with(VecDeque::new)
            .push_back(task);
    }
    
    /// 尝试发送数据：返回可发送的（流ID, FEC帧）对
    pub fn try_send(&mut self) -> Vec<(u64, FecFrame)> {
    let mut result = Vec::new();
    
    // 定期检查防饥饿
    self.check_starvation();
    
    // 按优先级顺序处理
    let priorities = [
        Priority::Urgent,
        Priority::High, 
        Priority::Normal,
        Priority::Low,
    ];
    
    for &priority in &priorities {
        // 获取这个优先级的待处理任务列表
        let tasks_to_process: Vec<FECTask> = {
            if let Some(queue) = self.pending_tasks.get_mut(&priority) {
                queue.drain(..).collect()
            } else {
                continue;
            }
        };
        
        // 处理每个任务
        let mut remaining_tasks = Vec::new();
        
        for mut task in tasks_to_process {
            // 检查等待时间
            if task.enqueue_time.elapsed() > self.max_wait_time {
                // 提升优先级
                self.resubmit_with_higher_priority(task);
                continue;
            }
            
            let frames_copy = task.frames.clone();
            let total_frames = frames_copy.len();
            let mut frames_to_send = Vec::new();
            let mut streams_assigned = Vec::new();
            let mut sent_count = 0;
            
            // 尝试发送每个帧
            for frame in frames_copy {
                if let Some(stream_id) = self.pool.acquire_stream(is_high_priority(priority)) {
                    frames_to_send.push((stream_id, frame));
                    streams_assigned.push(stream_id);
                    sent_count += 1;
                } else {
                    break;
                }
            }
            
            if sent_count > 0 {
                // 记录活跃会话
                self.active_sessions.insert(task.session_id, ActiveSession {
                    sent_frames: sent_count,
                    total_frames,
                    assigned_streams: streams_assigned,
                    start_time: Instant::now(),
                });
                
                // 添加到结果
                result.extend(frames_to_send);
                
                if sent_count < total_frames {
                    // 部分发送，保留剩余帧
                    task.frames.drain(0..sent_count);
                    remaining_tasks.push(task);
                }
                // 全部发送完成，不保留
            } else {
                // 无法发送，保留原任务
                remaining_tasks.push(task);
            }
        }
        
        // 将剩余任务放回队列
        if let Some(queue) = self.pending_tasks.get_mut(&priority) {
            for task in remaining_tasks {
                queue.push_back(task);
            }
        }
    }
    
    // 清理空闲流
    self.pool.cleanup_idle_streams();
    
    result
}
    
    /// 标记帧发送完成，释放流
    pub fn mark_frame_sent(&mut self, stream_id: u64) {
        self.pool.release_stream(stream_id);
    }
    
    /// 标记整个FEC会话完成
    pub fn mark_session_complete(&mut self, session_id: Uuid) {
        if let Some(session) = self.active_sessions.remove(&session_id) {
            for stream_id in session.assigned_streams {
                self.pool.release_stream(stream_id);
            }
        }
    }
    
    /// 获取调度器统计信息
    pub fn stats(&self) -> SchedulerStats {
        let pool_stats = self.pool.stats();
        
        let pending_counts: HashMap<Priority, usize> = self.pending_tasks
            .iter()
            .map(|(&prio, queue)| (prio, queue.len()))
            .collect();
        
        SchedulerStats {
            pool_stats,
            pending_counts,
            active_sessions: self.active_sessions.len(),
        }
    }
    
    // === 私有方法 ===
    
    fn check_starvation(&mut self) {
        let now = Instant::now();
        
        // 每5秒检查一次
        if now.duration_since(self.last_priority_boost) < Duration::from_secs(5) {
            return;
        }
        
        // 检查低优先级任务是否等待太久
        for priority in [Priority::Low, Priority::Normal] {
            if let Some(queue) = self.pending_tasks.get(&priority) {
                if let Some(front_task) = queue.front() {
                    if front_task.enqueue_time.elapsed() > self.max_wait_time {
                        // 提升优先级（Low -> Normal, Normal -> High）
                        let new_priority = match priority {
                            Priority::Low => Priority::Normal,
                            Priority::Normal => Priority::High,
                            _ => continue,
                        };
                        
                        // 重新提交为更高优先级
                        if let Some(mut queue) = self.pending_tasks.remove(&priority) {
                            while let Some(mut task) = queue.pop_front() {
                                task.priority = new_priority;
                                self.pending_tasks
                                    .entry(new_priority)
                                    .or_insert_with(VecDeque::new)
                                    .push_back(task);
                            }
                        }
                    }
                }
            }
        }
        
        self.last_priority_boost = now;
    }
    
    fn resubmit_with_higher_priority(&mut self, mut task: FECTask) {
        // 提升优先级（但不超过High）
        if task.priority < Priority::High {
            let new_priority = match task.priority {
                Priority::Low => Priority::Normal,
                Priority::Normal => Priority::High,
                _ => task.priority,
            };
            
            task.priority = new_priority;
        }
        
        task.enqueue_time = Instant::now(); // 重置等待时间
        
        self.pending_tasks
            .entry(task.priority)
            .or_insert_with(VecDeque::new)
            .push_front(task); // 放回队列前面
    }
}

/// 调度器统计信息
#[derive(Debug)]
pub struct SchedulerStats {
    pub pool_stats: PoolStats,
    pub pending_counts: HashMap<Priority, usize>,
    pub active_sessions: usize,
}

/// 判断优先级是否为高优先级
fn is_high_priority(priority: Priority) -> bool {
    matches!(priority, Priority::High | Priority::Urgent)
}