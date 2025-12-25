use tracing::{info, error, warn, debug};
use silent_speaker::logging::init;

use ring::rand::*;

use prost::Message;
use silent_speaker::whisper::{Whisper, Priority};
use silent_speaker::whisper::whisper::Payload;
use silent_speaker::critical_sender::CriticalSender;
use silent_speaker::dynamic_framing::{SaltGenerator, build_dynamic_frame, DynamicStreamParser, SilentConfig};
use silent_speaker::framing::FramingError; // Keep for error handling if needed, or remove if unused
use silent_speaker::stream::UnifiedStreamManager;
use silent_speaker::fec::FECEncoder;
use silent_speaker::whisper::{FecWhisper, FecFrame};

use std::collections::{HashMap, VecDeque, HashSet};

const MAX_DATAGRAM_SIZE: usize = 1350;
use silent_speaker::SESSION_BASE_SEED; // From lib.rs

fn main() {
    // 日志系统初始化
    init();
    
    // 新增：创建FEC发送器和统一流管理器
    let mut critical_sender = CriticalSender::new(4, 2, 100)
      .expect("FEC发送器初始化失败");
    critical_sender.register_connection(0);  // 客户端只有一个连接，ID为0
    
    // 新增：统一流管理器（客户端单例）
    // use silent_speaker::stream::UnifiedStreamManager; // This import is now at the top
    // let mut stream_manager = UnifiedStreamManager::new(100); // This initialization is replaced below

    // Dynamic Framing    // 动态分帧状态
    let mut stream_generators: HashMap<u64, SaltGenerator> = HashMap::new();
    let mut stream_parsers: HashMap<u64, DynamicStreamParser> = HashMap::new(); // For receiving ACKs

    // Phase 4: 统一流管理器和FEC编码器
    let mut stream_manager = UnifiedStreamManager::new(100); // Max 100 streams
    let mut fec_encoder = FECEncoder::new(4, 2).expect("FEC编码器初始化失败"); // 4 data + 2 parity
    
    // Phase 5 Config
    let silent_config = SilentConfig::default(); // Robust Mode enabled by default
    
    // 注册预留流 (0 used for handshake/control potentially?)
    stream_manager.reserve_stream(0);

    let mut buf = [0; 65535];
    let mut out = [0; MAX_DATAGRAM_SIZE];

    let mut args = std::env::args();

    let cmd = &args.next().unwrap();

    if args.len() != 1 {
        println!("用法: {cmd} URL");
        println!("\n更完整的实现请参见工具/应用。");
        return;
    }

    let url = url::Url::parse(&args.next().unwrap()).unwrap();

    // Setup the event loop.
    let mut poll = mio::Poll::new().unwrap();
    let mut events = mio::Events::with_capacity(1024);

    // Resolve server address.
    let peer_addr = url.socket_addrs(|| None).unwrap()[0];

    // Bind to INADDR_ANY or IN6ADDR_ANY depending on the IP family of the
    // server address. This is needed on macOS and BSD variants that don't
    // support binding to IN6ADDR_ANY for both v4 and v6.
    let bind_addr = match peer_addr {
        std::net::SocketAddr::V4(_) => "0.0.0.0:0",
        std::net::SocketAddr::V6(_) => "[::]:0",
    };

    // Create the UDP socket backing the QUIC connection, and register it with
    // the event loop.
    let mut socket =
        mio::net::UdpSocket::bind(bind_addr.parse().unwrap()).unwrap();
    poll.registry()
        .register(&mut socket, mio::Token(0), mio::Interest::READABLE)
        .unwrap();

    // Create the configuration for the QUIC connection.
    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();

    // *CAUTION*: this should not be set to `false' in production!!!
    config.verify_peer(false);

    config
    .set_application_protos(&[b"silent-speaker-v1"])
    .unwrap();

    config.set_max_idle_timeout(5000);
    config.set_max_recv_udp_payload_size(MAX_DATAGRAM_SIZE);
    config.set_max_send_udp_payload_size(MAX_DATAGRAM_SIZE);
    config.set_initial_max_data(10_000_000);
    config.set_initial_max_stream_data_bidi_local(1_000_000);
    config.set_initial_max_stream_data_bidi_remote(1_000_000);
    config.set_initial_max_streams_bidi(100);
    config.set_initial_max_streams_uni(100);
    config.set_disable_active_migration(true);

    // Generate a random source connection ID for the connection.
    let mut scid = [0; quiche::MAX_CONN_ID_LEN];
    SystemRandom::new().fill(&mut scid[..]).unwrap();

    let scid = quiche::ConnectionId::from_ref(&scid);

    // Get local address.
    let local_addr = socket.local_addr().unwrap();

    // Create a QUIC connection and initiate handshake.
    let mut conn =
        quiche::connect(url.domain(), &scid, local_addr, peer_addr, &mut config)
            .unwrap();

    info!(
        "连接到 {:} 从 {:} 使用scid {}",
        peer_addr,
        socket.local_addr().unwrap(),
        hex_dump(&scid)
    );

    let (write, send_info) = conn.send(&mut out).expect("initial send failed");

    while let Err(e) = socket.send_to(&out[..write], send_info.to) {
        if e.kind() == std::io::ErrorKind::WouldBlock {
            tracing::trace!("发送操作将阻塞");
            continue;
        }

        panic!("发送操作失败: {e:?}");
    }

    debug!("被写入 {write}");

    let req_start = std::time::Instant::now();
    let mut req_sent = false;

    loop {
        poll.poll(&mut events, conn.timeout()).unwrap();

        // Read incoming UDP packets from the socket and feed them to quiche,
        // until there are no more packets to read.
        'read: loop {
            // If the event loop reported no events, it means that the timeout
            // has expired, so handle it without attempting to read packets. We
            // will then proceed with the send loop.
            if events.is_empty() {
                debug!("等待超时");

                conn.on_timeout();
                break 'read;
            }

            let (len, from) = match socket.recv_from(&mut buf) {
                Ok(v) => v,

                Err(e) => {
                    // There are no more UDP packets to read, so end the read
                    // loop.
                    if e.kind() == std::io::ErrorKind::WouldBlock {
                        tracing::trace!("接受操作将阻塞");
                        break 'read;
                    }

                    panic!("接受操作失败: {e:?}");
                },
            };

            tracing::trace!("获得 {len} 字节");

            let recv_info = quiche::RecvInfo {
                to: socket.local_addr().unwrap(),
                from,
            };

            // Process potentially coalesced packets.
            let read = match conn.recv(&mut buf[..len], recv_info) {
                Ok(v) => v,

                Err(e) => {
                    error!("接受操作失败: {e:?}");
                    continue 'read;
                },
            };

            tracing::trace!("已处理 {read} 字节");
        }

        tracing::trace!("读取完成");

        if conn.is_closed() {
            info!("连接已关闭, {:?}", conn.stats());
            break;
        }

        if conn.is_established() && !req_sent {
            info!("正在发送消息 {}", url.path());

    // ============ 修改开始：使用统一流管理器发送普通消息 ============
    let mut whisper = Whisper::default();
    whisper.id = uuid::Uuid::new_v4().as_bytes().to_vec();
    whisper.payload = Some(Payload::Content("测试普通消息(动态帧+调度)".to_string()));
    whisper.timestamp_ns = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;
    whisper.priority = Priority::Normal as i32;

    let whisper_bytes = whisper.encode_to_vec();

    // 1. 分配流
    if let Some((stream_id, data_to_send)) = stream_manager.allocate_stream_for_normal_message(whisper_bytes, Priority::Normal) {
        // 2. 获取生成器
        let generator = stream_generators.entry(stream_id).or_insert_with(|| {
            SaltGenerator::new_diversified(SESSION_BASE_SEED, stream_id)
        });

        // 3. 构建动态帧
        match build_dynamic_frame(generator, &data_to_send, silent_config) {
            Ok(framed_data) => {
                // 4. 发送
                match conn.stream_send(stream_id, &framed_data, true) {
                    Ok(_) => {
                        info!("普通消息已发送 (流ID: {})", stream_id);
                        stream_manager.mark_frame_sent(stream_id); // 立即标记因为stream_send是非阻塞的writer
                        // 注意：实际上stream_send只是写入buffer，不代表ACK。
                        // Scheduler的mark_frame_sent通常意味着"流已由该帧占用完成"。
                        // 对于StreamPool，release_stream应该在确认收到或者流关闭时调用？
                        // quiche中 fin=true 会关闭流的写端。
                        // 需要等待 fin ack 吗？ StreamPool用于限制并发流数量。
                        // 简单起见，我们在发送后释放，或者等待 receiving ack?
                        // StreamManager logic calls release_stream in mark_frame_sent.
                    },
                    Err(e) => error!("发送失败: {:?}", e),
                }
            },
            Err(e) => error!("分帧失败: {}", e),
        }
    } else {
        warn!("无法分配流发送普通消息 (可能是流耗尽)");
    }
    // ============ 修改结束 ============
    
    // 新增：发送关键信令（FEC保护）- 使用分帧版本
    match send_critical_message_integrated(&mut conn, &mut fec_encoder, &mut stream_manager, &mut stream_generators, "这是一条关键信令(动态帧)！") {
        Ok(_) => info!("关键信令发送成功"),
        Err(e) => error!("关键信令发送失败: {}", e),
    }

        req_sent = true;
    }

        // Process all readable streams.
        for s in conn.readable() {
            while let Ok((read, fin)) = conn.stream_recv(s, &mut buf) {
                debug!("已接收 {read} 字节");

                let stream_buf = &buf[..read];

                debug!(
                    "流 {} 有 {} 字节 (结束fin? {})",
                    s,
                    stream_buf.len(),
                    fin
                );

                // ============ 修改开始：尝试解析分帧消息（ACK） ============
                // 获取解析器
                let parser = stream_parsers.entry(s).or_insert_with(|| {
                     let generator = SaltGenerator::new_diversified(SESSION_BASE_SEED, s);
                     DynamicStreamParser::new(generator)
                });
                
                if let Err(e) = parser.append_data(stream_buf) {
                     error!("ACK解析Buffer溢出/错误: {}", e);
                     continue;
                }
                
                loop {
                    match parser.try_parse_next(silent_config) {
                         Ok(Some(payload)) => {
                             // ACK 应该是 Whisper 消息
                             if let Ok(whisper) = Whisper::decode(&payload[..]) {
                                 match whisper.payload {
                                     Some(Payload::Content(txt)) => info!("收到服务端ACK: {}", txt),
                                     _ => info!("收到服务端非文本ACK"),
                                 }
                             } else {
                                 warn!("收到无法解析的Protobuf ACK");
                             }
                         },
                         Ok(None) => break, // Need more data
                         Err(e) => {
                             error!("ACK动态帧解析失败: {}", e);
                             break;
                         }
                    }
                }
                // ============ 修改结束 ============

                // 服务器报告没有更多数据发送，我们已收到完整响应。关闭连接。
                if fin {
                    info!(
                        "接受的响应位于{:?}, 正在关闭...",
                        req_start.elapsed()
                    );

                    conn.close(true, 0x00, b"kthxbye").unwrap();
                }
            }
        }

        // Generate outgoing QUIC packets and send them on the UDP socket, until
        // quiche reports that there are no more packets to be sent.
        loop {
            let (write, send_info) = match conn.send(&mut out) {
                Ok(v) => v,

                Err(quiche::Error::Done) => {
                    tracing::trace!("写入完成");
                    break;
                },

                Err(e) => {
                    error!("发送操作失败: {e:?}");

                    conn.close(false, 0x1, b"fail").ok();
                    break;
                },
            };

            while let Err(e) = socket.send_to(&out[..write], send_info.to) {
                if e.kind() == std::io::ErrorKind::WouldBlock {
                    tracing::trace!("发送操作将阻塞");
                    break;
                }

                panic!("发送操作失败: {e:?}");
            }

            tracing::trace!("已写入 {write}");
        }

        if conn.is_closed() {
            info!("连接已关闭, {:?}", conn.stats());
            break;
        }
    }
}

// Integrated Critical Message Sending
fn send_critical_message_integrated(
    conn: &mut quiche::Connection,
    encoder: &mut FECEncoder,
    manager: &mut UnifiedStreamManager,
    generators: &mut HashMap<u64, SaltGenerator>,
    message: &str,
) -> Result<(), String> {
    
    // 1. Encode Content
    let (frames, session_id) = encoder.encode(message.as_bytes())
        .map_err(|e| format!("FEC Encoding Error: {:?}", e))?;
        
    info!("关键信令FEC编码完成: 会话ID={}, 帧数={}", session_id, frames.len());
    
    // 2. Scheduler Allocation
    // Allocate streams for all frames
    let allocated = manager.allocate_streams_for_fec(frames, session_id, Priority::Urgent);
    
    if allocated.is_empty() {
        return Err("Scheduler failed to allocate streams".to_string());
    }
    
    // 3. Send Each Frame
    for (stream_id, frame) in allocated {
        // Wrap in Whisper -> FecWhisper
        let fec_whisper = FecWhisper {
            fec_frame: Some(frame),
        };
        let whisper = Whisper {
            id: uuid::Uuid::new_v4().as_bytes().to_vec(),
            timestamp_ns: 0,
            priority: Priority::Urgent as i32,
            payload: Some(Payload::FecPayload(fec_whisper)),
        };
        
        // Serialize
        let bytes = whisper.encode_to_vec();
        
        // Get Generator
        let generator = generators.entry(stream_id).or_insert_with(|| {
             SaltGenerator::new_diversified(SESSION_BASE_SEED, stream_id)
        });
        
        // Dynamic Frame
        let framed_bytes = build_dynamic_frame(generator, &bytes, SilentConfig::default())
             .map_err(|e| format!("Framing Error: {}", e))?;
             
        // Send via QUIC
        // fin=true implies single usage of this stream for this frame (simpler for now)
        match conn.stream_send(stream_id, &framed_bytes, true) {
            Ok(_) => {
                debug!("FEC帧已发送: 流ID={}", stream_id);
                manager.mark_frame_sent(stream_id);
            },
            Err(e) => error!("FEC帧发送失败 (流{}): {:?}", stream_id, e),
        }
    }
    
    Ok(())
}

fn hex_dump(buf: &[u8]) -> String {
    let vec: Vec<String> = buf.iter().map(|b| format!("{b:02x}")).collect();

    vec.join("")
}