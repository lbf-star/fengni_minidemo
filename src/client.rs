use tracing::{info, error, warn, debug};
use silent_speaker::logging::init;

use ring::rand::*;

use prost::Message;
use silent_speaker::whisper::{Whisper, Priority};
use silent_speaker::whisper::whisper::Payload;
use silent_speaker::critical_sender::CriticalSender;
use silent_speaker::dynamic_framing::{SaltGenerator, build_dynamic_frame, DynamicStreamParser}; // Updated imports
use silent_speaker::framing::FramingError; // Keep for error handling if needed, or remove if unused

use std::collections::HashMap; // Import HashMap

const MAX_DATAGRAM_SIZE: usize = 1350;
const SESSION_BASE_SEED: [u8; 32] = [0x42; 32]; // Hardcoded seed for Phase 3

fn main() {
    // 日志系统初始化
    init();
    
    // 新增：创建FEC发送器和统一流管理器
    let mut critical_sender = CriticalSender::new(4, 2, 100)
      .expect("FEC发送器初始化失败");
    critical_sender.register_connection(0);  // 客户端只有一个连接，ID为0
    
    // 新增：统一流管理器（客户端单例）
    use silent_speaker::stream::UnifiedStreamManager;
    let mut stream_manager = UnifiedStreamManager::new(100);

    // Dynamic Framing State
    let mut stream_generators: HashMap<u64, SaltGenerator> = HashMap::new();
    let mut stream_parsers: HashMap<u64, DynamicStreamParser> = HashMap::new(); // For receiving ACKs

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
            debug!("发送操作将阻塞");
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
                        debug!("接受操作将阻塞");
                        break 'read;
                    }

                    panic!("接受操作失败: {e:?}");
                },
            };

            debug!("获得 {len} 字节");

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

            debug!("已处理 {read} 字节");
        }

        debug!("读取完成");

        if conn.is_closed() {
            info!("连接已关闭, {:?}", conn.stats());
            break;
        }

        if conn.is_established() && !req_sent {
            info!("正在发送消息 {}", url.path());

    // ============ 修改开始：使用分帧发送普通消息 ============
    let mut whisper = Whisper::default();
    whisper.id = uuid::Uuid::new_v4().as_bytes().to_vec();
    whisper.payload = Some(Payload::Content("测试普通消息(动态帧)".to_string()));
    whisper.timestamp_ns = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;
    whisper.priority = Priority::Normal as i32;
    
    // 为演示目的，我们手动指定一个StreamID (例如 4)
    // 在生产代码中，这应该由StreamManager或quiche自动分配
    let stream_id = 4; // 示例
    
    // 获取 Generator
    let generator = stream_generators.entry(stream_id).or_insert_with(|| {
        SaltGenerator::new_diversified(SESSION_BASE_SEED, stream_id)
    });
    
    // 序列化 Whisper
    let whisper_bytes = whisper.encode_to_vec();
    
    // 动态分帧
    match build_dynamic_frame(generator, &whisper_bytes) {
        Ok(framed_data) => {
            // 发送
            match conn.stream_send(stream_id, &framed_data, true) { // fin=true
                 Ok(_) => info!("普通消息已发送 (动态帧), 流ID: {}", stream_id),
                 Err(e) => error!("发送失败: {:?}", e),
            }
        },
        Err(e) => error!("分帧失败: {}", e),
    }

    // ============ 修改结束 ============
    
    // 新增：发送关键信令（FEC保护）- 使用分帧版本
    match send_critical_message_with_framing(&mut conn, &mut critical_sender, &mut stream_generators, "这是一条关键信令(动态帧)！") {
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
                    match parser.try_parse_next() {
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
                    debug!("写入完成");
                    break;
                },

                Err(e) => {
                    error!("发送操作失败: {e:?}");

                    conn.close(false, 0x1, b"fail").ok();
                    break;
                },
            };

            if let Err(e) = socket.send_to(&out[..write], send_info.to) {
                if e.kind() == std::io::ErrorKind::WouldBlock {
                    debug!("发送操作将阻塞");
                    break;
                }

                panic!("发送操作失败: {e:?}");
            }

            debug!("已写入 {write}");
        }

        if conn.is_closed() {
            info!("连接已关闭, {:?}", conn.stats());
            break;
        }
    }
}

// ============ 新增：使用分帧的关键信令发送函数 ============
fn send_critical_message_with_framing(
    conn: &mut quiche::Connection,
    sender: &mut CriticalSender,
    generators: &mut HashMap<u64, SaltGenerator>,
    message: &str,
) -> Result<(), String> {
    info!("发送关键信令: {}", message); 
    // 准备FEC消息（返回原始的FecWhisper）
    let messages = sender.prepare_critical_message(0, message.as_bytes(), Priority::Urgent)?;
    
    if messages.is_empty() {
        return Err("没有获取到可用的流".to_string());
    }
    
    for (stream_id, fec_whisper) in messages {
        // 创建Whisper消息（包含FEC负载）
        let mut whisper = Whisper::default();
        whisper.id = uuid::Uuid::new_v4().as_bytes().to_vec();
        whisper.payload = Some(Payload::FecPayload(fec_whisper));
        whisper.timestamp_ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;
        whisper.priority = Priority::Urgent as i32;
    
        // 序列化
        let whisper_bytes = whisper.encode_to_vec();
        
        // 获取/创建Generator
        let generator = generators.entry(stream_id).or_insert_with(|| {
             SaltGenerator::new_diversified(SESSION_BASE_SEED, stream_id)
        });
        
        // 动态分帧
        let framed_data = build_dynamic_frame(generator, &whisper_bytes)
             .map_err(|e| format!("Dynamic Framing Error: {}", e))?;
        
        // 检查流是否可写
        let writable_streams = conn.writable().collect::<Vec<_>>();
        if !writable_streams.contains(&stream_id) {
            // 尝试初始化流 - 发送空数据包打开流
            match conn.stream_send(stream_id, &[], false) {
                Ok(_) => debug!("流 {} 初始化成功", stream_id),
                Err(e) => {
                    warn!("流 {} 初始化失败: {}, 跳过", stream_id, e);
                    continue;
                }
            }
        }
        
        // 发送分帧数据，fin=false（流保持打开）
        conn.stream_send(stream_id, &framed_data, false)
            .map_err(|e| format!("QUIC发送失败: {}", e))?;
        // 发送完毕后关闭流
        conn.stream_send(stream_id, &[], true)
            .map_err(|e| format!("QUIC关闭流失败: {}", e))?;
        
        // 标记已发送
        if let Err(e) = sender.mark_frame_sent(0, stream_id) {
            warn!("标记帧发送失败: {}", e);
        }
        
        info!("已发送FEC块到流{} (DynamicFrame)", stream_id);
    }
    
    Ok(())
}

fn hex_dump(buf: &[u8]) -> String {
    let vec: Vec<String> = buf.iter().map(|b| format!("{b:02x}")).collect();

    vec.join("")
}