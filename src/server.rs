use tracing::{info, error, warn, debug, trace};
use silent_speaker::logging::init;

use silent_speaker::critical_sender::CriticalSender;

use std::sync::Arc;
use std::sync::Mutex;
use std::net;
use std::collections::HashMap;

use ring::rand::*;
use hex;


use prost::Message;
use silent_speaker::whisper::{Whisper, Priority};
use silent_speaker::whisper::whisper::Payload;
use silent_speaker::framing::{frame_message, StreamParser};

const MAX_DATAGRAM_SIZE: usize = 1350;

struct PartialResponse {
    body: Vec<u8>,
    written: usize,
}

struct Client {
    conn: quiche::Connection,
    partial_responses: HashMap<u64, PartialResponse>,
    conn_id: u64,  // 新增：数字连接ID用于FEC发送器
    stream_parsers: HashMap<u64, StreamParser>,
}

type ClientMap = HashMap<quiche::ConnectionId<'static>, Client>;

fn main() {
    // 日志系统初始化
    init();

    // 创建FEC关键信令发送器
    let critical_sender = CriticalSender::new(4, 2, 100).expect("FEC发送器初始化失败");

    let next_conn_id = Arc::new(Mutex::new(0u64));

    let mut buf = [0; 65535];
    let mut out = [0; MAX_DATAGRAM_SIZE];

    let mut args = std::env::args();

    let cmd = &args.next().unwrap();

    if args.len() != 0 {
        println!("用法: {cmd}");
        println!("\n更完整的实现请参见工具/应用。");
        return;
    }

    // Setup the event loop.
    let mut poll = mio::Poll::new().unwrap();
    let mut events = mio::Events::with_capacity(1024);

    // Create the UDP listening socket, and register it with the event loop.
    let mut socket =
        mio::net::UdpSocket::bind("127.0.0.1:4433".parse().unwrap()).unwrap();
    poll.registry()
        .register(&mut socket, mio::Token(0), mio::Interest::READABLE)
        .unwrap();

    // Create the configuration for the QUIC connections.
    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();

    config
        .load_cert_chain_from_pem_file("ca/cert.crt")
        .unwrap();
    config
        .load_priv_key_from_pem_file("ca/cert.key")
        .unwrap();

    config
        .set_application_protos(&[b"silent-speaker-v1"])
        .unwrap();

    config.set_max_idle_timeout(5000);
    config.set_max_recv_udp_payload_size(MAX_DATAGRAM_SIZE);
    config.set_max_send_udp_payload_size(MAX_DATAGRAM_SIZE);
    config.set_initial_max_data(10_000_000);
    config.set_initial_max_stream_data_bidi_local(1_000_000);
    config.set_initial_max_stream_data_bidi_remote(1_000_000);
    config.set_initial_max_stream_data_uni(1_000_000);
    config.set_initial_max_streams_bidi(100);
    config.set_initial_max_streams_uni(100);
    config.set_disable_active_migration(true);
    config.enable_early_data();

    let rng = SystemRandom::new();
    let conn_id_seed =
        ring::hmac::Key::generate(ring::hmac::HMAC_SHA256, &rng).unwrap();

    let mut clients = ClientMap::new();

    let local_addr = socket.local_addr().unwrap();

    loop {
        // Find the shorter timeout from all the active connections.
        //
        // TODO: use event loop that properly supports timers
        let timeout = clients.values().filter_map(|c| c.conn.timeout()).min();

        poll.poll(&mut events, timeout).unwrap();

        // Read incoming UDP packets from the socket and feed them to quiche,
        // until there are no more packets to read.
        'read: loop {
            // If the event loop reported no events, it means that the timeout
            // has expired, so handle it without attempting to read packets. We
            // will then proceed with the send loop.
            if events.is_empty() {
                debug!("等待超时");

                clients.values_mut().for_each(|c| c.conn.on_timeout());

                break 'read;
            }

            let (len, from) = match socket.recv_from(&mut buf) {
                Ok(v) => v,

                Err(e) => {
                    // There are no more UDP packets to read, so end the read
                    // loop.
                    if e.kind() == std::io::ErrorKind::WouldBlock {
                        debug!("接收操作将阻塞");
                        break 'read;
                    }

                    panic!("接受操作失败: {e:?}");
                },
            };

            debug!("收到 {len} 字节");

            let pkt_buf = &mut buf[..len];

            // Parse the QUIC packet's header.
            let hdr = match quiche::Header::from_slice(
                pkt_buf,
                quiche::MAX_CONN_ID_LEN,
            ) {
                Ok(v) => v,

                Err(e) => {
                    error!("解析数据包头部失败: {e:?}");
                    continue 'read;
                },
            };

            trace!("获得数据包 {hdr:?}");

            let conn_id = ring::hmac::sign(&conn_id_seed, &hdr.dcid);
            let conn_id = &conn_id.as_ref()[..quiche::MAX_CONN_ID_LEN];
            let conn_id = conn_id.to_vec().into();

            // Lookup a connection based on the packet's connection ID. If there
            // is no connection matching, create a new one.
            let client = if !clients.contains_key(&hdr.dcid) &&
                !clients.contains_key(&conn_id)
            {
                if hdr.ty != quiche::Type::Initial {
                    error!("数据包不是初始包");
                    continue 'read;
                }

                if !quiche::version_is_supported(hdr.version) {
                    warn!("正在进行版本协商");

                    let len =
                        quiche::negotiate_version(&hdr.scid, &hdr.dcid, &mut out)
                            .unwrap();

                    let out = &out[..len];

                    if let Err(e) = socket.send_to(out, from) {
                        if e.kind() == std::io::ErrorKind::WouldBlock {
                            debug!("发送操作将阻塞");
                            break;
                        }

                        panic!("发送操作失败: {e:?}");
                    }
                    continue 'read;
                }

                let mut scid = [0; quiche::MAX_CONN_ID_LEN];
                scid.copy_from_slice(&conn_id);

                let scid = quiche::ConnectionId::from_ref(&scid);

                // Token is always present in Initial packets.
                let token = hdr.token.as_ref().unwrap();

                // Do stateless retry if the client didn't send a token.
                if token.is_empty() {
                    warn!("正在执行无状态重试");

                    let new_token = mint_token(&hdr, &from);

                    let len = quiche::retry(
                        &hdr.scid,
                        &hdr.dcid,
                        &scid,
                        &new_token,
                        hdr.version,
                        &mut out,
                    )
                    .unwrap();

                    let out = &out[..len];

                    if let Err(e) = socket.send_to(out, from) {
                        if e.kind() == std::io::ErrorKind::WouldBlock {
                            debug!("发送操作将阻塞");
                            break;
                        }

                        panic!("发送操作失败: {e:?}");
                    }
                    continue 'read;
                }

                let odcid = validate_token(&from, token);

                // The token was not valid, meaning the retry failed, so
                // drop the packet.
                if odcid.is_none() {
                    error!("地址验证令牌无效");
                    continue 'read;
                }

                if scid.len() != hdr.dcid.len() {
                    error!("目标连接ID无效");
                    continue 'read;
                }

                // Reuse the source connection ID we sent in the Retry packet,
                // instead of changing it again.
                let scid = hdr.dcid.clone();

                debug!("新连接建立: dcid={:?} scid={:?}", hdr.dcid, scid);

                let conn = quiche::accept(
                    &scid,
                    odcid.as_ref(),
                    local_addr,
                    from,
                    &mut config,
                )
                .unwrap();

                // 分配数字连接ID
                let numeric_conn_id = {
                    let mut id = next_conn_id.lock().unwrap();
                    *id += 1;
                    *id
                };

                // 注册连接到FEC发送器
                critical_sender.register_connection(numeric_conn_id);

                let client = Client {
                    conn,
                    partial_responses: HashMap::new(),
                    conn_id: numeric_conn_id,  // 存储数字连接ID
                    stream_parsers: HashMap::new(),
                };

                clients.insert(scid.clone(), client);

                clients.get_mut(&scid).unwrap()
            } else {
                match clients.get_mut(&hdr.dcid) {
                    Some(v) => v,

                    None => clients.get_mut(&conn_id).unwrap(),
                }
            };

            let recv_info = quiche::RecvInfo {
                to: socket.local_addr().unwrap(),
                from,
            };

            // Process potentially coalesced packets.
            let read = match client.conn.recv(pkt_buf, recv_info) {
                Ok(v) => v,

                Err(e) => {
                    error!("{} 接收失败: {:?}", client.conn.trace_id(), e);
                    continue 'read;
                },
            };

            debug!("{} 已处理 {} 字节", client.conn.trace_id(), read);

            if client.conn.is_in_early_data() || client.conn.is_established() {
                // Handle writable streams.
                for stream_id in client.conn.writable() {
                    handle_writable(client, stream_id);
                }

                // Process all readable streams.
                for s in client.conn.readable() {
                    while let Ok((read, fin)) =
                        client.conn.stream_recv(s, &mut buf)
                    {
                        debug!(
                            "{} 已接收 {} 字节",
                            client.conn.trace_id(),
                            read
                        );

                        let stream_buf = &buf[..read];

                        debug!(
                            "{} 流 {} 有 {} 字节 (结束fin? {})",
                            client.conn.trace_id(),
                            s,
                            stream_buf.len(),
                            fin
                        );

                        handle_stream(client, s, stream_buf, &critical_sender);
                    }
                }
            }
        }

        // Generate outgoing QUIC packets for all active connections and send
        // them on the UDP socket, until quiche reports that there are no more
        // packets to be sent.
        for client in clients.values_mut() {
            loop {
                let (write, send_info) = match client.conn.send(&mut out) {
                    Ok(v) => v,

                    Err(quiche::Error::Done) => {
                        debug!("{} 写入完成", client.conn.trace_id());
                        break;
                    },

                    Err(e) => {
                        error!("{} 发送失败: {:?}", client.conn.trace_id(), e);

                        client.conn.close(false, 0x1, b"fail").ok();
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

                debug!("{} 已写入 {} 字节", client.conn.trace_id(), write);
            }
        }

        // Garbage collect closed connections.
        clients.retain(|_, ref mut c| {
            debug!("正在清理垃圾连接");

            if c.conn.is_closed() {
                info!(
                    "{} 已收集连接 {:?}",
                    c.conn.trace_id(),
                    c.conn.stats()
                );
            }

            !c.conn.is_closed()
        });
    }
}

/// Generate a stateless retry token.
///
/// The token includes the static string `"quiche"` followed by the IP address
/// of the client and by the original destination connection ID generated by the
/// client.
///
/// Note that this function is only an example and doesn't do any cryptographic
/// authenticate of the token. *It should not be used in production system*.
fn mint_token(hdr: &quiche::Header, src: &net::SocketAddr) -> Vec<u8> {
    let mut token = Vec::new();

    token.extend_from_slice(b"quiche");

    let addr = match src.ip() {
        std::net::IpAddr::V4(a) => a.octets().to_vec(),
        std::net::IpAddr::V6(a) => a.octets().to_vec(),
    };

    token.extend_from_slice(&addr);
    token.extend_from_slice(&hdr.dcid);

    token
}

/// Validates a stateless retry token.
///
/// This checks that the ticket includes the `"quiche"` static string, and that
/// the client IP address matches the address stored in the ticket.
///
/// Note that this function is only an example and doesn't do any cryptographic
/// authenticate of the token. *It should not be used in production system*.
fn validate_token<'a>(
    src: &net::SocketAddr, token: &'a [u8],
) -> Option<quiche::ConnectionId<'a>> {
    if token.len() < 6 {
        return None;
    }

    if &token[..6] != b"quiche" {
        return None;
    }

    let token = &token[6..];

    let addr = match src.ip() {
        std::net::IpAddr::V4(a) => a.octets().to_vec(),
        std::net::IpAddr::V6(a) => a.octets().to_vec(),
    };

    if token.len() < addr.len() || &token[..addr.len()] != addr.as_slice() {
        return None;
    }

    Some(quiche::ConnectionId::from_ref(&token[addr.len()..]))
}

/// Handles incoming Whisper Protobuf messages with FEC support and message framing.
/// 
/// This function processes framed messages using the new framing protocol:
/// [4-byte length prefix][Protobuf message data]
/// 
/// # Arguments
/// * `client` - The client connection state
/// * `stream_id` - QUIC stream ID where the message arrived
/// * `buf` - Raw message bytes (may contain partial or multiple framed messages)
/// * `critical_sender` - FEC critical message sender (for future FEC reassembly)
/// 
/// # Returns
/// * Nothing, but may send ACK responses back to the client
fn handle_stream(
    client: &mut Client, 
    stream_id: u64, 
    buf: &[u8],
    critical_sender: &CriticalSender,
) {
    let conn = &mut client.conn;
    
    debug!(
        "{} 流 {} 收到 {} 字节数据",
        conn.trace_id(),
        stream_id,
        buf.len()
    );
    
    // 步骤1: 获取或创建解析器
    let parser = client.stream_parsers
        .entry(stream_id)
        .or_insert_with(StreamParser::new);
    
    // 步骤2: 检查缓冲区大小
    if parser.buffer_size() > 10 * 1024 * 1024 {
        warn!(
            "{} 流 {} 解析器缓冲区过大({}字节)，重置解析器",
            conn.trace_id(),
            stream_id,
            parser.buffer_size()
        );
        parser.clear();
        return;
    }
    
    // 步骤3: 添加数据到解析器
    if let Err(e) = parser.append_data(buf) {
        error!(
            "{} 流 {} 数据添加失败: {:?}，重置解析器",
            conn.trace_id(),
            stream_id,
            e
        );
        parser.clear();
        return;
    }
    
    // 步骤4: 收集所有解析出的消息
    let mut messages = Vec::new();
    loop {
        match parser.try_parse_next() {
            Ok(Some(whisper)) => {
                messages.push(whisper);
            }
            Ok(None) => {
                // 数据不完整，等待更多数据
                break;
            }
            Err(e) => {
                error!(
                    "{} 流 {} 消息解析失败: {:?}，重置解析器",
                    conn.trace_id(),
                    stream_id,
                    e
                );
                parser.clear();
                return;
            }
        }
    }
    
    // 步骤5: 记录日志状态
    if messages.is_empty() && parser.buffer_size() > 0 {
        debug!(
            "{} 流 {} 数据不完整，等待更多数据。当前缓冲区: {} 字节",
            conn.trace_id(),
            stream_id,
            parser.buffer_size()
        );
    } else if !messages.is_empty() {
        debug!(
            "{} 流 {} 已解析 {} 个消息，准备处理",
            conn.trace_id(),
            stream_id,
            messages.len()
        );
    }
    
    // 步骤6: 处理消息 - 修复：传递conn引用而不是整个client
    if !messages.is_empty() {
        process_messages(conn, stream_id, messages, critical_sender);
    }
}

// 新增：处理消息的函数，不接收整个client
fn process_messages(
    conn: &mut quiche::Connection,
    stream_id: u64,
    messages: Vec<Whisper>,
    critical_sender: &CriticalSender,
) {
    for whisper in messages {
        process_single_message(conn, stream_id, whisper, critical_sender);
    }
}

// 修改原来的处理函数，只接收conn
fn process_single_message(
    conn: &mut quiche::Connection,
    stream_id: u64,
    whisper: Whisper,
    critical_sender: &CriticalSender,
) {
    match &whisper.payload {
        Some(Payload::Content(content)) => {
            info!(
                "{} 收到whisper格式消息，流ID {}",
                conn.trace_id(),
                stream_id
            );
            
            info!(
                "消息ID: {:?}, 内容: {}, 优先级: {:?}",
                hex::encode(&whisper.id),
                content,
                Priority::from_i32(whisper.priority).unwrap_or(Priority::Normal)
            );
            
            // 创建ACK消息
            let mut ack_whisper = Whisper::default();
            ack_whisper.id = uuid::Uuid::new_v4().as_bytes().to_vec();
            let ack_content = format!("确认ACK: 收到 '{}'", content);
            ack_whisper.payload = Some(Payload::Content(ack_content));
            ack_whisper.timestamp_ns = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos() as u64;
            ack_whisper.priority = whisper.priority;
            
            // 使用分帧函数包装ACK消息
            let framed_ack = silent_speaker::frame_message(&ack_whisper);
            
            // 发送ACK回执
            match conn.stream_send(stream_id, &framed_ack, false) {
                Ok(_) => debug!("{} 已发送ACK", conn.trace_id()),
                Err(e) => error!("{} 发送ACK失败: {:?}", conn.trace_id(), e),
            }
        }
        Some(Payload::FecPayload(fec)) => {
            if let Some(frame) = &fec.fec_frame {
                info!(
                    "{} 收到FEC帧 -> 会话:{} 块索引:{} 类型:{:?}",
                    conn.trace_id(),
                    hex::encode(&frame.session_id[..4]),
                    frame.block_index,
                    frame.block_type()
                );
                
                // 创建FEC确认消息
                let mut ack_whisper = Whisper::default();
                ack_whisper.id = uuid::Uuid::new_v4().as_bytes().to_vec();
                let ack_content = format!("收到FEC块[{}]", frame.block_index);
                ack_whisper.payload = Some(Payload::Content(ack_content));
                ack_whisper.timestamp_ns = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos() as u64;
                ack_whisper.priority = Priority::Normal as i32;
                
                let framed_ack = silent_speaker::frame_message(&ack_whisper);
                
                match conn.stream_send(stream_id, &framed_ack, false) {
                    Ok(_) => debug!("{} 已发送FEC确认", conn.trace_id()),
                    Err(e) => error!("{} 发送FEC确认失败: {:?}", conn.trace_id(), e),
                }
            }
        }
        None => {
            warn!("{} 收到无内容消息", conn.trace_id());
        }
    }
}

/// Handles newly writable streams (for sending responses)
/// 
/// This function sends any pending data on writable streams.
/// 
/// # Arguments
/// * `client` - The client connection
/// * `stream_id` - QUIC stream ID that is now writable
fn handle_writable(client: &mut Client, stream_id: u64) {
    let conn = &mut client.conn;

    debug!("{} 流 {} 可写入", conn.trace_id(), stream_id);

    // 如果没有部分响应要发送，直接返回
    if !client.partial_responses.contains_key(&stream_id) {
        return;
    }

    let resp = client.partial_responses.get_mut(&stream_id).unwrap();
    let body = &resp.body[resp.written..];

    let written = match conn.stream_send(stream_id, body, true) {
        Ok(v) => v,
        Err(quiche::Error::Done) => 0,
        Err(e) => {
            client.partial_responses.remove(&stream_id);
            error!("{} 流发送失败 {:?}", conn.trace_id(), e);
            return;
        },
    };

    resp.written += written;

    if resp.written == resp.body.len() {
        client.partial_responses.remove(&stream_id);
    }
}

/// 处理已解析的Whisper消息（内部函数）
/// 
/// This function handles a single parsed Whisper message and sends appropriate responses.
/// 
/// # Arguments
/// * `client` - The client connection
/// * `stream_id` - QUIC stream ID
/// * `whisper` - Parsed Whisper message
/// * `critical_sender` - FEC sender for handling FEC messages
fn process_parsed_whisper(
    client: &mut Client,
    stream_id: u64,
    whisper: Whisper,
    critical_sender: &CriticalSender,
) {
    let conn = &mut client.conn;
    
    // 统一的消息类型处理（支持普通文本和FEC数据）
    match &whisper.payload {
        Some(Payload::Content(content)) => {
            info!(
                "{} 收到whisper格式消息，流ID {}",
                conn.trace_id(),
                stream_id
            );
            
            info!(
                "消息ID: {:?}, 内容: {}, 优先级: {:?}",
                hex::encode(&whisper.id),
                content,
                whisper.priority()
            );
            
            // 在这里处理消息：打印、转发、存储等
            // 示例：发送简单的确认回执
            
            // 创建ACK消息
            let mut ack_whisper = Whisper::default();
            ack_whisper.id = uuid::Uuid::new_v4().as_bytes().to_vec();
            let ack_content = format!("确认ACK: 收到 '{}'", content);
            ack_whisper.payload = Some(Payload::Content(ack_content));
            ack_whisper.timestamp_ns = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos() as u64;
            ack_whisper.priority = whisper.priority as i32; // 使用原消息的优先级
            
            // 使用分帧函数包装ACK消息
            let framed_ack = frame_message(&ack_whisper);
            
            // 发送ACK回执
            match conn.stream_send(stream_id, &framed_ack, false) {
                Ok(_) => {
                    debug!("{} 已发送ACK", conn.trace_id());
                    
                    // 如果这是高优先级消息，立即尝试发送
                    if whisper.priority() == Priority::Urgent || whisper.priority() == Priority::High {
                        debug!("{} 高优先级消息，立即刷新发送缓冲区", conn.trace_id());
                        // 注意：这里只是标记需要发送，实际发送在主循环中进行
                    }
                }
                Err(e) => error!("{} 发送ACK失败: {:?}", conn.trace_id(), e),
            }
        }
        Some(Payload::FecPayload(fec)) => {
            // FEC消息处理：记录收到的FEC块，用于后续重组
            if let Some(frame) = &fec.fec_frame {
                info!(
                    "{} 收到FEC帧 -> 会话:{} 块索引:{} 类型:{:?}",
                    conn.trace_id(),
                    hex::encode(&frame.session_id[..4]),  // 显示前4字节用于调试
                    frame.block_index,
                    frame.block_type()
                );
                
                // TODO: 实现FEC重组逻辑
                // 1. 按session_id缓存FEC帧
                // 2. 当收到足够数量的帧时(k个)，调用FEC解码器恢复原始数据
                // 3. 处理恢复后的原始消息
                
                // 暂时发送FEC确认（使用分帧）
                let mut ack_whisper = Whisper::default();
                ack_whisper.id = uuid::Uuid::new_v4().as_bytes().to_vec();
                let ack_content = format!("收到FEC块[{}]", frame.block_index);
                ack_whisper.payload = Some(Payload::Content(ack_content));
                ack_whisper.timestamp_ns = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos() as u64;
                ack_whisper.priority = Priority::Normal as i32; // FEC确认使用普通优先级
                
                let framed_ack = frame_message(&ack_whisper);
                
                match conn.stream_send(stream_id, &framed_ack, false) {
                    Ok(_) => debug!("{} 已发送FEC确认", conn.trace_id()),
                    Err(e) => error!("{} 发送FEC确认失败: {:?}", conn.trace_id(), e),
                }
            } else {
                warn!("{} 收到空的FEC消息", conn.trace_id());
                
                // 发送错误回执
                let mut error_whisper = Whisper::default();
                error_whisper.id = uuid::Uuid::new_v4().as_bytes().to_vec();
                error_whisper.payload = Some(Payload::Content("错误：空的FEC消息".to_string()));
                error_whisper.timestamp_ns = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos() as u64;
                error_whisper.priority = Priority::Normal as i32;
                
                let framed_error = frame_message(&error_whisper);
                let _ = conn.stream_send(stream_id, &framed_error, false);
            }
        }
        None => {
            warn!(
                "{} 收到无内容消息，消息ID: {:?}",
                conn.trace_id(),
                hex::encode(&whisper.id)
            );
            
            // 发送错误回执
            let mut error_whisper = Whisper::default();
            error_whisper.id = uuid::Uuid::new_v4().as_bytes().to_vec();
            error_whisper.payload = Some(Payload::Content("错误：消息内容为空".to_string()));
            error_whisper.timestamp_ns = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos() as u64;
            error_whisper.priority = Priority::Normal as i32;
            
            let framed_error = frame_message(&error_whisper);
            let _ = conn.stream_send(stream_id, &framed_error, false);
        }
    }
}

/// 清理空闲的流解析器（防止内存泄漏）
/// 
/// 移除长时间未使用的流解析器，释放内存。
/// 
/// # Arguments
/// * `client` - The client connection
fn cleanup_idle_parsers(client: &mut Client) {
    // 这里可以添加基于时间的清理逻辑
    // 例如：移除超过30分钟未使用的解析器
    
    // 简单实现：如果解析器数量过多，清理一些
    const MAX_PARSERS_PER_CLIENT: usize = 100;
    if client.stream_parsers.len() > MAX_PARSERS_PER_CLIENT {
        warn!(
            "{} 流解析器数量过多({})，清理部分空闲解析器",
            client.conn.trace_id(),
            client.stream_parsers.len()
        );
        
        // 简单的清理策略：移除缓冲区为空的解析器
        client.stream_parsers.retain(|_, parser| parser.buffer_size() > 0);
        
        info!(
            "{} 清理后流解析器数量: {}",
            client.conn.trace_id(),
            client.stream_parsers.len()
        );
    }
}