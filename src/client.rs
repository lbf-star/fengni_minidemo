use tracing::{info, error, warn, debug};
use silent_speaker::logging::init;

use ring::rand::*;

use prost::Message;
use silent_speaker::whisper::*;

const MAX_DATAGRAM_SIZE: usize = 1350;

const HTTP_REQ_STREAM_ID: u64 = 4;

fn main() {
    // 日志系统初始化
    init();

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

    // *CAUTION*: this should not be set to `false` in production!!!
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

          // 创建 Whisper 消息
          let mut whisper = Whisper::default();
          whisper.id = uuid::Uuid::new_v4().as_bytes().to_vec();
          whisper.content = "测试消息发送".to_string();
          whisper.timestamp_ns = std::time::SystemTime::now()
              .duration_since(std::time::UNIX_EPOCH)
              .unwrap()
              .as_nanos() as u64;
          whisper.priority = Priority::Normal as i32;

          // 序列化并发送
          let data = whisper.encode_to_vec();
          conn.stream_send(HTTP_REQ_STREAM_ID, &data, true)
              .unwrap();

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

                // 尝试解析为 Whisper 消息，如果失败则作为普通文本处理
                match Whisper::decode(stream_buf) {
                    Ok(whisper) => {
                        info!("接收到whisper响应: {}", whisper.content);
                        print!("服务确认ACK: {}", whisper.content);
                    }
                    Err(_) => {
                        // 如果不是 Protobuf，可能是普通文本确认
                        print!("{}", unsafe {
                            std::str::from_utf8_unchecked(stream_buf)
                        });
                    }
                }

                // 服务器报告没有更多数据发送，我们已收到完整响应。关闭连接。
                if s == HTTP_REQ_STREAM_ID && fin {
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

fn hex_dump(buf: &[u8]) -> String {
    let vec: Vec<String> = buf.iter().map(|b| format!("{b:02x}")).collect();

    vec.join("")
}