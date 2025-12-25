use silent_speaker::dynamic_framing::{SaltGenerator, build_dynamic_frame, DynamicStreamParser, SilentConfig};
use silent_speaker::stream::UnifiedStreamManager;
use silent_speaker::fec::{FECEncoder, FECReassembler};
use silent_speaker::whisper::{Whisper, Priority, FecWhisper};
use silent_speaker::whisper::whisper::Payload;
use prost::Message;
use std::collections::HashMap;

// 模拟会话种子
const TEST_SESSION_SEED: [u8; 32] = [0xAA; 32];

#[test]
fn test_integrated_stack_normal_message() {
    // 1. 初始化组件
    let mut manager = UnifiedStreamManager::new(10);
    let mut sender_generators = HashMap::new();
    let mut receiver_parsers = HashMap::new();

    // 2. 准备数据
    let original_text = "Phase 4 Integrated Test Message";
    let mut whisper = Whisper::default();
    whisper.id = vec![1, 2, 3, 4];
    whisper.priority = Priority::Normal as i32;
    whisper.payload = Some(Payload::Content(original_text.to_string()));
    let whisper_bytes = whisper.encode_to_vec();

    // 3. 发送端：分配流 & 动态分帧
    let allocation = manager.allocate_stream_for_normal_message(whisper_bytes.clone(), Priority::Normal);
    assert!(allocation.is_some(), "Stream allocation failed");
    let (stream_id, data_to_send) = allocation.unwrap();

    let generator = sender_generators.entry(stream_id).or_insert_with(|| {
        SaltGenerator::new_diversified(TEST_SESSION_SEED, stream_id)
    });

    let config = SilentConfig::default();
    let frame = build_dynamic_frame(generator, &data_to_send, config).expect("Framing failed");

    // 4. 接收端：解析
    let parser = receiver_parsers.entry(stream_id).or_insert_with(|| {
        let generator = SaltGenerator::new_diversified(TEST_SESSION_SEED, stream_id); // Same seed/stream_id
        DynamicStreamParser::new(generator)
    });
    
    parser.append_data(&frame).expect("Append failed");
    let parsed_opt = parser.try_parse_next(config).expect("Parse failed");
    assert!(parsed_opt.is_some(), "Should parse one frame");
    let parsed_bytes = parsed_opt.unwrap();

    // 5. 验证内容
    assert_eq!(parsed_bytes, whisper_bytes, "Decrypted bytes match original");
    let decoded_whisper = Whisper::decode(&parsed_bytes[..]).expect("Protobuf decode failed");
    
    if let Some(Payload::Content(text)) = decoded_whisper.payload {
        assert_eq!(text, original_text);
    } else {
        panic!("Wrong payload type");
    }
}

#[test]
fn test_integrated_stack_fec_message() {
    // 1. 初始化
    let mut manager = UnifiedStreamManager::new(10);
    let mut encoder = FECEncoder::new(4, 2).unwrap();
    let mut reassembler = FECReassembler::new(4, 2);
    let mut sender_generators = HashMap::new();
    let mut receiver_parsers = HashMap::new();

    // 2. 准备关键信令
    let critical_text = "Critical Alert: System Failure!";
    
    // 3. 编码 & 调度
    let (frames, session_id) = encoder.encode(critical_text.as_bytes()).unwrap();
    let allocated_streams = manager.allocate_streams_for_fec(frames.clone(), session_id, Priority::Urgent);
    
    assert_eq!(allocated_streams.len(), frames.len());

    // 4. 模拟传输（丢弃部分包来测试恢复能力？）
    // 让我们丢弃第 3 个包 (Index 2)
    let drop_index = 2;
    
    for (i, (stream_id, frame)) in allocated_streams.iter().enumerate() {
        if i == drop_index {
            println!("Simulating packet loss for index {}", i);
            continue; 
        }

        // Wrap in Whisper
        let fec_whisper = FecWhisper { fec_frame: Some(frame.clone()) };
        let whisper = Whisper {
            id: vec![0; 16],
            timestamp_ns: 0,
            priority: Priority::Urgent as i32,
            payload: Some(Payload::FecPayload(fec_whisper)),
        };
        let bytes = whisper.encode_to_vec();

        // Frame
        let generator = sender_generators.entry(*stream_id).or_insert_with(|| {
            SaltGenerator::new_diversified(TEST_SESSION_SEED, *stream_id)
        });
        let wired_frame = build_dynamic_frame(generator, &bytes, SilentConfig::default()).unwrap();

        // Receive
        let parser = receiver_parsers.entry(*stream_id).or_insert_with(|| {
             let generator = SaltGenerator::new_diversified(TEST_SESSION_SEED, *stream_id);
             DynamicStreamParser::new(generator)
        });
        parser.append_data(&wired_frame).unwrap();
        
        let decrypted_bytes = parser.try_parse_next(SilentConfig::default()).unwrap().unwrap();
        
        // Decode Protobuf
        let decoded = Whisper::decode(&decrypted_bytes[..]).unwrap();
        if let Some(Payload::FecPayload(fw)) = decoded.payload {
            if let Some(f) = fw.fec_frame {
                 // Reassemble
                 match reassembler.process_fec_frame(&f) {
                     Ok(Some(recovered)) => {
                         assert_eq!(recovered.original_data, critical_text.as_bytes(), "Restored data matches");
                         println!("FEC Recovery Successful!");
                         return;
                     },
                     Ok(None) => {}, // Waiting for more frames
                     Err(e) => panic!("Reassembly error: {}", e),
                 }
            }
        }
    }
    
    // 如果我们要测试恢复能力，我们需要足够的包。
    // 4 data + 2 parity. We need 4 packets.
    // Total 6. Drop 1 -> 5 remaining. Recovery should succeed.
    // Reassembler returns Some only when newly complete.
    panic!("FEC Reassembly did not complete (should have recovered)");
}
