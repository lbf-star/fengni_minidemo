//! Dynamic Framing Module
//!
//! Implements "Phase 3: Realizing Core Soul" logic:
//! - Salt Rotation
//! - Dynamic Frame Generation (Encryption + Obfuscation)
//! - Dynamic Frame Parsing
//!
//! # Frame Structure
//! [Obfuscated Length (4 bytes)] [Encrypted Body (Data + Padding + Tag)]
//!
//! The "Obfuscated Length" is the length of the *Encrypted Body* XORed with a mask derived from the Salt.

use ring::aead::{self, Aad, LessSafeKey, UnboundKey};
use ring::digest::{self, Context, SHA256};
use ring::rand::{SecureRandom, SystemRandom};
use std::convert::TryInto;
use thiserror::Error;

/// Protocol Configuration
#[derive(Debug, Clone, Copy)]
pub struct SilentConfig {
    /// Enable Robust Mode: Embeds a 2-byte obfuscated sequence hint in the header.
    /// This allows the receiver to recover from sequence desynchronization/packet loss.
    /// Default: true
    pub enable_sequence_hint: bool,
    
    /// Enable Paranoid Mode: Periodic Rekeying (Scheme C)
    /// Inserts fresh entropy (e.g. Ephemeral PubKey) every `ratchet_interval` frames.
    /// Default: false (but we will enable it for demonstration if user asks)
    pub enable_double_ratchet: bool,
    
    /// Interval for Rekeying (in number of frames).
    /// Default: 1000
    pub ratchet_interval: u64,
}

impl Default for SilentConfig {
    fn default() -> Self {
        Self {
            enable_sequence_hint: true,
            enable_double_ratchet: false, 
            ratchet_interval: 1000,
        }
    }
}

#[derive(Debug, Error)]
pub enum DynamicFramingError {
    #[error("Encryption error")]
    EncryptionError,
    
    #[error("Decryption error")]
    DecryptionError,
    
    #[error("Invalid data length: {0}")]
    InvalidLength(usize),
    
    #[error("Incomplete data")]
    IncompleteData,
}

/// Manages salt rotation and synchronization
pub struct SaltGenerator {
    seed: [u8; 32],
    sequence: u64,
}

impl SaltGenerator {
    /// Create a new generator with a specific seed
    pub fn new(seed: [u8; 32]) -> Self {
        Self { seed, sequence: 0 }
    }

    /// Create a new generator with a random seed
    pub fn new_random() -> Self {
        let rng = SystemRandom::new();
        let mut seed = [0u8; 32];
        rng.fill(&mut seed).expect("Failed to generate random seed");
        Self::new(seed)
    }

    /// Reset sequence to 0
    pub fn reset(&mut self) {
        self.sequence = 0;
    }

    /// Get the current sequence number
    pub fn sequence(&self) -> u64 {
        self.sequence
    }
    
    /// Set the sequence number (useful for sync)
    pub fn set_sequence(&mut self, seq: u64) {
        self.sequence = seq;
    }

    /// Generate the next salt and advance sequence
    /// Salt = SHA256(Seed + Sequence_BE_Bytes)
    pub fn next_salt(&mut self) -> [u8; 32] {
        let mut context = Context::new(&SHA256);
        context.update(&self.seed);
        context.update(&self.sequence.to_be_bytes());
        
        self.sequence += 1;
        
        let digest = context.finish();
        let mut salt = [0u8; 32];
        salt.copy_from_slice(digest.as_ref());
        salt
    }
    
    /// Generate salt for a specific sequence without advancing state
    pub fn get_salt_for_sequence(&self, seq: u64) -> [u8; 32] {
        let mut context = Context::new(&SHA256);
        context.update(&self.seed);
        context.update(&seq.to_be_bytes());
        
        let digest = context.finish();
        let mut salt = [0u8; 32];
        salt.copy_from_slice(digest.as_ref());
        salt
    }

    /// Create a new generator with a seed diversified by a stream ID (or other context)
    /// NewSeed = SHA256(BaseSeed + ContextID)
    pub fn new_diversified(base_seed: [u8; 32], context_id: u64) -> Self {
        let mut context = Context::new(&SHA256);
        context.update(&base_seed);
        context.update(&context_id.to_be_bytes());
        
        let digest = context.finish();
        let mut new_seed = [0u8; 32];
        new_seed.copy_from_slice(digest.as_ref());
        
        Self::new(new_seed)
    }

    
    /// Mix fresh entropy into the current seed (Rekeying)
    /// NewSeed = SHA256(OldSeed + Entropy)
    /// Resets sequence to 0 (or keeps it? Usually rekeying resets sequence context, 
    /// but for this specific "Stream" abstraction, keeping sequence monotonic is easier for QUIC mapping.
    /// Let's KEEP sequence monotonic but change the seed foundation.
    pub fn mix_entropy(&mut self, entropy: &[u8]) {
        let mut context = Context::new(&SHA256);
        context.update(&self.seed);
        context.update(entropy);
        
        let digest = context.finish();
        self.seed.copy_from_slice(digest.as_ref());
        // Note: We do NOT reset sequence here to simplify upper layer logic (allocating streams),
        // but cryptographically it effectively starts a new chain.
    }
}

/// Stream data parser for Dynamic Frames
pub struct DynamicStreamParser {
    buffer: Vec<u8>,
    max_buffer_size: usize,
    generator: SaltGenerator,
}

impl DynamicStreamParser {
    pub fn new(generator: SaltGenerator) -> Self {
        Self {
            buffer: Vec::new(),
            max_buffer_size: 10 * 1024 * 1024, // 10MB
            generator,
        }
    }

    pub fn append_data(&mut self, data: &[u8]) -> Result<(), DynamicFramingError> {
        if self.buffer.len() + data.len() > self.max_buffer_size {
            self.buffer.clear();
            return Err(DynamicFramingError::InvalidLength(self.buffer.len() + data.len()));
        }
        self.buffer.extend_from_slice(data);
        Ok(())
    }

    /// Try to parse the next frame.
    /// Returns:
    /// - Ok(Some(payload)): Successfully parsed a frame.
    /// - Ok(None): Incomplete data.
    /// - Err: Error (decryption, etc).
    pub fn try_parse_next(&mut self, config: SilentConfig) -> Result<Option<Vec<u8>>, DynamicFramingError> {
        // We need to clone the generator state to try parsing, because parse_dynamic_frame modifies it.
        // If parsing fails due to IncompleteData, we must revert the generator.
        // Actually `parse_dynamic_frame` modifies generator.
        // So we can backup sequence.
        
        let start_seq = self.generator.sequence;
        
        match parse_dynamic_frame(&mut self.generator, &self.buffer, config) {
            Ok((payload, consumed)) => {
                self.buffer.drain(0..consumed);
                Ok(Some(payload))
            }
            Err(DynamicFramingError::IncompleteData) => {
                // Revert sequence
                self.generator.sequence = start_seq;
                Ok(None)
            }
            Err(e) => {
                // Fatal error, clear buffer? 
                // Unlike static framing, if we fail to decrypt, it might be a sync issue or attack.
                // We probably can't recover easily without resync (which QUIC handles by retransmit, but we are top level).
                // Actually, if it's just garbled data, we are stuck.
                self.buffer.clear();
                Err(e)
            }
        }
    }
    
    pub fn buffer_size(&self) -> usize {
        self.buffer.len()
    }
    
    pub fn clear(&mut self) {
        self.buffer.clear();
    }
}

/// Build a dynamic frame
/// 
/// Process:
/// 1. Generate Salt for current sequence.
/// 2. Derive Key and Nonce from Salt.
/// 3. Add random padding to data.
/// 4. Encrypt (Data + Padding).
/// 5. Obfuscate Length of encrypted data.
/// 6. Return [ObfuscatedLength][EncryptedData]
pub fn build_dynamic_frame(
    generator: &mut SaltGenerator, 
    payload: &[u8],
    config: SilentConfig
) -> Result<Vec<u8>, DynamicFramingError> {
    let salt = generator.next_salt();
    let sequence = generator.sequence - 1; // next_salt incremented it, so we use (seq-1) used for this salt.
    // Wait, next_salt() -> self.sequence += 1.
    // So salt was generated using `sequence` BEFORE increment.
    // Let's check SaltGenerator implementation:
    // context.update(&self.sequence.to_be_bytes()); self.sequence += 1;
    // So salt corellates to `sequence` (the old value). 
    // Correct.
    
    // 1. Derive Keys from Salt
    // Key = Salt[0..32] (ChaCha20 key is 32 bytes)
    // Nonce = Salt[0..12] (96-bit nonce)
    // Mask = Salt[12..16] (32-bit (4 byte) mask for length)
    
    let key_bytes: [u8; 32] = salt; // Use salt directly as key
    let nonce_bytes: [u8; 12] = salt[0..12].try_into().unwrap();
    let mask_bytes: [u8; 4] = salt[12..16].try_into().unwrap();
    let mask = u32::from_be_bytes(mask_bytes);
    
    // 2. Encryption Setup
    let unbound_key = UnboundKey::new(&aead::CHACHA20_POLY1305, &key_bytes)
        .map_err(|_| DynamicFramingError::EncryptionError)?;
    let key = LessSafeKey::new(unbound_key);
    let nonce = aead::Nonce::assume_unique_for_key(nonce_bytes);
    
    // 3. Prepare Buffer (Payload + Tag Space)
    // We don't add extra random padding for now to keep it simple, 
    // but the architecture allows it. The Tag adds 16 bytes.
    let mut buffer = payload.to_vec();
    
    // 4. Encrypt in place (append tag)
    key.seal_in_place_append_tag(nonce, Aad::empty(), &mut buffer)
        .map_err(|_| DynamicFramingError::EncryptionError)?;
        
    let encrypted_len = buffer.len();
    if encrypted_len > u32::MAX as usize {
        return Err(DynamicFramingError::InvalidLength(encrypted_len));
    }
    
    // 5. Obfuscate Length
    let obfuscated_len = (encrypted_len as u32) ^ mask;
    
    // 6. Assemble Frame
    // Format: [ObfuscatedLength (4B)] [ObfuscatedHint (2B, Optional)] [EncryptedData]
    // 6. Assemble Frame
    // Format: [ObfuscatedLength (4B)] [ObfuscatedHint (2B, Optional)] [RekeyEntropy (32B, Optional)] [EncryptedData]
    // Check if we need to insert Rekey Entropy
    // Condition: Enabled && sequence > 0 && sequence % interval == 0
    // Note: We use `sequence` (the value used for THIS frame).
    // If sequence == 0, we don't rekey immediately (initial state).
    let do_rekey = config.enable_double_ratchet && sequence > 0 && (sequence % config.ratchet_interval == 0);
    
    let mut capacity = 4 + encrypted_len;
    if config.enable_sequence_hint { capacity += 2; }
    if do_rekey { capacity += 32; }
    
    let mut frame = Vec::with_capacity(capacity); 
    frame.extend_from_slice(&obfuscated_len.to_be_bytes());
    
    if config.enable_sequence_hint {
        // Calculate Hint: Low 16 bits of Sequence ^ High 16 bits of Mask (or some other part of Salt)
        // Let's use Mask's high 16 bits.
        // mask is u32 from salt[12..16].
        // Let's just use salt[16..18] for hint mask to avoid reusing the length mask bits too much (though it's fine).
        // Salt is 32 bytes.
        let hint_mask_bytes: [u8; 2] = salt[16..18].try_into().unwrap();
        let hint_mask = u16::from_be_bytes(hint_mask_bytes);
        
        // Sequence used was `sequence` (before increment).
        let seq_low = (sequence as u16);
        let hint = seq_low ^ hint_mask;
        
        frame.extend_from_slice(&hint.to_be_bytes());
    }
    
    if do_rekey {
        // Generate Fresh Entropy (Simulating Ephemeral Public Key)
        let rng = SystemRandom::new();
        let mut entropy = [0u8; 32];
        rng.fill(&mut entropy).map_err(|_| DynamicFramingError::EncryptionError)?;
        
        // Insert into header
        frame.extend_from_slice(&entropy);
        
        // Update local generator state
        generator.mix_entropy(&entropy);
    }
    
    frame.extend_from_slice(&buffer);
    
    Ok(frame)
}

/// Parse a dynamic frame
/// 
/// Note: This function attempts to parse ONE frame from the beginning of `data`.
/// It assumes the `generator` is synchronized to the correct state for this frame.
/// 
/// Returns: (Decrypted Payload, Total Bytes Consumed)
pub fn parse_dynamic_frame(
    generator: &mut SaltGenerator,
    data: &[u8],
    config: SilentConfig
) -> Result<(Vec<u8>, usize), DynamicFramingError> {
    // Basic header size depends on config
    let mut header_size = 4;
    if config.enable_sequence_hint { header_size += 2; }
    
    // We need to know if we expect rekeying to calculate header size.
    // Speculative: We need to know the sequence first!
    // But `generator.sequence` tells us what we expect.
    // If `generator.sequence % interval == 0`, we expect rekey.
    // Warning: If we are desynced (Robust Mode needed), we might predict wrong header size!
    // This is the tricky part of mixing Robust Mode with Rekeying.
    // Robust Mode relies on fixed header offsets to find the Hint?
    // Actually, Hint is always at offset 4. Rekeying comes AFTER Hint. Safe.
    
    // However, if we resync (jump sequence), we might jump over a rekey frame or land on one.
    // For now, assume sync or simple resync.
    
    let current_seq = generator.sequence;
    // Note: parse is called BEFORE next_salt implies we haven't consumed this seq yet?
    // No, parse_dynamic_frame calls next_salt().
    // So `generator.sequence` is the stored state (e.g. 0).
    // The frame we are about to parse corresponds to `generator.sequence` (e.g. 0).
    
    let do_rekey = config.enable_double_ratchet && current_seq > 0 && (current_seq % config.ratchet_interval == 0);
    if do_rekey { header_size += 32; }
    
    if data.len() < header_size {
        return Err(DynamicFramingError::IncompleteData);
    }

    // 1. Generate Salt (Peek next state, don't advance yet if we fail? 
    // Actually simplicity: we assume we are trying to parse the *next* expected frame.
    // If we fail, the stream might be desynced, which is fatal for this protocol phase.
    // So we generate the salt.
    // 1. Generate Salt (Peek / Speculate)
    // If Sequence Hint is enabled, we first try to recover the correct sequence.
    
    // Helper to extract fields from salt
    fn derive_keys(salt: [u8; 32]) -> ([u8; 32], [u8; 12], u32, u16) {
         let key_bytes: [u8; 32] = salt;
         let nonce_bytes: [u8; 12] = salt[0..12].try_into().unwrap();
         let mask_bytes: [u8; 4] = salt[12..16].try_into().unwrap();
         let mask = u32::from_be_bytes(mask_bytes);
         let hint_mask = u16::from_be_bytes(salt[16..18].try_into().unwrap());
         (key_bytes, nonce_bytes, mask, hint_mask)
    }

    let current_seq = generator.sequence;
    
    // Strategy:
    // If Hint is enabled:
    //   Calculate what Hint we expect for current_seq.
    //   Compare with received Hint.
    //   If mismatch, check if (current_seq + delta) matches received Hint.
    //   We only look forward (e.g., up to 1000 frames) to avoid replay attacks or excessive CPU.
    
    let mut salt = generator.next_salt(); // Temporarily advance
    let (_, _, mask, hint_mask) = derive_keys(salt);
    
    if config.enable_sequence_hint {
        let received_hint_bytes: [u8; 2] = data[4..6].try_into().unwrap();
        let received_hint = u16::from_be_bytes(received_hint_bytes);
        
        let expected_hint = (current_seq as u16) ^ hint_mask;
        

        if received_hint != expected_hint {
            // Desync detected! Search forward.
            let search_window = 1000;
            let mut found_sync = None;
            
            for offset in 1..=search_window {
                let check_seq = current_seq + offset;
                // Important: If we skip frames, we might skip rekey events!
                // If we skip a rekey event, our Seed calculation for `check_seq` will be WRONG 
                // because we missed the `mix_entropy` update.
                // This implies Robust Mode + Rekeying is complex: 
                // You cannot easily jump over a Rekey frame without the rekey payload.
                // Limitation: If we lose a Rekey Frame, we might be permanently desynced until full reset?
                // Or we need to try to detect if `check_seq` implies we missed a rekey.
                // For this "Simple" implementation, we will assume we don't jump OVER a rekey frame 
                // OR that `get_salt_for_sequence` generates based on the *current* seed (ignoring missed rekeys).
                // This means future salts are valid only if seed hasn't changed.
                // If seed changed (missed rekey), we can't recover.
                // This is a trade-off. We accept it for now.
                
                let check_salt = generator.get_salt_for_sequence(check_seq);
                // ... (rest of logic same)
                let (_, _, _, check_hint_mask) = derive_keys(check_salt);
                let check_hint = (check_seq as u16) ^ check_hint_mask;
                
                if received_hint == check_hint {
                    found_sync = Some((check_seq, check_salt));
                    break;
                }
            }
            
            if let Some((new_seq, new_salt)) = found_sync {
                // Adjust
                generator.set_sequence(new_seq + 1);
                salt = new_salt; // Update salt
                
                // Correction: If we jumped, we might have skipped rekey logic.
                // But for THIS frame, if it is a rekey frame, we need to handle it below.
                // We established `do_rekey` based on `current_seq` (old). 
                // If we jumped `new_seq`, does this frame contain rekey data?
                // We need to re-evaluate `do_rekey` based on `new_seq`.
                let new_do_rekey = config.enable_double_ratchet && new_seq > 0 && (new_seq % config.ratchet_interval == 0);
                if new_do_rekey != do_rekey {
                    // Header size mismatch!
                     return Err(DynamicFramingError::DecryptionError); // Complex resync failed
                }
            } else {
                 generator.set_sequence(current_seq);
                 return Err(DynamicFramingError::DecryptionError); 
            }
        }
    }
    
    // Extract Rekey Entropy if needed
    if do_rekey {
        // Entropy is after Hint (if any).
        let entropy_offset = if config.enable_sequence_hint { 6 } else { 4 };
        let entropy: [u8; 32] = data[entropy_offset..entropy_offset+32].try_into().unwrap();
        
        // Mix into generator
        generator.mix_entropy(&entropy);
        
        // Note: We mixed entropy. usage of `salt` (derived from OLD seed) is still valid for THIS frame?
        // Protocol decision: 
        // Option A: Rekey payload allows decrypting THIS frame with NEW key?
        // Option B: Rekey payload prepares for NEXT frame. THIS frame uses OLD key.
        // `build` did: `salt = next_salt()` (OLD seed) -> Encrypt -> `mix_entropy()` (NEW seed).
        // So THIS frame is encrypted with OLD seed. Correct.
    }
    
    let (key_bytes, nonce_bytes, mask, _) = derive_keys(salt);
    
    // 2. De-obfuscate Length
    let obfuscated_len_bytes: [u8; 4] = data[0..4].try_into().unwrap();
    let obfuscated_len = u32::from_be_bytes(obfuscated_len_bytes);
    let encrypted_len = (obfuscated_len ^ mask) as usize;
    
    // 3. Check bounds
    // Max frame size sanity check (e.g. 10MB)
    if encrypted_len > 10 * 1024 * 1024 {
         return Err(DynamicFramingError::InvalidLength(encrypted_len));
    }
    
    let total_frame_size = header_size + encrypted_len;
    if data.len() < total_frame_size {
        // We need to revert the generator state because we didn't consume the message?
        // Or caller should ensure they have enough data? 
        // For a stream parser, we usually need to know "length needed".
        // But here we just calculated the length needed!
        // So we return IncompleteData with enough info?
        // Let's rely on the caller handling "IncompleteData" by NOT advancing generator?
        // Wait, we ALREADY advanced generator inside next_salt().
        // We need a way to peek or revert.
        // Let's revert manually:
        generator.sequence -= 1;
        return Err(DynamicFramingError::IncompleteData);
    }
    
    // 4. Decrypt
    let unbound_key = UnboundKey::new(&aead::CHACHA20_POLY1305, &key_bytes)
        .map_err(|_| DynamicFramingError::DecryptionError)?;
    let key = LessSafeKey::new(unbound_key);
    let nonce = aead::Nonce::assume_unique_for_key(nonce_bytes);
    
    // Make a copy to decrypt in place (or modify input if signature allowed, but here we take slice)
    let mut buffer = data[header_size..total_frame_size].to_vec();
    
    let decrypted_data = key.open_in_place(nonce, Aad::empty(), &mut buffer)
        .map_err(|_| DynamicFramingError::DecryptionError)?;
        
    // 5. Return
    Ok((decrypted_data.to_vec(), total_frame_size))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_salt_rotation() {
        let mut generator = SaltGenerator::new([0u8; 32]);
        let s1 = generator.next_salt();
        let s2 = generator.next_salt();
        assert_ne!(s1, s2);
        
        let mut gen2 = SaltGenerator::new([0u8; 32]);
        let s1_prime = gen2.next_salt();
        assert_eq!(s1, s1_prime);
    }
    
    #[test]
    fn test_frame_roundtrip() {
        let seed = [1u8; 32];
        let mut sender_gen = SaltGenerator::new(seed);
        let mut receiver_gen = SaltGenerator::new(seed);
        
        let payload = b"Hello, Dynamic World!";
        
        // Build
        let config = SilentConfig::default();
        let frame = build_dynamic_frame(&mut sender_gen, payload, config).unwrap();
        
        // Parse
        let (decoded, consumed) = parse_dynamic_frame(&mut receiver_gen, &frame, config).unwrap();
        
        assert_eq!(consumed, frame.len());
        assert_eq!(decoded, payload);
    }
    
    #[test]
    fn test_sequences_must_match() {
        let seed = [2u8; 32];
        let mut sender_gen = SaltGenerator::new(seed);
        let mut receiver_gen = SaltGenerator::new(seed);
        
        let payload = b"Secret";
        let config = SilentConfig::default();
        let frame = build_dynamic_frame(&mut sender_gen, payload, config).unwrap();
        
        // Desync receiver
        receiver_gen.next_salt(); 
        
        // Should fail (or RESYNC if robust mode is on?)
        // If robust mode is on, it might succeed if next_salt() only advanced by 1.
        // Let's test with Robust Mode OFF to ensure strictness, or test Resync.
        
        let mut strict_config = SilentConfig::default();
        strict_config.enable_sequence_hint = false;
        
        // Re-generate frame without hint
        let mut sender_gen_strict = SaltGenerator::new(seed);
        let frame_strict = build_dynamic_frame(&mut sender_gen_strict, payload, strict_config).unwrap();
        
        let mut receiver_gen_strict = SaltGenerator::new(seed);
        receiver_gen_strict.next_salt(); // Desync
        
        let result = parse_dynamic_frame(&mut receiver_gen_strict, &frame_strict, strict_config);
        assert!(result.is_err());
    }

    #[test]
    fn test_periodic_rekeying() {
        let seed = [3u8; 32];
        let mut sender_gen = SaltGenerator::new(seed);
        let mut receiver_gen = SaltGenerator::new(seed);
        
        let mut config = SilentConfig::default();
        config.enable_double_ratchet = true;
        config.ratchet_interval = 2; // Rekey every 2 frames
        
        // Frame 1 (Seq 0): No Rekey
        let payload1 = b"Frame 1";
        let frame1 = build_dynamic_frame(&mut sender_gen, payload1, config).unwrap();
        // 4(Len)+2(Hint)+Data+Tag. No 32B entropy for seq 0.
        assert_eq!(frame1.len(), 4 + 2 + payload1.len() + 16); 
        
        let (dec1, _) = parse_dynamic_frame(&mut receiver_gen, &frame1, config).unwrap();
        assert_eq!(dec1, payload1);
        
        // Frame 2 (Seq 1): No Rekey (Wait, sequence starts at 0. config uses (sequence % interval == 0) and sequence > 0)
        // If ratchet_interval is 2: 
        // Seq 0: No
        // Seq 1: No
        // Seq 2: Yes
        let payload2 = b"Frame 2";
        let frame2 = build_dynamic_frame(&mut sender_gen, payload2, config).unwrap();
        assert_eq!(frame2.len(), 4 + 2 + payload2.len() + 16);
        
        let (dec2, _) = parse_dynamic_frame(&mut receiver_gen, &frame2, config).unwrap();
        assert_eq!(dec2, payload2);
        
        // Frame 3 (Seq 2): Rekey! (2 % 2 == 0)
        let payload3 = b"Frame 3 - Rekey";
        let frame3 = build_dynamic_frame(&mut sender_gen, payload3, config).unwrap();
        // Should be larger by 32 bytes
        assert_eq!(frame3.len(), 4 + 2 + 32 + payload3.len() + 16);
        
        let (dec3, _) = parse_dynamic_frame(&mut receiver_gen, &frame3, config).unwrap();
        assert_eq!(dec3, payload3);
        
        // Verify seeds have diverged from a naive non-rekeyed generator
        let mut naive_gen = SaltGenerator::new(seed);
        naive_gen.next_salt(); naive_gen.next_salt(); naive_gen.next_salt(); // Advance 3 times
        
        let s_rekeyed = sender_gen.next_salt();
        let s_naive = naive_gen.next_salt();
        assert_ne!(s_rekeyed, s_naive);
    }
}
