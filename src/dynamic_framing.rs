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
    pub fn try_parse_next(&mut self) -> Result<Option<Vec<u8>>, DynamicFramingError> {
        // We need to clone the generator state to try parsing, because parse_dynamic_frame modifies it.
        // If parsing fails due to IncompleteData, we must revert the generator.
        // Actually `parse_dynamic_frame` modifies generator.
        // So we can backup sequence.
        
        let start_seq = self.generator.sequence;
        
        match parse_dynamic_frame(&mut self.generator, &self.buffer) {
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
    payload: &[u8]
) -> Result<Vec<u8>, DynamicFramingError> {
    let salt = generator.next_salt();
    
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
    let mut frame = Vec::with_capacity(4 + encrypted_len);
    frame.extend_from_slice(&obfuscated_len.to_be_bytes());
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
    data: &[u8]
) -> Result<(Vec<u8>, usize), DynamicFramingError> {
    if data.len() < 4 {
        return Err(DynamicFramingError::IncompleteData);
    }

    // 1. Generate Salt (Peek next state, don't advance yet if we fail? 
    // Actually simplicity: we assume we are trying to parse the *next* expected frame.
    // If we fail, the stream might be desynced, which is fatal for this protocol phase.
    // So we generate the salt.
    let salt = generator.next_salt();
    
    let key_bytes: [u8; 32] = salt;
    let nonce_bytes: [u8; 12] = salt[0..12].try_into().unwrap();
    let mask_bytes: [u8; 4] = salt[12..16].try_into().unwrap();
    let mask = u32::from_be_bytes(mask_bytes);
    
    // 2. De-obfuscate Length
    let obfuscated_len_bytes: [u8; 4] = data[0..4].try_into().unwrap();
    let obfuscated_len = u32::from_be_bytes(obfuscated_len_bytes);
    let encrypted_len = (obfuscated_len ^ mask) as usize;
    
    // 3. Check bounds
    // Max frame size sanity check (e.g. 10MB)
    if encrypted_len > 10 * 1024 * 1024 {
         return Err(DynamicFramingError::InvalidLength(encrypted_len));
    }
    
    let total_frame_size = 4 + encrypted_len;
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
    let mut buffer = data[4..total_frame_size].to_vec();
    
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
        let frame = build_dynamic_frame(&mut sender_gen, payload).unwrap();
        
        // Parse
        let (decoded, consumed) = parse_dynamic_frame(&mut receiver_gen, &frame).unwrap();
        
        assert_eq!(consumed, frame.len());
        assert_eq!(decoded, payload);
    }
    
    #[test]
    fn test_sequences_must_match() {
        let seed = [2u8; 32];
        let mut sender_gen = SaltGenerator::new(seed);
        let mut receiver_gen = SaltGenerator::new(seed);
        
        let payload = b"Secret";
        let frame = build_dynamic_frame(&mut sender_gen, payload).unwrap();
        
        // Desync receiver
        receiver_gen.next_salt(); 
        
        // Should fail
        let result = parse_dynamic_frame(&mut receiver_gen, &frame);
        assert!(result.is_err());
    }
}
