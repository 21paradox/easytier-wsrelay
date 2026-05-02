use crate::constants::{MY_PEER_ID, PacketType};
use crate::packet::create_header;
use getrandom::getrandom;
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::JsFuture;
use web_sys::{Crypto, CryptoKey, SubtleCrypto};

// ---- SipHash-1-3 implementation ----

fn rotl64(x: u64, b: u32) -> u64 {
    (x << b) | (x >> (64 - b))
}

fn sip_round(v: &mut [u64; 4]) {
    v[0] = v[0].wrapping_add(v[1]);
    v[1] = rotl64(v[1], 13);
    v[1] ^= v[0];
    v[0] = rotl64(v[0], 32);

    v[2] = v[2].wrapping_add(v[3]);
    v[3] = rotl64(v[3], 16);
    v[3] ^= v[2];

    v[0] = v[0].wrapping_add(v[3]);
    v[3] = rotl64(v[3], 21);
    v[3] ^= v[0];

    v[2] = v[2].wrapping_add(v[1]);
    v[1] = rotl64(v[1], 17);
    v[1] ^= v[2];
    v[2] = rotl64(v[2], 32);
}

fn read_u64_le(msg: &[u8], offset: usize) -> u64 {
    let mut bytes = [0u8; 8];
    let len = msg.len().saturating_sub(offset).min(8);
    bytes[..len].copy_from_slice(&msg[offset..offset + len]);
    u64::from_le_bytes(bytes)
}

/// SipHash-1-3: c=1 round per block, d=3 rounds finalization.
pub fn siphash_1_3(msg: &[u8], k0: u64, k1: u64) -> u64 {
    let b: u64 = (msg.len() as u64) << 56;

    let mut v: [u64; 4] = [
        0x736f6d6570736575u64 ^ k0,
        0x646f72616e646f6du64 ^ k1,
        0x6c7967656e657261u64 ^ k0,
        0x7465646279746573u64 ^ k1,
    ];

    let full_len = msg.len() - (msg.len() % 8);
    for i in (0..full_len).step_by(8) {
        let m = read_u64_le(msg, i);
        v[3] ^= m;
        sip_round(&mut v);
        v[0] ^= m;
    }

    let mut m = b;
    let left = msg.len() % 8;
    for i in 0..left {
        m |= (msg[full_len + i] as u64) << (8 * i);
    }

    v[3] ^= m;
    sip_round(&mut v);
    v[0] ^= m;

    v[2] ^= 0xffu64;
    sip_round(&mut v);
    sip_round(&mut v);
    sip_round(&mut v);

    v[0] ^ v[1] ^ v[2] ^ v[3]
}

// ---- Digest generation ----

/// Generate a digest of given length from two strings using SipHash-1-3.
/// digest_len must be a multiple of 8.
pub fn generate_digest_from_str(str1: &str, str2: &str, digest_len: usize) -> Vec<u8> {
    assert!(digest_len > 0 && digest_len % 8 == 0, "digest_len must be multiple of 8");

    let mut hasher = SipHashHasher::new();
    hasher.write(str1.as_bytes());
    hasher.write(str2.as_bytes());

    let shard_count = digest_len / 8;
    let mut digest = Vec::with_capacity(digest_len);
    for i in 0..shard_count {
        let h = u64_to_be_bytes(hasher.finish());
        digest.extend_from_slice(&h);
        hasher.write(&digest[0..((i + 1) * 8)]);
    }
    digest
}

fn u64_to_be_bytes(x: u64) -> [u8; 8] {
    let mut out = [0u8; 8];
    out[0] = ((x >> 56) & 0xff) as u8;
    out[1] = ((x >> 48) & 0xff) as u8;
    out[2] = ((x >> 40) & 0xff) as u8;
    out[3] = ((x >> 32) & 0xff) as u8;
    out[4] = ((x >> 24) & 0xff) as u8;
    out[5] = ((x >> 16) & 0xff) as u8;
    out[6] = ((x >> 8) & 0xff) as u8;
    out[7] = (x & 0xff) as u8;
    out
}

// ---- Key derivation ----

/// Derive 128-bit and 256-bit keys from a network secret using SipHash.
pub struct DerivedKeys {
    pub key128: Vec<u8>,
    pub key256: Vec<u8>,
}

pub fn derive_keys(network_secret: &str) -> DerivedKeys {
    let secret = network_secret.as_bytes();

    // Derive 128-bit key
    let mut hasher = SipHashHasher::new();
    hasher.write(secret);
    let first = u64_to_be_bytes(hasher.finish());
    let mut key128 = vec![0u8; 16];
    key128[0..8].copy_from_slice(&first);
    hasher.write(&key128[0..8]);
    let second = u64_to_be_bytes(hasher.finish());
    key128[8..16].copy_from_slice(&second);
    hasher.write(&key128);

    // Derive 256-bit key
    let mut hasher256 = SipHashHasher::new();
    hasher256.write(secret);
    hasher256.write(b"easytier-256bit-key");
    let mut key256 = vec![0u8; 32];
    for i in 0..4 {
        let chunk_start = i * 8;
        if chunk_start > 0 {
            hasher256.write(&key256[0..chunk_start]);
        }
        hasher256.write(&[i as u8]);
        let chunk = u64_to_be_bytes(hasher256.finish());
        key256[chunk_start..chunk_start + 8].copy_from_slice(&chunk);
    }

    DerivedKeys { key128, key256 }
}

// ---- SipHash-based hasher (matching JS DefaultHasher) ----

struct SipHashHasher {
    parts: Vec<Vec<u8>>,
    total: usize,
}

impl SipHashHasher {
    fn new() -> Self {
        SipHashHasher {
            parts: Vec::new(),
            total: 0,
        }
    }

    fn write(&mut self, buf: &[u8]) {
        if buf.is_empty() {
            return;
        }
        self.total += buf.len();
        self.parts.push(buf.to_vec());
    }

    fn finish(&self) -> u64 {
        if self.parts.len() == 1 {
            return siphash_1_3(&self.parts[0], 0, 0);
        }
        let mut msg = Vec::with_capacity(self.total);
        for p in &self.parts {
            msg.extend_from_slice(p);
        }
        siphash_1_3(&msg, 0, 0)
    }
}

// ---- Random utilities ----

/// Generate a random u64 as a string (matching JS randomU64String).
pub fn random_u64_string() -> String {
    let mut bytes = [0u8; 8];
    getrandom(&mut bytes).expect("getrandom failed");
    u64::from_be_bytes(bytes).to_string()
}

/// Generate random bytes of given length.
pub fn get_random_bytes(len: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; len];
    getrandom(&mut bytes).expect("getrandom failed");
    bytes
}

// ---- AES-GCM encryption (async, using Web Crypto API) ----

fn get_crypto() -> SubtleCrypto {
    let crypto: Crypto = js_sys::global()
        .unchecked_into::<web_sys::WorkerGlobalScope>()
        .crypto()
        .expect("crypto not available");
    crypto.subtle()
}

async fn import_aes_gcm_key(key_bytes: &[u8]) -> Result<CryptoKey, String> {
    let subtle = get_crypto();
    let key_obj = js_sys::Object::new();
    js_sys::Reflect::set(&key_obj, &"name".into(), &"AES-GCM".into())
        .map_err(|e| format!("set name: {:?}", e))?;

    let promise = subtle
        .import_key_with_object(
            "raw",
            &js_sys::Uint8Array::from(key_bytes),
            &key_obj,
            false,
            &["encrypt", "decrypt"].iter().map(|s| JsValue::from(*s)).collect::<js_sys::Array>(),
        )
        .map_err(|e| format!("import_key: {:?}", e))?;

    let js_val = JsFuture::from(promise).await.map_err(|e| format!("import_key await: {:?}", e))?;
    Ok(js_val.unchecked_into())
}

pub async fn encrypt_aes_gcm(payload: &[u8], key: &[u8]) -> Result<Vec<u8>, String> {
    let subtle = get_crypto();
    let nonce = get_random_bytes(12);

    let crypto_key = import_aes_gcm_key(key).await?;

    let algo = js_sys::Object::new();
    js_sys::Reflect::set(&algo, &"name".into(), &"AES-GCM".into())
        .map_err(|e| format!("set name: {:?}", e))?;
    js_sys::Reflect::set(&algo, &"iv".into(), &js_sys::Uint8Array::from(nonce.as_slice()))
        .map_err(|e| format!("set iv: {:?}", e))?;
    js_sys::Reflect::set(&algo, &"tagLength".into(), &JsValue::from(128))
        .map_err(|e| format!("set tagLength: {:?}", e))?;

    let promise = subtle
        .encrypt_with_object_and_buffer_source(&algo, &crypto_key, &js_sys::Uint8Array::from(payload))
        .map_err(|e| format!("encrypt: {:?}", e))?;

    let result = JsFuture::from(promise)
        .await
        .map_err(|e| format!("encrypt await: {:?}", e))?;

    let ciphertext_with_tag: Vec<u8> = js_sys::Uint8Array::new(&result).to_vec();

    // Format: ciphertext || tag(16 bytes) || nonce(12 bytes)
    // Web Crypto API returns ciphertext + tag concatenated
    let mut output = ciphertext_with_tag;
    output.extend_from_slice(&nonce);
    Ok(output)
}

pub async fn decrypt_aes_gcm(payload: &[u8], key: &[u8]) -> Result<Vec<u8>, String> {
    if payload.len() < 28 {
        return Err(format!("encrypted payload too short: {}", payload.len()));
    }

    let text_len = payload.len() - 28; // minus 16 tag, 12 nonce
    let ciphertext_with_tag = &payload[..text_len + 16];
    let nonce = &payload[text_len + 16..];

    let subtle = get_crypto();
    let crypto_key = import_aes_gcm_key(key).await?;

    let algo = js_sys::Object::new();
    js_sys::Reflect::set(&algo, &"name".into(), &"AES-GCM".into())
        .map_err(|e| format!("set name: {:?}", e))?;
    js_sys::Reflect::set(&algo, &"iv".into(), &js_sys::Uint8Array::from(nonce))
        .map_err(|e| format!("set iv: {:?}", e))?;
    js_sys::Reflect::set(&algo, &"tagLength".into(), &JsValue::from(128))
        .map_err(|e| format!("set tagLength: {:?}", e))?;

    let promise = subtle
        .decrypt_with_object_and_buffer_source(
            &algo,
            &crypto_key,
            &js_sys::Uint8Array::from(ciphertext_with_tag),
        )
        .map_err(|e| format!("decrypt: {:?}", e))?;

    let result = JsFuture::from(promise)
        .await
        .map_err(|e| format!("decrypt await: {:?}", e))?;

    Ok(js_sys::Uint8Array::new(&result).to_vec())
}

// ---- Packet wrapping (encryption wrapper) ----

/// Crypto state attached to each WebSocket.
#[derive(Debug, Clone)]
pub struct WsCrypto {
    pub enabled: bool,
    pub key128: Vec<u8>,
    pub key256: Vec<u8>,
}

impl Default for WsCrypto {
    fn default() -> Self {
        WsCrypto {
            enabled: false,
            key128: Vec::new(),
            key256: Vec::new(),
        }
    }
}

/// Wrap a payload into a full packet with optional AES-GCM encryption.
/// Returns the full packet bytes (header + body).
pub async fn wrap_packet(
    from_peer_id: u32,
    to_peer_id: u32,
    packet_type: PacketType,
    payload: &[u8],
    crypto: &WsCrypto,
) -> Result<Vec<u8>, String> {
    let mut body = payload.to_vec();
    let mut flags: u8 = 0;

    if crypto.enabled && packet_type != PacketType::HandShake {
        if !crypto.key128.is_empty() {
            body = encrypt_aes_gcm(&body, &crypto.key128).await?;
        } else if !crypto.key256.is_empty() {
            body = encrypt_aes_gcm(&body, &crypto.key256).await?;
        }
        flags |= 1;
    }

    let header = create_header(from_peer_id, to_peer_id, packet_type, body.len() as u32);
    let mut full = header;
    full[9] = flags;
    let body_len = body.len() as u32;
    full[12..16].copy_from_slice(&body_len.to_le_bytes());
    full.extend_from_slice(&body);

    Ok(full)
}

/// Wrap a packet as server (from MY_PEER_ID).
pub async fn wrap_server_packet(
    to_peer_id: u32,
    packet_type: PacketType,
    payload: &[u8],
    crypto: &WsCrypto,
) -> Result<Vec<u8>, String> {
    wrap_packet(MY_PEER_ID, to_peer_id, packet_type, payload, crypto).await
}
