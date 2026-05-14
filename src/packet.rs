use serde::{Deserialize, Serialize};

use crate::constants::{PacketType, HEADER_SIZE, MY_PEER_ID};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacketHeader {
    pub from_peer_id: u32,
    pub to_peer_id: u32,
    pub packet_type: u8,
    pub flags: u8,
    pub forward_counter: u8,
    pub reserved: u8,
    pub len: u32,
}

impl PacketHeader {
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < HEADER_SIZE {
            return None;
        }
        let b = &bytes[..HEADER_SIZE];
        Some(PacketHeader {
            from_peer_id: u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
            to_peer_id: u32::from_le_bytes([b[4], b[5], b[6], b[7]]),
            packet_type: b[8],
            flags: b[9],
            forward_counter: b[10],
            reserved: b[11],
            len: u32::from_le_bytes([b[12], b[13], b[14], b[15]]),
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = vec![0u8; HEADER_SIZE];
        buf[0..4].copy_from_slice(&self.from_peer_id.to_le_bytes());
        buf[4..8].copy_from_slice(&self.to_peer_id.to_le_bytes());
        buf[8] = self.packet_type;
        buf[9] = self.flags;
        buf[10] = self.forward_counter;
        buf[11] = self.reserved;
        buf[12..16].copy_from_slice(&self.len.to_le_bytes());
        buf
    }

    pub fn packet_type_enum(&self) -> PacketType {
        PacketType::from_u8(self.packet_type)
    }
}

/// Parse a 16-byte packet header from a buffer. Returns None if buffer is too short.
pub fn parse_header(bytes: &[u8]) -> Option<PacketHeader> {
    PacketHeader::from_bytes(bytes)
}

/// Create a 16-byte packet header.
pub fn create_header(from_peer_id: u32, to_peer_id: u32, packet_type: PacketType, payload_len: u32) -> Vec<u8> {
    PacketHeader {
        from_peer_id,
        to_peer_id,
        packet_type: packet_type as u8,
        flags: 0,
        forward_counter: 1,
        reserved: 0,
        len: payload_len,
    }
    .to_bytes()
}

/// Create a header for server response (from MY_PEER_ID to target).
pub fn create_server_header(to_peer_id: u32, packet_type: PacketType, payload_len: u32) -> Vec<u8> {
    create_header(MY_PEER_ID, to_peer_id, packet_type, payload_len)
}
