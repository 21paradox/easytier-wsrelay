/// Magic number used in EasyTier handshake protocol.
pub const MAGIC: u32 = 0xd1e1a5e1;

/// Protocol version.
pub const VERSION: u32 = 1;

/// Server's own Peer ID.
pub const MY_PEER_ID: u32 = 10000001;

/// Size of the binary packet header in bytes.
pub const HEADER_SIZE: usize = 16;

/// Packet types for EasyTier protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PacketType {
    Invalid = 0,
    Data = 1,
    HandShake = 2,
    RoutePacket = 3, // deprecated
    Ping = 4,
    Pong = 5,
    TaRpc = 6, // deprecated
    Route = 7, // deprecated
    RpcReq = 8,
    RpcResp = 9,
    ForeignNetworkPacket = 10,
    KcpSrc = 11,
    KcpDst = 12,
    NoiseHandshakeMsg1 = 13,
    NoiseHandshakeMsg2 = 14,
    NoiseHandshakeMsg3 = 15,
    QuicSrc = 16,
    QuicDst = 17,
    RelayHandshake = 20,
    RelayHandshakeAck = 21,
}

impl PacketType {
    pub fn from_u8(v: u8) -> Self {
        match v {
            1 => PacketType::Data,
            2 => PacketType::HandShake,
            3 => PacketType::RoutePacket,
            4 => PacketType::Ping,
            5 => PacketType::Pong,
            6 => PacketType::TaRpc,
            7 => PacketType::Route,
            8 => PacketType::RpcReq,
            9 => PacketType::RpcResp,
            10 => PacketType::ForeignNetworkPacket,
            11 => PacketType::KcpSrc,
            12 => PacketType::KcpDst,
            13 => PacketType::NoiseHandshakeMsg1,
            14 => PacketType::NoiseHandshakeMsg2,
            15 => PacketType::NoiseHandshakeMsg3,
            16 => PacketType::QuicSrc,
            17 => PacketType::QuicDst,
            20 => PacketType::RelayHandshake,
            21 => PacketType::RelayHandshakeAck,
            _ => PacketType::Invalid,
        }
    }
}
