use prost::Message;

use crate::proto::common::{RpcPacket, RpcRequest, RpcResponse};
use crate::proto::peer_rpc::{
    GetGlobalPeerMapRequest, GetGlobalPeerMapResponse, HandshakeRequest, ReportPeersRequest,
    ReportPeersResponse, RoutePeerInfo, SyncRouteInfoRequest, SyncRouteInfoResponse,
};

// ---- Direct prost decode/encode (for pure Rust consumers) ----

macro_rules! prost_decode_fn {
    ($name:ident, $type:ty) => {
        pub fn $name(bytes: &[u8]) -> Result<$type, String> {
            <$type>::decode(bytes).map_err(|e| format!("decode {} failed: {}", stringify!($type), e))
        }
    };
}

macro_rules! prost_encode_fn {
    ($name:ident, $type:ty) => {
        pub fn $name(msg: &$type) -> Vec<u8> {
            msg.encode_to_vec()
        }
    };
}

prost_decode_fn!(decode_handshake_request, HandshakeRequest);
prost_encode_fn!(encode_handshake_request, HandshakeRequest);

prost_decode_fn!(decode_rpc_packet, RpcPacket);
prost_encode_fn!(encode_rpc_packet, RpcPacket);

prost_decode_fn!(decode_rpc_request, RpcRequest);
prost_encode_fn!(encode_rpc_request, RpcRequest);

prost_decode_fn!(decode_rpc_response, RpcResponse);
prost_encode_fn!(encode_rpc_response, RpcResponse);

prost_decode_fn!(decode_sync_route_info_request, SyncRouteInfoRequest);
prost_encode_fn!(encode_sync_route_info_request, SyncRouteInfoRequest);

prost_decode_fn!(decode_sync_route_info_response, SyncRouteInfoResponse);
prost_encode_fn!(encode_sync_route_info_response, SyncRouteInfoResponse);

prost_decode_fn!(decode_report_peers_request, ReportPeersRequest);
prost_encode_fn!(encode_report_peers_request, ReportPeersRequest);

prost_decode_fn!(decode_report_peers_response, ReportPeersResponse);
prost_encode_fn!(encode_report_peers_response, ReportPeersResponse);

prost_decode_fn!(decode_get_global_peer_map_request, GetGlobalPeerMapRequest);
prost_encode_fn!(encode_get_global_peer_map_request, GetGlobalPeerMapRequest);

prost_decode_fn!(decode_get_global_peer_map_response, GetGlobalPeerMapResponse);
prost_encode_fn!(encode_get_global_peer_map_response, GetGlobalPeerMapResponse);

prost_decode_fn!(decode_route_peer_info, RoutePeerInfo);
prost_encode_fn!(encode_route_peer_info, RoutePeerInfo);

