use prost::Message;
use serde_json::Value;

use crate::proto::common::{RpcPacket, RpcRequest, RpcResponse};
use crate::proto::peer_rpc::{
    GetGlobalPeerMapRequest, GetGlobalPeerMapResponse, HandshakeRequest, ReportPeersRequest,
    ReportPeersResponse, RoutePeerInfo, SyncRouteInfoRequest, SyncRouteInfoResponse,
};

// JS Number.MAX_SAFE_INTEGER / MIN_SAFE_INTEGER
const JS_MAX_SAFE_INTEGER: i64 = 9007199254740991i64;
const JS_MIN_SAFE_INTEGER: i64 = -9007199254740991i64;

/// Recursively convert JSON numbers outside JS safe integer range to strings.
/// This prevents JSON.parse in JavaScript from losing precision for i64/u64 fields.
fn convert_out_of_safe_int_to_string(value: &mut Value) {
    match value {
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                if i > JS_MAX_SAFE_INTEGER || i < JS_MIN_SAFE_INTEGER {
                    *value = Value::String(i.to_string());
                }
            } else if let Some(u) = n.as_u64() {
                if u > JS_MAX_SAFE_INTEGER as u64 {
                    *value = Value::String(u.to_string());
                }
            }
        }
        Value::Object(map) => {
            for v in map.values_mut() {
                convert_out_of_safe_int_to_string(v);
            }
        }
        Value::Array(arr) => {
            for v in arr.iter_mut() {
                convert_out_of_safe_int_to_string(v);
            }
        }
        _ => {}
    }
}

/// Recursively convert JSON strings that look like big integers back to numbers.
fn convert_bigint_string_back_to_number(value: &mut Value) {
    match value {
        Value::String(s) => {
            if s.len() > 15 {
                let mut chars = s.chars();
                let first = chars.next().unwrap();
                let is_digits = (first == '-' || first.is_ascii_digit())
                    && chars.all(|c| c.is_ascii_digit());
                if is_digits {
                    if let Ok(i) = s.parse::<i64>() {
                        *value = serde_json::json!(i);
                    } else if let Ok(u) = s.parse::<u64>() {
                        *value = serde_json::json!(u);
                    }
                }
            }
        }
        Value::Object(map) => {
            for v in map.values_mut() {
                convert_bigint_string_back_to_number(v);
            }
        }
        Value::Array(arr) => {
            for v in arr.iter_mut() {
                convert_bigint_string_back_to_number(v);
            }
        }
        _ => {}
    }
}

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

// ---- JSON encode/decode (for compatibility with JS clients) ----

macro_rules! json_decode_fn {
    ($name:ident, $json_name:ident, $type:ty) => {
        pub fn $json_name(bytes: &[u8]) -> Result<String, String> {
            let msg = <$type>::decode(bytes)
                .map_err(|e| format!("decode {} failed: {}", stringify!($type), e))?;
            let mut value = serde_json::to_value(&msg)
                .map_err(|e| e.to_string())?;
            convert_out_of_safe_int_to_string(&mut value);
            serde_json::to_string(&value).map_err(|e| e.to_string())
        }
    };
}

macro_rules! json_encode_fn {
    ($name:ident, $json_name:ident, $type:ty) => {
        pub fn $json_name(json: &str) -> Result<Vec<u8>, String> {
            let mut value: serde_json::Value =
                serde_json::from_str(json).map_err(|e| e.to_string())?;
            convert_bigint_string_back_to_number(&mut value);
            let msg: $type = serde_json::from_value(value).map_err(|e| e.to_string())?;
            Ok(msg.encode_to_vec())
        }
    };
}

json_decode_fn!(decode_handshake_request, decode_handshake_request_json, HandshakeRequest);
json_encode_fn!(encode_handshake_request, encode_handshake_request_json, HandshakeRequest);

json_decode_fn!(decode_rpc_packet, decode_rpc_packet_json, RpcPacket);
json_encode_fn!(encode_rpc_packet, encode_rpc_packet_json, RpcPacket);

json_decode_fn!(decode_rpc_request, decode_rpc_request_json, RpcRequest);
json_encode_fn!(encode_rpc_request, encode_rpc_request_json, RpcRequest);

json_decode_fn!(decode_rpc_response, decode_rpc_response_json, RpcResponse);
json_encode_fn!(encode_rpc_response, encode_rpc_response_json, RpcResponse);

json_decode_fn!(decode_sync_route_info_request, decode_sync_route_info_request_json, SyncRouteInfoRequest);
json_encode_fn!(encode_sync_route_info_request, encode_sync_route_info_request_json, SyncRouteInfoRequest);

json_decode_fn!(decode_sync_route_info_response, decode_sync_route_info_response_json, SyncRouteInfoResponse);
json_encode_fn!(encode_sync_route_info_response, encode_sync_route_info_response_json, SyncRouteInfoResponse);

json_decode_fn!(decode_report_peers_request, decode_report_peers_request_json, ReportPeersRequest);
json_encode_fn!(encode_report_peers_request, encode_report_peers_request_json, ReportPeersRequest);

json_decode_fn!(decode_report_peers_response, decode_report_peers_response_json, ReportPeersResponse);
json_encode_fn!(encode_report_peers_response, encode_report_peers_response_json, ReportPeersResponse);

json_decode_fn!(decode_get_global_peer_map_request, decode_get_global_peer_map_request_json, GetGlobalPeerMapRequest);
json_encode_fn!(encode_get_global_peer_map_request, encode_get_global_peer_map_request_json, GetGlobalPeerMapRequest);

json_decode_fn!(decode_get_global_peer_map_response, decode_get_global_peer_map_response_json, GetGlobalPeerMapResponse);
json_encode_fn!(encode_get_global_peer_map_response, encode_get_global_peer_map_response_json, GetGlobalPeerMapResponse);

json_decode_fn!(decode_route_peer_info, decode_route_peer_info_json, RoutePeerInfo);
json_encode_fn!(encode_route_peer_info, encode_route_peer_info_json, RoutePeerInfo);
