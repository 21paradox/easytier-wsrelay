use prost::Message;

use crate::codec;
use crate::compress;
use crate::constants::{PacketType, MY_PEER_ID};
use crate::crypto::{random_u64_string, WsCrypto};
use crate::peer_center::PeerCenter;
use crate::peer_manager::PeerManager;
use crate::peer_manager::WsPeerContext;
use crate::proto::common::{RpcCompressionInfo, RpcDescriptor, RpcPacket, RpcRequest, RpcResponse};
use crate::proto::peer_rpc::SyncRouteInfoResponse;

/// Action to take after processing an RPC request/response.
#[derive(Debug)]
pub enum RpcAction {
    /// Send bytes to a specific peer.
    SendTo { peer_id: u32, bytes: Vec<u8> },
    /// Push a full route update to a specific peer (after handling SyncRouteInfo).
    PushRouteUpdate { peer_id: u32, group_key: String },
    /// Broadcast route update to all peers in the group (except excluded).
    BroadcastRouteUpdate { group_key: String, exclude_peer_id: u32 },
    /// No action needed.
    None,
}

/// Handle an incoming RPC request.
/// Routes to PeerCenterRpc or OspfRouteRpc based on the descriptor.
/// Returns a list of actions to take (may be empty).
pub fn handle_rpc_req(
    ctx: &mut WsPeerContext,
    peer_manager: &mut PeerManager,
    peer_center_map: &mut std::collections::HashMap<String, PeerCenter>,
    payload: &[u8],
) -> Vec<RpcAction> {
    web_sys::console::log_1(
        &format!(
            "[RPC] handle_rpc_req payload_len={} peer_id={} group_key={}",
            payload.len(),
            ctx.peer_id,
            ctx.group_key
        )
        .into(),
    );
    let rpc_packet = match codec::decode_rpc_packet(payload) {
        Ok(p) => p,
        Err(e) => {
            web_sys::console::error_1(&format!("[RPC] decode_rpc_packet failed: {}", e).into());
            return vec![];
        }
    };
    web_sys::console::log_1(
        &format!(
            "[RPC] decoded rpc_packet: is_request={} service={:?} method={:?}",
            rpc_packet.is_request,
            rpc_packet.descriptor.as_ref().map(|d| d.service_name.as_str()),
            rpc_packet.descriptor.as_ref().map(|d| d.method_index),
        )
        .into(),
    );

    // Decompress body if needed
    let mut rpc_body = rpc_packet.body.clone();
    if let Some(ref comp) = rpc_packet.compression_info {
        if comp.algo > 1 {
            rpc_body = compress::gunzip_maybe(&rpc_packet.body);
        }
    }

    // Extract inner request body
    let mut inner_req_body = rpc_body.clone();
    if rpc_packet.is_request {
        if let Ok(rpc_request) = codec::decode_rpc_request(&rpc_body) {
            inner_req_body = rpc_request.request;
        }
    }

    let descriptor = rpc_packet.descriptor.as_ref();
    let service_name = descriptor.map(|d| d.service_name.as_str()).unwrap_or("");

    // --- PeerCenterRpc ---
    if service_name == "peer_rpc.PeerCenterRpc" || service_name == "PeerCenterRpc" {
        let group_key = ctx.group_key.clone();
        let pc = peer_center_map.entry(group_key.clone()).or_insert_with(PeerCenter::new);

        let method_index = descriptor.map(|d| d.method_index).unwrap_or(0);
        web_sys::console::log_1(&format!("[RPC] PeerCenterRpc method_index={}", method_index).into());

        if method_index == 0 {
            // report_peers
            match pc.report_peers(&group_key, &inner_req_body) {
                Ok(resp_bytes) => {
                    let send_bytes = build_rpc_response_bytes(&rpc_packet, &resp_bytes, ctx.peer_id);
                    return vec![RpcAction::SendTo {
                        peer_id: ctx.peer_id,
                        bytes: send_bytes,
                    }];
                }
                Err(e) => {
                    web_sys::console::error_1(&format!("PeerCenter report_peers failed: {}", e).into());
                    return vec![];
                }
            }
        }

        if method_index == 1 {
            // get_global_peer_map
            match pc.get_global_peer_map(&group_key, &inner_req_body) {
                Ok(resp_bytes) => {
                    let send_bytes = build_rpc_response_bytes(&rpc_packet, &resp_bytes, ctx.peer_id);
                    return vec![RpcAction::SendTo {
                        peer_id: ctx.peer_id,
                        bytes: send_bytes,
                    }];
                }
                Err(e) => {
                    web_sys::console::error_1(&format!("PeerCenter get_global_peer_map failed: {}", e).into());
                    return vec![];
                }
            }
        }

        web_sys::console::log_1(&format!("Unhandled PeerCenterRpc methodIndex={}", method_index).into());
        return vec![];
    }

    // --- OspfRouteRpc ---
    if service_name == "peer_rpc.OspfRouteRpc" || service_name == "OspfRouteRpc" {
        let group_key = ctx.group_key.clone();
        let method_index = descriptor.map(|d| d.method_index).unwrap_or(0);
        web_sys::console::log_1(
            &format!(
                "[RPC] OspfRouteRpc method_index={} group_key={}",
                method_index, group_key
            )
            .into(),
        );

        if method_index == 0 || method_index == 1 {
            return handle_sync_route_info(ctx, peer_manager, &rpc_packet, &inner_req_body, &group_key);
        }

        web_sys::console::log_1(&format!("Unhandled OspfRouteRpc methodIndex={}", method_index).into());
        return vec![];
    }

    web_sys::console::log_1(
        &format!(
            "Unhandled RPC Service: {} (proto: {})",
            service_name,
            descriptor.map(|d| d.proto_name.as_str()).unwrap_or("")
        )
        .into(),
    );
    vec![]
}

/// Handle an incoming RPC response.
pub fn handle_rpc_resp(
    ctx: &mut WsPeerContext,
    peer_manager: &mut PeerManager,
    header_from_peer_id: u32,
    payload: &[u8],
) -> Option<RpcAction> {
    let rpc_packet = codec::decode_rpc_packet(payload).ok()?;

    // Decompress body
    let mut rpc_body = rpc_packet.body.clone();
    if let Some(ref comp) = rpc_packet.compression_info {
        if comp.algo > 1 {
            rpc_body = compress::gunzip_maybe(&rpc_packet.body);
        }
    }

    let descriptor = rpc_packet.descriptor.as_ref();
    let service_name = descriptor.map(|d| d.service_name.as_str()).unwrap_or("");

    // Extract inner response body
    let mut service_resp_bytes = rpc_body.clone();
    if !rpc_packet.is_request {
        if let Ok(rpc_response) = codec::decode_rpc_response(&rpc_body) {
            service_resp_bytes = rpc_response.response;
        }
    }

    // Handle SyncRouteInfoResponse ack (OspfRouteRpc)
    if service_name == "peer_rpc.OspfRouteRpc" || service_name == "OspfRouteRpc" {
        if let Ok(resp) = codec::decode_sync_route_info_response(&service_resp_bytes) {
            if resp.session_id != 0 {
                let group_key = ctx.group_key.clone();
                peer_manager.on_route_session_ack(
                    &group_key,
                    header_from_peer_id,
                    resp.session_id,
                    ctx.we_are_initiator,
                );
                web_sys::console::log_1(
                    &format!(
                        "RpcResp SyncRouteInfoResponse from={} sessionId={} acked",
                        header_from_peer_id, resp.session_id
                    )
                    .into(),
                );
            }
        }
        return None;
    }

    None
}

/// Handle SyncRouteInfo RPC: update peer info, generate response, and push route update.
fn handle_sync_route_info(
    ctx: &mut WsPeerContext,
    peer_manager: &mut PeerManager,
    rpc_packet: &RpcPacket,
    inner_req_body: &[u8],
    group_key: &str,
) -> Vec<RpcAction> {
    web_sys::console::log_1(
        &format!(
            "[RPC] handle_sync_route_info group_key={} peer_id={} body_len={}",
            group_key,
            ctx.peer_id,
            inner_req_body.len()
        )
        .into(),
    );
    // Ensure server session ID
    if ctx.server_session_id.is_empty() {
        ctx.server_session_id = random_u64_string();
    }

    let mut p2p_changed = false;

    // Decode SyncRouteInfoRequest to check initiator flag
    if let Ok(sync_req) = codec::decode_sync_route_info_request(inner_req_body) {
        web_sys::console::log_1(
            &format!(
                "[RPC] SyncRouteInfoRequest decoded: is_initiator={} my_session_id={}",
                sync_req.is_initiator, sync_req.my_session_id
            )
            .into(),
        );
        ctx.we_are_initiator = !sync_req.is_initiator;

        // Ack the session
        peer_manager.on_route_session_ack(group_key, ctx.peer_id, sync_req.my_session_id, ctx.we_are_initiator);

        // Process incoming peer infos. has_peer_info_change is true when:
        // - New peers were discovered, OR
        // - Existing peer's version increased (e.g., reconnecting peer)
        let has_peer_info_change = peer_manager
            .process_incoming_peer_infos(group_key, ctx.peer_id, inner_req_body)
            .unwrap_or(false);

        // Also process conn_info so P2P edges are propagated to other peers
        p2p_changed = peer_manager.process_incoming_conn_info(group_key, ctx.peer_id, inner_req_body);

        // When peer info changed (new peers or version updates from reconnecting
        // peers), broadcast to all other peers so they learn about the changes.
        if has_peer_info_change && !p2p_changed {
            p2p_changed = true;
        }
    } else {
        web_sys::console::warn_1(
            &format!(
                "[RPC] decode_sync_route_info_request FAILED for inner_req_body len={}",
                inner_req_body.len()
            )
            .into(),
        );
    }

    // Generate response
    let resp_bytes = peer_manager.handle_sync_route_info(group_key, ctx.peer_id, inner_req_body);
    web_sys::console::log_1(
        &format!(
            "[RPC] handle_sync_route_info_request returned resp={}",
            resp_bytes.is_some()
        )
        .into(),
    );

    // Build RPC response and send
    if let Some(resp) = resp_bytes {
        let send_bytes = build_rpc_response_bytes(rpc_packet, &resp, ctx.peer_id);
        web_sys::console::log_1(
            &format!("[RPC] Sending RpcResp len={} to peer={}", send_bytes.len(), ctx.peer_id).into(),
        );

        let mut actions = vec![
            RpcAction::SendTo {
                peer_id: ctx.peer_id,
                bytes: send_bytes,
            },
            RpcAction::PushRouteUpdate {
                peer_id: ctx.peer_id,
                group_key: group_key.to_string(),
            },
        ];

        // When P2P connections change, broadcast to all other peers so they
        // learn about the new direct edges.
        if p2p_changed {
            web_sys::console::log_1(
                &format!(
                    "[P2P] p2p_changed=true, adding BroadcastRouteUpdate for group={} exclude={}",
                    group_key, ctx.peer_id
                )
                .into(),
            );
            actions.push(RpcAction::BroadcastRouteUpdate {
                group_key: group_key.to_string(),
                exclude_peer_id: ctx.peer_id,
            });
        }

        return actions;
    }

    vec![]
}

/// Build a full RPC response packet (without outer packet header wrapping).
pub fn build_rpc_response_bytes(req_rpc_packet: &RpcPacket, response_body: &[u8], to_peer_id: u32) -> Vec<u8> {
    // Compress if needed
    let mut body = response_body.to_vec();
    let compression_info = RpcCompressionInfo {
        algo: 1,
        accepted_algo: 1,
    };

    // Build RpcResponse
    let rpc_response = RpcResponse {
        response: body,
        error: None,
        runtime_us: 0,
    };
    let rpc_response_bytes = codec::encode_rpc_response(&rpc_response);

    // Build RpcPacket
    let descriptor = req_rpc_packet.descriptor.clone();
    let rpc_resp_packet = RpcPacket {
        from_peer: MY_PEER_ID,
        to_peer: to_peer_id,
        transaction_id: req_rpc_packet.transaction_id,
        descriptor,
        body: rpc_response_bytes,
        is_request: false,
        total_pieces: 1,
        piece_idx: 0,
        trace_id: req_rpc_packet.trace_id,
        compression_info: Some(compression_info),
    };

    codec::encode_rpc_packet(&rpc_resp_packet)
}
