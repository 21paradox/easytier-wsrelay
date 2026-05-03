use std::cell::RefCell;
use std::collections::HashMap;

use prost::Message;

use crate::codec;
use crate::constants::MY_PEER_ID;
use crate::crypto::random_u64_string;
use crate::peer_center::PeerCenter;
use crate::proto::common::{RpcDescriptor, RpcPacket, RpcRequest};
use crate::proto::peer_rpc::SyncRouteInfoRequest;
use crate::route_state::RouteState;

/// WebSocket context needed by peer_manager for building RPC messages.
/// These fields mirror the metadata attached to each WebSocket in the JS version.
#[derive(Debug, Clone)]
pub struct WsPeerContext {
    pub peer_id: u32,
    pub group_key: String,
    pub domain_name: String,
    pub server_session_id: String,
    pub we_are_initiator: bool,
}

impl Default for WsPeerContext {
    fn default() -> Self {
        WsPeerContext {
            peer_id: 0,
            group_key: String::new(),
            domain_name: "public_server".to_string(),
            server_session_id: random_u64_string(),
            we_are_initiator: false,
        }
    }
}

/// PeerManager wraps RouteState and provides methods to build RPC messages.
pub struct PeerManager {
    pub route_state: RouteState,
}

impl PeerManager {
    pub fn new() -> Self {
        PeerManager {
            route_state: RouteState::new(),
        }
    }

    pub fn add_peer(&mut self, group_key: &str, peer_id: u32) {
        self.route_state.add_peer(group_key, peer_id);
        self.route_state.bump_my_info_version(group_key);
    }

    pub fn remove_peer(&mut self, ctx: &WsPeerContext) -> bool {
        let peer_id = ctx.peer_id;
        let group_key = &ctx.group_key;
        if peer_id == 0 {
            return false;
        }
        self.route_state.remove_peer(group_key, peer_id);
        true
    }

    pub fn list_peer_ids_in_group(&self, group_key: &str) -> Vec<u32> {
        self.route_state.get_peer_ids_in_group(group_key)
    }

    pub fn update_peer_info(
        &mut self,
        group_key: &str,
        peer_id: u32,
        info_bytes: &[u8],
    ) {
        if let Err(e) = self.route_state.update_peer_info(group_key, peer_id, info_bytes) {
            web_sys::console::warn_1(
                &format!("updatePeerInfo error: {}", e).into(),
            );
        }
    }

    pub fn on_route_session_ack(
        &mut self,
        group_key: &str,
        peer_id: u32,
        their_session_id: u64,
        we_are_initiator: bool,
    ) {
        self.route_state
            .on_route_session_ack(group_key, peer_id, their_session_id, we_are_initiator);
    }

    /// Build a SyncRouteInfo RPC request to send to target_peer_id.
    /// Returns the raw bytes of the RpcPacket (without packet header wrapping).
    pub fn build_route_update(
        &mut self,
        ctx: &WsPeerContext,
        target_peer_id: u32,
        force_full: bool,
    ) -> Option<Vec<u8>> {
        let group_key = &ctx.group_key;
        let server_session_id: u64 = ctx.server_session_id.parse().unwrap_or(0);

        let req_bytes = self
            .route_state
            .build_sync_route_info_request(
                group_key,
                target_peer_id,
                server_session_id,
                ctx.we_are_initiator,
                force_full,
            )
            .ok()?;

        // Build RpcRequest
        let rpc_request = RpcRequest {
            descriptor: None,
            request: req_bytes,
            timeout_ms: 5000,
        };
        let rpc_request_bytes = codec::encode_rpc_request(&rpc_request);

        // Build transaction ID
        let transaction_id: u32 = random_u64_string()
            .parse::<u64>()
            .unwrap_or(0)
            .wrapping_mul(1) as u32;

        // Build RpcPacket
        let rpc_packet = RpcPacket {
            from_peer: MY_PEER_ID,
            to_peer: target_peer_id,
            transaction_id: transaction_id as i64,
            descriptor: Some(RpcDescriptor {
                domain_name: ctx.domain_name.clone(),
                proto_name: "OspfRouteRpc".to_string(),
                service_name: "OspfRouteRpc".to_string(),
                method_index: 1,
            }),
            body: rpc_request_bytes,
            is_request: true,
            total_pieces: 1,
            piece_idx: 0,
            trace_id: 0,
            compression_info: Some(crate::proto::common::RpcCompressionInfo {
                algo: 1,
                accepted_algo: 1,
            }),
        };

        Some(codec::encode_rpc_packet(&rpc_packet))
    }

    /// Handle an incoming SyncRouteInfoRequest and produce response bytes.
    pub fn handle_sync_route_info(
        &mut self,
        group_key: &str,
        from_peer_id: u32,
        request_bytes: &[u8],
    ) -> Option<Vec<u8>> {
        self.route_state
            .handle_sync_route_info_request(group_key, from_peer_id, request_bytes)
            .ok()
    }

    /// Process peer infos from an incoming SyncRouteInfo request.
    /// Updates local peer info store and returns whether new peers were discovered.
    pub fn process_incoming_peer_infos(
        &mut self,
        group_key: &str,
        from_peer_id: u32,
        request_bytes: &[u8],
    ) -> Result<bool, String> {
        let req = SyncRouteInfoRequest::decode(request_bytes)
            .map_err(|e| format!("decode SyncRouteInfoRequest: {}", e))?;

        let mut has_new = false;
        if let Some(infos) = &req.peer_infos {
            for info in &infos.items {
                if info.peer_id != MY_PEER_ID {
                    let existing = self.route_state.get_peer_ids_in_group(group_key);
                    let is_new = !existing.contains(&info.peer_id);
                    let info_bytes = codec::encode_route_peer_info(info);
                    self.route_state
                        .update_peer_info(group_key, info.peer_id, &info_bytes)
                        .ok();
                    if is_new {
                        has_new = true;
                    }
                } else {
                    let info_bytes = codec::encode_route_peer_info(info);
                    self.route_state
                        .update_peer_info(group_key, info.peer_id, &info_bytes)
                        .ok();
                }
            }
        }

        Ok(has_new)
    }
}

// ── Global singleton that survives DO hibernation via WASM linear memory ──

/// All DO-level state that must survive hibernation.
/// Lives in WASM linear memory as a thread_local, analogous to JS module-scope singletons.
pub(crate) struct GlobalStateInner {
    pub peer_manager: PeerManager,
    pub peer_center_map: HashMap<String, PeerCenter>,
    pub network_digest_registry: HashMap<String, String>,
}

thread_local! {
    static GLOBAL_STATE: RefCell<Option<GlobalStateInner>> = RefCell::new(None);
}

/// Get or initialize the global state, then run the closure with a mutable reference.
/// On first call (or after isolate restart), state is freshly created.
/// On DO hibernation wakeup, the existing state survives via WASM memory snapshot.
pub(crate) fn with_global_state<F, R>(f: F) -> R
where
    F: FnOnce(&mut GlobalStateInner) -> R,
{
    GLOBAL_STATE.with(|cell| {
        let mut opt = cell.borrow_mut();
        if opt.is_none() {
            *opt = Some(GlobalStateInner {
                peer_manager: PeerManager::new(),
                peer_center_map: HashMap::new(),
                network_digest_registry: HashMap::new(),
            });
        }
        f(opt.as_mut().unwrap())
    })
}
