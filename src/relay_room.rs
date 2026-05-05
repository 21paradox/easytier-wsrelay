use serde::{Deserialize, Serialize};
use worker::*;

use crate::codec;
use crate::constants::{PacketType, HEADER_SIZE, MY_PEER_ID};
use crate::crypto::{random_u64_string, wrap_packet, WsCrypto};
use crate::handlers;
use crate::packet::{parse_header, create_header};
use crate::peer_manager::{self, WsPeerContext};
use crate::rpc_handler::{self, RpcAction};

const CLEANUP_INTERVAL_MS: u64 = 30_000;
const SOCKET_TIMEOUT_MS: u64 = 120_000;

/// Attachment data stored on each WebSocket for hibernation recovery.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct WsAttachment {
    peer_id: u32,
    group_key: String,
    domain_name: String,
    server_session_id: String,
    #[serde(default)]
    we_are_initiator: bool,
    /// Last time (in millis since epoch) any message was received on this socket.
    #[serde(default)]
    last_seen_ms: i64,
}

/// Convert attachment to WsPeerContext.
fn attachment_to_ctx(att: &WsAttachment) -> WsPeerContext {
    WsPeerContext {
        peer_id: att.peer_id,
        group_key: att.group_key.clone(),
        domain_name: if att.domain_name.is_empty() {
            "public_server".to_string()
        } else {
            att.domain_name.clone()
        },
        server_session_id: if att.server_session_id.is_empty() {
            random_u64_string()
        } else {
            att.server_session_id.clone()
        },
        we_are_initiator: att.we_are_initiator,
    }
}

#[durable_object]
pub struct RelayRoom {
    state: State,
    env: Env,
}

impl DurableObject for RelayRoom {
    fn new(state: State, env: Env) -> Self {
        // Ensure peers from existing sockets are tracked in the global state.
        // - First creation / isolate restart: global PeerManager is fresh, add all peers.
        // - DO hibernation wakeup: peers already present in global state, this is a no-op.
        let sockets = state.get_websockets();
        peer_manager::with_global_state(|gs| {
            for ws in &sockets {
                if let Ok(Some(att)) = ws.deserialize_attachment::<WsAttachment>() {
                    if att.peer_id != 0 {
                        let existing = gs.peer_manager.list_peer_ids_in_group(&att.group_key);
                        if !existing.contains(&att.peer_id) {
                            gs.peer_manager.add_peer(&att.group_key, att.peer_id);
                        }
                    }
                }
            }
        });

        RelayRoom { state, env }
    }

    async fn fetch(&self, req: Request) -> Result<Response> {
        let url = req.url()?;

        // Verify it's a websocket upgrade request
        let upgrade_header = req.headers().get("Upgrade")?;
        if upgrade_header.as_deref() != Some("websocket") {
            return Response::error("Expected websocket", 400);
        }

        let pair = WebSocketPair::new()?;
        let server = pair.server;
        let client = pair.client;

        // Accept with WebSocket Hibernation API
        self.state.accept_web_socket(&server);

        // Initialize socket metadata
        let att = WsAttachment {
            peer_id: 0,
            group_key: String::new(),
            domain_name: String::new(),
            server_session_id: random_u64_string(),
            we_are_initiator: false,
            last_seen_ms: Date::now().as_millis() as i64,
        };
        server.serialize_attachment(&att)?;

        web_sys::console::log_1(&"[RelayRoom] new websocket connection".into());

        // Schedule cleanup alarm if not already set
        self.schedule_cleanup_alarm().await;

        Ok(ResponseBuilder::new()
            .with_status(101)
            .with_websocket(client)
            .empty())
    }

    async fn alarm(&self) -> Result<Response> {
        let now = Date::now().as_millis() as i64;

        let sockets = self.state.get_websockets();
        let mut alive_count = 0;
        let mut group_keys: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();

        for ws in &sockets {
            match ws.deserialize_attachment::<WsAttachment>() {
                Ok(Some(att)) if att.last_seen_ms > 0 => {
                    let elapsed = now.saturating_sub(att.last_seen_ms);
                    if elapsed as u64 > SOCKET_TIMEOUT_MS {
                        web_sys::console::warn_1(
                            &format!(
                                "[cleanup] closing dead socket peer_id={} last_seen_ago={}ms",
                                att.peer_id, elapsed
                            )
                            .into(),
                        );
                        // Close the timed-out socket; this triggers websocket_close
                        let _ = ws.close(Some(1001), Some("timeout"));
                        continue;
                    }
                    if !att.group_key.is_empty() {
                        group_keys.insert(att.group_key.clone());
                    }
                }
                _ => {}
            }
            alive_count += 1;
        }

        // Re-arm alarm if there are still websockets
        if alive_count > 0 {
            self.schedule_cleanup_alarm().await;

            // Clean up stale P2P connections for peers disconnected > 10 min.
            // Mirrors official easytier's clear_expired_peer pattern.
            const STALE_P2P_THRESHOLD_MS: u64 = 600_000; // 10 minutes
            for group_key in &group_keys {
                peer_manager::with_global_state(|gs| {
                    gs.peer_manager.cleanup_stale_peer_connections(
                        group_key,
                        STALE_P2P_THRESHOLD_MS,
                    );
                });
            }

            // Periodic route refresh: broadcast to all peers to keep their
            // RoutePeerInfo.last_update fresh. Without this, clients will
            // expire idle peers after REMOVE_DEAD_PEER_INFO_AFTER (~1 hour).
            for group_key in &group_keys {
                web_sys::console::log_1(
                    &format!("[RelayRoom] alarm: periodic route refresh for group={}", group_key).into(),
                );
                if let Err(e) = self.broadcast_route_update(group_key, 0) {
                    web_sys::console::error_1(
                        &format!("[RelayRoom] alarm: broadcast failed: {:?}", e).into(),
                    );
                }
            }
        }

        web_sys::console::log_1(&format!("[RelayRoom] alarm: {} sockets alive", alive_count).into());
        Response::ok("ok")
    }

    async fn websocket_message(
        &self,
        ws: WebSocket,
        message: WebSocketIncomingMessage,
    ) -> Result<()> {
        let bytes = match message {
            WebSocketIncomingMessage::Binary(data) => data,
            WebSocketIncomingMessage::String(_) => {
                web_sys::console::warn_1(&"[ws] received text message, expected binary".into());
                return Ok(());
            }
        };

        if bytes.len() < HEADER_SIZE {
            web_sys::console::warn_1(&format!("[ws] message too short: {} bytes", bytes.len()).into());
            return Ok(());
        }

        web_sys::console::log_1(&format!("[ws] recv len={}", bytes.len()).into());

        // Parse header
        let header = match parse_header(&bytes) {
            Some(h) => h,
            None => {
                web_sys::console::error_1(&format!("[ws] parseHeader failed, raw hex={}", hex::encode(&bytes)).into());
                return Ok(());
            }
        };

        web_sys::console::log_1(
            &format!(
                "[ws] header from={} to={} type={} len={}",
                header.from_peer_id, header.to_peer_id, header.packet_type, header.len
            )
            .into(),
        );

        let payload = &bytes[HEADER_SIZE..];
        let packet_type = header.packet_type_enum();

        // Get current attachment
        let mut att: WsAttachment = ws.deserialize_attachment()?.unwrap_or_default();

        // Update last_seen on every message to track socket liveness
        att.last_seen_ms = Date::now().as_millis() as i64;

        match packet_type {
            PacketType::HandShake => {
                web_sys::console::log_1(&format!("[ws] -> handleHandshake").into());

                let outcome = peer_manager::with_global_state(|gs| {
                    handlers::handle_handshake(
                        payload,
                        &mut gs.network_digest_registry,
                    )
                });

                if let Some(outcome) = outcome {
                    // Update attachment
                    att.peer_id = outcome.peer_id;
                    att.group_key = outcome.group_key.clone();
                    att.domain_name = outcome.domain_name.clone();
                    att.we_are_initiator = false;
                    ws.serialize_attachment(&att)?;

                    // Add peer to manager + update peer info
                    peer_manager::with_global_state(|gs| {
                        gs.peer_manager.add_peer(&outcome.group_key, outcome.peer_id);

                        let peer_info = crate::proto::peer_rpc::RoutePeerInfo {
                            peer_id: outcome.peer_id,
                            version: 1,
                            last_update: Some(crate::proto::Timestamp {
                                seconds: (Date::now().as_millis() / 1000) as i64,
                                nanos: 0,
                            }),
                            inst_id: Some(crate::proto::common::Uuid {
                                part1: 0, part2: 0, part3: 0, part4: 0,
                            }),
                            network_length: 24,
                            ..Default::default()
                        };
                        let peer_info_bytes = codec::encode_route_peer_info(&peer_info);
                        gs.peer_manager.update_peer_info(
                            &outcome.group_key,
                            outcome.peer_id,
                            &peer_info_bytes,
                        );
                        gs.peer_manager.route_state.bump_my_info_version(&outcome.group_key);
                    });

                    // Send handshake response
                    ws.send_with_bytes(&outcome.response_bytes)?;

                    // Broadcast route update to all other peers in the same group
                    {
                        let group_key = outcome.group_key.clone();
                        let peer_id = outcome.peer_id;
                        if let Err(e) = self.broadcast_route_update(&group_key, peer_id) {
                            web_sys::console::error_1(
                                &format!("Broadcast after handshake failed for {}: {:?}", peer_id, e).into(),
                            );
                        }
                    }

                    // Push initial route update to the new peer
                    {
                        let ctx = attachment_to_ctx(&att);
                        let route_update = peer_manager::with_global_state(|gs| {
                            gs.peer_manager.build_route_update(&ctx, att.peer_id, true)
                        });
                        if let Some(rpc_bytes) = route_update {
                            web_sys::console::log_1(&format!("[ws] HandShake -> pushing initial route update to peer={}", att.peer_id).into());
                            let crypto = WsCrypto::default();
                            match wrap_packet(MY_PEER_ID, att.peer_id, PacketType::RpcReq, &rpc_bytes, &crypto).await {
                                Ok(packet) => { ws.send_with_bytes(&packet)?; }
                                Err(e) => { web_sys::console::error_1(&format!("initial route update wrap_packet failed: {}", e).into()); }
                            }
                        }
                    }
                } else {
                    // Handshake failed (invalid magic or digest mismatch) — close the connection
                    web_sys::console::warn_1(&format!("[ws] HandShake failed for peer, closing connection").into());
                    let _ = ws.close(Some(1001), Some("handshake failed"));
                }
            }

            PacketType::Ping => {
                let response = handlers::handle_ping(header.from_peer_id, payload);
                ws.send_with_bytes(&response)?;
            }

            PacketType::RpcReq => {
                if header.to_peer_id == 0 || header.to_peer_id == MY_PEER_ID {
                    // Handle locally
                    let ctx = attachment_to_ctx(&att);
                    let actions = peer_manager::with_global_state(|gs| {
                        let mut ctx_mut = ctx.clone();
                        rpc_handler::handle_rpc_req(
                            &mut ctx_mut,
                            &mut gs.peer_manager,
                            &mut gs.peer_center_map,
                            payload,
                        )
                    });

                    if actions.is_empty() {
                        web_sys::console::warn_1(&format!("[ws] RpcReq -> handle_rpc_req returned no action (peer_id={} group_key={})", att.peer_id, att.group_key).into());
                    }

                    for action in actions {
                        match action {
                            RpcAction::SendTo { peer_id: _, bytes } => {
                                web_sys::console::log_1(&format!("[ws] RpcReq -> sending RpcResp len={}", bytes.len()).into());
                                let crypto = WsCrypto::default();
                                match wrap_packet(MY_PEER_ID, att.peer_id, PacketType::RpcResp, &bytes, &crypto).await {
                                    Ok(packet) => { ws.send_with_bytes(&packet)?; }
                                    Err(e) => { web_sys::console::error_1(&format!("wrap_packet failed: {}", e).into()); }
                                }
                            }
                            RpcAction::PushRouteUpdate { peer_id, group_key: _ } => {
                                web_sys::console::log_1(&format!("[ws] RpcReq -> pushing route update to peer={}", peer_id).into());
                                let route_update = peer_manager::with_global_state(|gs| {
                                    let ctx = attachment_to_ctx(&att);
                                    gs.peer_manager.build_route_update(&ctx, peer_id, true)
                                });
                                if let Some(rpc_bytes) = route_update {
                                    let crypto = WsCrypto::default();
                                    match wrap_packet(MY_PEER_ID, peer_id, PacketType::RpcReq, &rpc_bytes, &crypto).await {
                                        Ok(packet) => { ws.send_with_bytes(&packet)?; }
                                        Err(e) => { web_sys::console::error_1(&format!("pushRouteUpdate wrap_packet failed: {}", e).into()); }
                                    }
                                }
                            }
                            RpcAction::BroadcastRouteUpdate { group_key, exclude_peer_id } => {
                                web_sys::console::log_1(&format!("[ws] RpcReq -> broadcasting route update to group={} exclude={}", group_key, exclude_peer_id).into());
                                if let Err(e) = self.broadcast_route_update(&group_key, exclude_peer_id) {
                                    web_sys::console::error_1(&format!("broadcastRouteUpdate failed: {:?}", e).into());
                                }
                            }
                            _ => {}
                        }
                    }
                } else {
                    // Forward
                    self.forward_message(&ws, &header, &bytes, &att)?;
                }
            }

            PacketType::RpcResp => {
                if header.to_peer_id == 0 || header.to_peer_id == MY_PEER_ID {
                    // Handle locally
                    let ctx = attachment_to_ctx(&att);
                    let mut ctx_mut = ctx.clone();
                    let _action = peer_manager::with_global_state(|gs| {
                        rpc_handler::handle_rpc_resp(
                            &mut ctx_mut,
                            &mut gs.peer_manager,
                            header.from_peer_id,
                            payload,
                        )
                    });
                } else {
                    // Forward
                    self.forward_message(&ws, &header, &bytes, &att)?;
                }
            }

            PacketType::Data | _ => {
                self.forward_message(&ws, &header, &bytes, &att)?;
            }
        }

        // Update attachment after processing
        ws.serialize_attachment(&att)?;

        Ok(())
    }

    async fn websocket_close(
        &self,
        ws: WebSocket,
        _code: usize,
        _reason: String,
        _was_clean: bool,
    ) -> Result<()> {
        if let Ok(Some(att)) = ws.deserialize_attachment::<WsAttachment>() {
            if att.peer_id != 0 {
                let ctx = attachment_to_ctx(&att);
                peer_manager::with_global_state(|gs| {
                    gs.peer_manager.remove_peer(&ctx);
                });
                self.broadcast_route_update(&att.group_key, att.peer_id)?;
            }
        }
        Ok(())
    }

    async fn websocket_error(&self, ws: WebSocket, _error: Error) -> Result<()> {
        // Delegate to close handling
        if let Ok(Some(att)) = ws.deserialize_attachment::<WsAttachment>() {
            if att.peer_id != 0 {
                let ctx = attachment_to_ctx(&att);
                peer_manager::with_global_state(|gs| {
                    gs.peer_manager.remove_peer(&ctx);
                });
                self.broadcast_route_update(&att.group_key, att.peer_id)?;
            }
        }
        Ok(())
    }
}

impl RelayRoom {
    /// Forward a message from source to target peer.
    fn forward_message(
        &self,
        source_ws: &WebSocket,
        header: &crate::packet::PacketHeader,
        full_message: &[u8],
        _source_att: &WsAttachment,
    ) -> Result<()> {
        let target_peer_id = header.to_peer_id;
        let sockets = self.state.get_websockets();

        for target_ws in &sockets {
            if let Ok(Some(att)) = target_ws.deserialize_attachment::<WsAttachment>() {
                if att.peer_id == target_peer_id {
                    // Check group key match
                    if let Ok(Some(src_att)) = source_ws.deserialize_attachment::<WsAttachment>() {
                        if !src_att.group_key.is_empty()
                            && !att.group_key.is_empty()
                            && src_att.group_key != att.group_key
                        {
                            return Ok(());
                        }
                    }

                    target_ws.send_with_bytes(full_message)?;
                    return Ok(());
                }
            }
        }

        Ok(())
    }

    /// Broadcast a route update to all peers in the same group.
    fn broadcast_route_update(
        &self,
        group_key: &str,
        exclude_peer_id: u32,
    ) -> Result<()> {
        let sockets = self.state.get_websockets();

        for ws in &sockets {
            if let Ok(Some(att)) = ws.deserialize_attachment::<WsAttachment>() {
                if att.peer_id == exclude_peer_id {
                    continue;
                }
                if att.group_key != group_key {
                    continue;
                }

                let ctx = attachment_to_ctx(&att);
                let route_update = peer_manager::with_global_state(|gs| {
                    gs.peer_manager.build_route_update(&ctx, att.peer_id, true)
                });

                if let Some(rpc_bytes) = route_update {
                    let header = create_header(MY_PEER_ID, att.peer_id, PacketType::RpcReq, rpc_bytes.len() as u32);
                    let mut packet = header;
                    packet.extend_from_slice(&rpc_bytes);
                    if let Err(e) = ws.send_with_bytes(&packet) {
                        web_sys::console::error_1(
                            &format!("broadcastRouteUpdate send failed: {:?}", e).into(),
                        );
                    }
                }
            }
        }

        Ok(())
    }

    /// Schedule a cleanup alarm if not already set.
    async fn schedule_cleanup_alarm(&self) {
        let alarm = self.state.storage().get_alarm().await;
        if alarm.ok().flatten().is_none() {
            let schedule_time = Date::now().as_millis() as i64 + CLEANUP_INTERVAL_MS as i64;
            let _ = self.state.storage().set_alarm(schedule_time).await;
        }
    }
}
