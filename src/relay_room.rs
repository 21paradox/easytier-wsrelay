use std::cell::RefCell;
use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use worker::*;

use crate::codec;
use crate::compress;
use crate::constants::{PacketType, HEADER_SIZE, MY_PEER_ID};
use crate::crypto::{random_u64_string, wrap_packet, WsCrypto};
use crate::handlers;
use crate::packet::parse_header;
use crate::peer_center::PeerCenter;
use crate::peer_manager::{PeerManager, WsPeerContext};
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
    peer_manager: RefCell<PeerManager>,
    peer_center_map: RefCell<HashMap<String, PeerCenter>>,
    network_digest_registry: RefCell<HashMap<String, String>>,
    state: State,
    env: Env,
}

impl DurableObject for RelayRoom {
    fn new(state: State, env: Env) -> Self {
        // Restore socket attachments after hibernation
        let sockets = state.get_websockets();
        let mut peer_mgr = PeerManager::new();
        for ws in &sockets {
            if let Ok(Some(att)) = ws.deserialize_attachment::<WsAttachment>() {
                if att.peer_id != 0 {
                    peer_mgr.add_peer(&att.group_key, att.peer_id);
                }
            }
        }

        RelayRoom {
            peer_manager: RefCell::new(peer_mgr),
            peer_center_map: RefCell::new(HashMap::new()),
            network_digest_registry: RefCell::new(HashMap::new()),
            state,
            env,
        }
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
        let now = Date::now().as_millis();

        let sockets = self.state.get_websockets();
        let mut alive_count = 0;

        for ws in &sockets {
            // Check attachment last_seen via deserialization
            // Since we don't have a direct last_seen field on the attachment,
            // we'll rely on the WebSocket state instead.
            // The WebSocket Hibernation API automatically closes dead sockets,
            // so just check which are still open.
            alive_count += 1;
        }

        // Re-arm alarm if there are still websockets
        if alive_count > 0 {
            self.schedule_cleanup_alarm().await;
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

        match packet_type {
            PacketType::HandShake => {
                web_sys::console::log_1(&format!("[ws] -> handleHandshake").into());

                let outcome = handlers::handle_handshake(
                    payload,
                    &mut self.network_digest_registry.borrow_mut(),
                );

                if let Some(outcome) = outcome {
                    // Update attachment
                    att.peer_id = outcome.peer_id;
                    att.group_key = outcome.group_key.clone();
                    att.domain_name = outcome.domain_name.clone();
                    att.we_are_initiator = false;
                    ws.serialize_attachment(&att)?;

                    // Add peer to manager
                    self.peer_manager.borrow_mut().add_peer(&outcome.group_key, outcome.peer_id);

                    // Update peer info
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
                    self.peer_manager.borrow_mut().update_peer_info(
                        &outcome.group_key,
                        outcome.peer_id,
                        &peer_info_bytes,
                    );
                    self.peer_manager.borrow_mut().route_state.bump_my_info_version(&outcome.group_key);

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

                    // Push initial route update to the new peer (after a short delay via alarm)
                    // This is handled by the client's next route sync request.
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
                    let action = {
                        let mut ctx_mut = ctx.clone();
                        let mut pm = self.peer_manager.borrow_mut();
                        let mut pcm = self.peer_center_map.borrow_mut();
                        rpc_handler::handle_rpc_req(
                            &mut ctx_mut,
                            &mut pm,
                            &mut pcm,
                            payload,
                        )
                    };

                    if let Some(RpcAction::SendTo { peer_id: _, bytes }) = action {
                        let crypto = WsCrypto::default();
                        match wrap_packet(MY_PEER_ID, att.peer_id, PacketType::RpcResp, &bytes, &crypto).await {
                            Ok(packet) => { ws.send_with_bytes(&packet)?; }
                            Err(e) => { web_sys::console::error_1(&format!("wrap_packet failed: {}", e).into()); }
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
                    let mut pm = self.peer_manager.borrow_mut();
                    let _action = rpc_handler::handle_rpc_resp(
                        &mut ctx_mut,
                        &mut pm,
                        header.from_peer_id,
                        payload,
                    );
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
                self.peer_manager.borrow_mut().remove_peer(&ctx);
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
                self.peer_manager.borrow_mut().remove_peer(&ctx);
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
                let route_update = {
                    let mut pm = self.peer_manager.borrow_mut();
                    pm.build_route_update(&ctx, att.peer_id, true)
                };

                if let Some(rpc_bytes) = route_update {
                    let ws_clone = ws.clone();
                    let peer_id = att.peer_id;
                    wasm_bindgen_futures::spawn_local(async move {
                        let crypto = WsCrypto::default();
                        match wrap_packet(MY_PEER_ID, peer_id, PacketType::RpcReq, &rpc_bytes, &crypto).await {
                            Ok(packet) => {
                                let _ = ws_clone.send_with_bytes(&packet);
                            }
                            Err(e) => {
                                web_sys::console::error_1(
                                    &format!("broadcastRouteUpdate wrap_packet failed: {}", e).into(),
                                );
                            }
                        }
                    });
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
