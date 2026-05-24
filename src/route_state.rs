use std::collections::{BTreeSet, HashMap};

use prost::Message;

use crate::proto::peer_rpc::{
    route_foreign_network_infos, ForeignNetworkRouteInfoEntry, ForeignNetworkRouteInfoKey, PeerIdVersion,
    RouteConnBitmap, RouteForeignNetworkInfos, RoutePeerInfo, RoutePeerInfos, SyncRouteInfoRequest,
    SyncRouteInfoResponse,
};

pub type PeerId = u32;
pub type Version = u32;
pub type SessionId = u64;

const MY_PEER_ID: PeerId = 10000001;

#[derive(Debug, Clone, Default)]
struct SessionState {
    my_session_id: Option<SessionId>,
    dst_session_id: Option<SessionId>,
    we_are_initiator: bool,
    peer_info_ver_map: HashMap<PeerId, Version>,
    conn_bitmap_ver_map: HashMap<PeerId, Version>,
    foreign_net_ver: u32,
    last_touch_ms: u64,
    last_conn_bitmap_sig: Option<String>,
}

#[derive(Debug, Clone, Default)]
struct RouteGroupData {
    peers: BTreeSet<PeerId>,
    peer_infos: HashMap<PeerId, RoutePeerInfo>,
    sessions: HashMap<PeerId, SessionState>,
    peer_conn_versions: HashMap<PeerId, Version>,
    my_info: RoutePeerInfo,
    my_info_version: Version,
    /// Per-peer P2P connections reported via SyncRouteInfo conn_info.
    /// Maps peer_id -> set of peer_ids it is directly connected to (excluding server).
    peer_connections: HashMap<PeerId, BTreeSet<PeerId>>,
    /// Timestamp (ms) when each peer was last removed from g.peers.
    /// Used to clean up stale peer_connections entries.
    peer_removed_at: HashMap<PeerId, u64>,
}

/// Route state manager.
/// Mirrors logic from easytier/src/peers/peer_ospf_route.rs and JS peer_manager.js.
#[derive(Default)]
pub struct RouteState {
    groups: HashMap<String, RouteGroupData>,
}

impl RouteState {
    pub fn new() -> Self {
        RouteState { groups: HashMap::new() }
    }

    fn now_ms() -> u64 {
        worker::Date::now().as_millis()
    }

    fn random_bytes_8() -> Vec<u8> {
        let mut buf = vec![0u8; 8];
        getrandom::getrandom(&mut buf).expect("getrandom failed");
        buf
    }

    fn random_u32() -> u32 {
        let bytes = Self::random_bytes_8();
        u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
    }

    fn random_u64() -> u64 {
        let bytes = Self::random_bytes_8();
        u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ])
    }

    fn random_uuid() -> crate::proto::common::Uuid {
        crate::proto::common::Uuid {
            part1: Self::random_u32(),
            part2: Self::random_u32(),
            part3: Self::random_u32(),
            part4: Self::random_u32(),
        }
    }

    fn ensure_group(&mut self, group_key: &str) -> &mut RouteGroupData {
        self.groups.entry(group_key.to_string()).or_insert_with(|| {
            let mut my_info = RoutePeerInfo::default();
            my_info.peer_id = MY_PEER_ID;
            my_info.inst_id = Some(Self::random_uuid());
            my_info.cost = 1;
            my_info.version = 1;
            my_info.network_length = 24;
            my_info.easytier_version = "cf-easytier-wsrelay".to_string();
            my_info.hostname = Some("cf-easytier-wsrelay".to_string());
            my_info.peer_route_id = Self::random_u64();
            my_info.feature_flag = Some(crate::proto::common::PeerFeatureFlag {
                is_public_server: true,
                avoid_relay_data: true,
                kcp_input: false,
                no_relay_kcp: false,
                support_conn_list_sync: false,
                quic_input: false,
                no_relay_quic: false,
                is_credential_peer: false,
                need_p2p: true,
                disable_p2p: false,
                ipv6_public_addr_provider: false,
            });
            RouteGroupData {
                peers: BTreeSet::new(),
                peer_infos: HashMap::new(),
                sessions: HashMap::new(),
                peer_conn_versions: HashMap::new(),
                my_info,
                my_info_version: 1,
                peer_connections: HashMap::new(),
                peer_removed_at: HashMap::new(),
            }
        })
    }

    pub fn add_peer(&mut self, group_key: &str, peer_id: PeerId) {
        let g = self.ensure_group(group_key);
        let is_new = g.peers.insert(peer_id);
        // Peer is back online, clear removal timestamp
        g.peer_removed_at.remove(&peer_id);
        if is_new {
            Self::bump_all_conn_versions(g);
        }
    }

    pub fn remove_peer(&mut self, group_key: &str, peer_id: PeerId) {
        let g = self.ensure_group(group_key);
        let was_present = g.peers.remove(&peer_id);
        g.peer_infos.remove(&peer_id);
        g.sessions.remove(&peer_id);
        g.peer_conn_versions.remove(&peer_id);
        // Record removal time for stale P2P cleanup.
        // peer_connections is intentionally preserved across brief
        // reconnections so P2P topology survives WebSocket flaps.
        // Stale entries are cleaned up by cleanup_stale_peer_connections().
        g.peer_removed_at.insert(peer_id, Self::now_ms());
        if was_present {
            Self::bump_all_conn_versions(g);
        }
    }

    /// Update peer info from bytes. Returns true if the info actually changed
    /// (new peer or version increased), false if stale/unchanged.
    pub fn update_peer_info(&mut self, group_key: &str, peer_id: PeerId, info_bytes: &[u8]) -> Result<bool, String> {
        let info = RoutePeerInfo::decode(info_bytes).map_err(|e| format!("decode RoutePeerInfo failed: {}", e))?;
        let g = self.ensure_group(group_key);
        let old_version = g.peer_infos.get(&peer_id).map(|i| i.version);
        let is_new = old_version.is_none();
        let changed = old_version.map_or(true, |old| info.version > old);
        if changed {
            g.peer_infos.insert(peer_id, info);
            if is_new {
                Self::bump_all_conn_versions(g);
            }
        }
        Ok(changed)
    }

    pub fn on_route_session_ack(
        &mut self,
        group_key: &str,
        peer_id: PeerId,
        their_session_id: SessionId,
        we_are_initiator: bool,
    ) {
        let g = self.ensure_group(group_key);
        let s = g.sessions.entry(peer_id).or_default();
        if s.dst_session_id != Some(their_session_id) {
            s.peer_info_ver_map.clear();
            s.conn_bitmap_ver_map.clear();
            s.foreign_net_ver = 0;
            s.last_conn_bitmap_sig = None;
        }
        s.dst_session_id = Some(their_session_id);
        s.we_are_initiator = we_are_initiator;
        s.last_touch_ms = Self::now_ms();
    }

    /// Get the current connection version for a peer.
    /// Used to initialize RoutePeerInfo.version for reconnecting peers
    /// so the version is monotonically increasing.
    pub fn get_peer_conn_version(&self, group_key: &str, peer_id: PeerId) -> u32 {
        self.groups
            .get(group_key)
            .and_then(|g| g.peer_conn_versions.get(&peer_id))
            .copied()
            .unwrap_or(1)
    }

    pub fn get_peer_ids_in_group(&self, group_key: &str) -> Vec<PeerId> {
        self.groups
            .get(group_key)
            .map(|g| g.peers.iter().copied().collect())
            .unwrap_or_default()
    }

    pub fn bump_my_info_version(&mut self, group_key: &str) {
        let g = self.ensure_group(group_key);
        g.my_info_version += 1;
        g.my_info.version = g.my_info_version;
    }

    pub fn set_my_info_field(&mut self, group_key: &str, field: &str, value: &str) -> Result<(), String> {
        let g = self.ensure_group(group_key);
        match field {
            "hostname" => g.my_info.hostname = Some(value.to_string()),
            "network_length" => {
                g.my_info.network_length = value.parse().map_err(|_| "invalid network_length".to_string())?;
            }
            "ipv4_addr" => {
                let addr: u32 = value.parse().map_err(|_| "invalid ipv4_addr".to_string())?;
                g.my_info.ipv4_addr = Some(crate::proto::common::Ipv4Addr { addr });
            }
            _ => return Err("unknown field".to_string()),
        }
        g.my_info_version += 1;
        g.my_info.version = g.my_info_version;
        Ok(())
    }

    /// Process conn_info from an incoming SyncRouteInfoRequest.
    /// Extracts the sending peer's P2P connections and stores them so they
    /// can be included in future conn_bitmap broadcasts.
    /// Returns true if P2P connections were added/removed/changed.
    pub fn update_peer_connections_from_conn_info(
        &mut self,
        group_key: &str,
        from_peer_id: PeerId,
        request_bytes: &[u8],
    ) -> bool {
        let req = match SyncRouteInfoRequest::decode(request_bytes) {
            Ok(r) => r,
            Err(e) => {
                web_sys::console::warn_1(&format!("update_peer_connections: decode failed: {}", e).into());
                return false;
            }
        };

        let g = self.ensure_group(group_key);

        let p2p_connections: BTreeSet<PeerId> = match req.conn_info {
            Some(crate::proto::peer_rpc::sync_route_info_request::ConnInfo::ConnBitmap(ref bitmap)) => {
                web_sys::console::log_1(
                    &format!(
                        "[P2P] from_peer={} conn_info=ConnBitmap peer_count={}",
                        from_peer_id,
                        bitmap.peer_ids.len()
                    )
                    .into(),
                );
                // Find the row for from_peer_id in the bitmap
                if let Some(peer_idx) = bitmap.peer_ids.iter().position(|p| p.peer_id == from_peer_id) {
                    let all_connected = get_connected_peers_from_bitmap(bitmap, peer_idx);
                    web_sys::console::log_1(
                        &format!("[P2P] from_peer={} all_connected={:?}", from_peer_id, all_connected).into(),
                    );
                    all_connected
                        .into_iter()
                        .filter(|&p| p != MY_PEER_ID && p != from_peer_id && g.peers.contains(&p))
                        .collect()
                } else {
                    web_sys::console::warn_1(
                        &format!("[P2P] from_peer={} NOT FOUND in bitmap peer_ids", from_peer_id).into(),
                    );
                    BTreeSet::new()
                }
            }
            Some(crate::proto::peer_rpc::sync_route_info_request::ConnInfo::ConnPeerList(ref list)) => {
                web_sys::console::log_1(
                    &format!(
                        "[P2P] from_peer={} conn_info=ConnPeerList entry_count={}",
                        from_peer_id,
                        list.peer_conn_infos.len()
                    )
                    .into(),
                );
                // Find the entry for from_peer_id
                list.peer_conn_infos
                    .iter()
                    .find(|info| info.peer_id.as_ref().map(|p| p.peer_id) == Some(from_peer_id))
                    .map(|info| {
                        info.connected_peer_ids
                            .iter()
                            .copied()
                            .filter(|&p| p != MY_PEER_ID && p != from_peer_id && g.peers.contains(&p))
                            .collect()
                    })
                    .unwrap_or_default()
            }
            None => {
                web_sys::console::log_1(
                    &format!(
                        "[P2P] from_peer={} conn_info=None, keeping existing connections",
                        from_peer_id
                    )
                    .into(),
                );
                // Don't remove existing P2P connections on heartbeat syncs
                return false;
            }
        };

        let changed = if p2p_connections.is_empty() {
            g.peer_connections.remove(&from_peer_id).is_some()
        } else {
            let old = g.peer_connections.insert(from_peer_id, p2p_connections.clone());
            old.map(|o| o != g.peer_connections[&from_peer_id]).unwrap_or(true)
        };

        if changed {
            web_sys::console::log_1(
                &format!(
                    "[P2P] from_peer={} p2p_connections={:?} CHANGED, bumping versions",
                    from_peer_id, p2p_connections
                )
                .into(),
            );
            Self::bump_all_conn_versions(g);
        } else {
            web_sys::console::log_1(
                &format!(
                    "[P2P] from_peer={} p2p_connections={:?} unchanged",
                    from_peer_id, p2p_connections
                )
                .into(),
            );
        }

        changed
    }

    /// Build a SyncRouteInfoRequest payload to send to target_peer_id.
    pub fn build_sync_route_info_request(
        &mut self,
        group_key: &str,
        target_peer_id: PeerId,
        server_session_id: SessionId,
        we_are_initiator: bool,
        force_full: bool,
    ) -> Result<Vec<u8>, String> {
        let g = self.ensure_group(group_key);

        // Update session
        {
            let session = g.sessions.entry(target_peer_id).or_default();
            session.my_session_id = Some(server_session_id);
            session.last_touch_ms = Self::now_ms();
        }

        let force_full_local = {
            let session = g.sessions.get(&target_peer_id);
            force_full || session.map(|s| s.dst_session_id.is_none()).unwrap_or(true)
        };

        let mut all_peers: BTreeSet<PeerId> = g.peers.clone();
        all_peers.insert(MY_PEER_ID);
        all_peers.insert(target_peer_id);

        let mut relevant_peers = vec![MY_PEER_ID];
        for pid in all_peers.iter().filter(|&&p| p != MY_PEER_ID) {
            relevant_peers.push(*pid);
        }
        relevant_peers.sort();

        let default_net_len = g.my_info.network_length.max(1);

        let mut peer_infos_items = Vec::new();
        {
            let session = g.sessions.entry(target_peer_id).or_default();
            for pid in &relevant_peers {
                if *pid != MY_PEER_ID && !g.peer_infos.contains_key(pid) {
                    let stub = make_stub_peer_info(*pid, default_net_len);
                    g.peer_infos.insert(*pid, stub);
                }
                let info = if *pid == MY_PEER_ID {
                    &g.my_info
                } else {
                    &g.peer_infos[pid]
                };
                let version = info.version.max(1);
                let prev = if force_full_local {
                    0
                } else {
                    session.peer_info_ver_map.get(pid).copied().unwrap_or(0)
                };
                if force_full_local || version > prev {
                    peer_infos_items.push(info.clone());
                    session.peer_info_ver_map.insert(*pid, version);
                }
            }
        }

        let conn_bitmap = Self::build_conn_bitmap(g, &relevant_peers, target_peer_id);

        let foreign_network_infos = {
            let session = g.sessions.entry(target_peer_id).or_default();
            let version = session.foreign_net_ver + 1;
            session.foreign_net_ver = version;
            Some(RouteForeignNetworkInfos {
                infos: vec![route_foreign_network_infos::Info {
                    key: Some(ForeignNetworkRouteInfoKey {
                        peer_id: MY_PEER_ID,
                        network_name: "dev-websocket-relay".to_string(),
                    }),
                    value: Some(ForeignNetworkRouteInfoEntry {
                        foreign_peer_ids: all_peers.iter().copied().collect(),
                        last_update: Some(crate::proto::Timestamp {
                            seconds: (Self::now_ms() / 1000) as i64,
                            nanos: 0,
                        }),
                        version,
                        network_secret_digest: vec![0u8; 32],
                        my_peer_id_for_this_network: MY_PEER_ID,
                    }),
                }],
            })
        };

        let req = SyncRouteInfoRequest {
            my_peer_id: MY_PEER_ID,
            my_session_id: server_session_id,
            is_initiator: we_are_initiator,
            peer_infos: if peer_infos_items.is_empty() {
                None
            } else {
                Some(RoutePeerInfos {
                    items: peer_infos_items,
                })
            },
            conn_info: conn_bitmap.map(|c| crate::proto::peer_rpc::sync_route_info_request::ConnInfo::ConnBitmap(c)),
            foreign_network_infos,
        };

        Ok(prost::Message::encode_to_vec(&req))
    }

    /// Handle an incoming SyncRouteInfoRequest and produce a SyncRouteInfoResponse.
    pub fn handle_sync_route_info_request(
        &mut self,
        group_key: &str,
        from_peer_id: PeerId,
        request_bytes: &[u8],
    ) -> Result<Vec<u8>, String> {
        let req = SyncRouteInfoRequest::decode(request_bytes)
            .map_err(|e| format!("decode SyncRouteInfoRequest failed: {}", e))?;

        let g = self.ensure_group(group_key);

        {
            let session = g.sessions.entry(from_peer_id).or_default();
            session.last_touch_ms = Self::now_ms();
            let sid = req.my_session_id;
            if session.dst_session_id != Some(sid) {
                session.peer_info_ver_map.clear();
                session.conn_bitmap_ver_map.clear();
                session.foreign_net_ver = 0;
                session.last_conn_bitmap_sig = None;
            }
            session.dst_session_id = Some(sid);
            if req.is_initiator {
                session.we_are_initiator = false;
            }
        }

        if let Some(infos) = &req.peer_infos {
            let mut need_bump = false;
            for info in &infos.items {
                let is_connected = g.peers.contains(&info.peer_id) || info.peer_id == from_peer_id;
                if !is_connected {
                    continue;
                }
                let is_new = !g.peer_infos.contains_key(&info.peer_id);
                let mut info = info.clone();
                info.last_update = Some(crate::proto::Timestamp {
                    seconds: (Self::now_ms() / 1000) as i64,
                    nanos: 0,
                });
                g.peer_infos.insert(info.peer_id, info);
                if is_new {
                    need_bump = true;
                }
            }
            if need_bump {
                Self::bump_all_conn_versions(g);
            }
        }

        let server_session_id = {
            let session = g.sessions.get(&from_peer_id);
            session.and_then(|s| s.my_session_id).unwrap_or(1)
        };
        let resp = SyncRouteInfoResponse {
            is_initiator: !req.is_initiator,
            session_id: server_session_id,
            error: None,
        };

        Ok(prost::Message::encode_to_vec(&resp))
    }

    /// Clean up stale peer_connections entries for peers that have been
    /// disconnected for longer than `stale_threshold_ms`. This prevents
    /// unbounded memory growth from peers that leave permanently.
    /// Mirrors official easytier's clear_expired_peer pattern.
    pub fn cleanup_stale_peer_connections(&mut self, group_key: &str, stale_threshold_ms: u64) {
        let g = self.ensure_group(group_key);
        let now = Self::now_ms();
        let mut stale_peers: Vec<PeerId> = Vec::new();
        for (&peer_id, &removed_at) in &g.peer_removed_at {
            if now.saturating_sub(removed_at) > stale_threshold_ms {
                stale_peers.push(peer_id);
            }
        }
        for peer_id in &stale_peers {
            g.peer_connections.remove(peer_id);
            g.peer_removed_at.remove(peer_id);
            // Also remove this peer from other peers' connection sets
            for conns in g.peer_connections.values_mut() {
                conns.remove(peer_id);
            }
        }
        if !stale_peers.is_empty() {
            web_sys::console::log_1(
                &format!(
                    "[P2P] cleanup_stale: removed {} stale peer_connections: {:?}",
                    stale_peers.len(),
                    stale_peers
                )
                .into(),
            );
        }
    }


    // --- helpers ---

    fn bump_all_conn_versions(g: &mut RouteGroupData) {
        let all: BTreeSet<PeerId> = g.peers.iter().chain(g.peer_infos.keys()).copied().collect();
        for pid in all {
            let v = g.peer_conn_versions.get(&pid).copied().unwrap_or(1);
            g.peer_conn_versions.insert(pid, v + 1);
        }
        g.peer_conn_versions
            .entry(MY_PEER_ID)
            .and_modify(|v| *v += 1)
            .or_insert(2);
    }

    fn build_conn_bitmap(
        g: &mut RouteGroupData,
        relevant_peers: &[PeerId],
        target_peer_id: PeerId,
    ) -> Option<RouteConnBitmap> {
        if relevant_peers.is_empty() {
            return None;
        }
        let n = relevant_peers.len();
        let bitmap_size = (n * n + 7) / 8;
        let mut bitmap = vec![0u8; bitmap_size];

        let idx_by_peer: HashMap<PeerId, usize> = relevant_peers.iter().enumerate().map(|(i, p)| (*p, i)).collect();

        let set_bit = |bitmap: &mut [u8], row: usize, col: usize| {
            let idx = row * n + col;
            bitmap[idx / 8] |= 1 << (idx % 8);
        };

        for i in 0..n {
            set_bit(&mut bitmap, i, i);
        }

        if let Some(&server_idx) = idx_by_peer.get(&MY_PEER_ID) {
            for i in 0..n {
                if i == server_idx {
                    continue;
                }
                set_bit(&mut bitmap, server_idx, i);
                set_bit(&mut bitmap, i, server_idx);
            }

            // Add peer-to-peer P2P edges from stored connections (bidirectional)
            if !g.peer_connections.is_empty() {
                web_sys::console::log_1(
                    &format!(
                        "[P2P] build_conn_bitmap: peer_connections={:?} relevant_peers={:?}",
                        g.peer_connections, relevant_peers
                    )
                    .into(),
                );
            }
            for (src_peer, dst_peers) in &g.peer_connections {
                let Some(&src_idx) = idx_by_peer.get(src_peer) else {
                    continue;
                };
                for dst_peer in dst_peers {
                    let Some(&dst_idx) = idx_by_peer.get(dst_peer) else {
                        continue;
                    };
                    if src_idx != dst_idx && src_idx != server_idx && dst_idx != server_idx {
                        set_bit(&mut bitmap, src_idx, dst_idx);
                        set_bit(&mut bitmap, dst_idx, src_idx);
                    }
                }
            }
        } else {
            for i in 0..n {
                for j in 0..n {
                    set_bit(&mut bitmap, i, j);
                }
            }
        }

        let peer_id_versions: Vec<PeerIdVersion> = relevant_peers
            .iter()
            .map(|pid| {
                let version = g.peer_conn_versions.get(pid).copied().unwrap_or(1);
                PeerIdVersion { peer_id: *pid, version }
            })
            .collect();

        let sig = format!(
            "{}|{}",
            peer_id_versions
                .iter()
                .map(|p| format!("{}:{}", p.peer_id, p.version))
                .collect::<Vec<_>>()
                .join(","),
            hex::encode(&bitmap)
        );

        let session = g.sessions.entry(target_peer_id).or_default();
        let conn_version = session.conn_bitmap_ver_map.get(&target_peer_id).copied().unwrap_or(0);
        let next_conn_version = if conn_version == 0 {
            peer_id_versions.iter().map(|p| p.version).max().unwrap_or(1)
        } else {
            conn_version
        };

        if session.last_conn_bitmap_sig.as_deref() == Some(&sig) {
            return None;
        }

        session.conn_bitmap_ver_map.insert(target_peer_id, next_conn_version);
        session.last_conn_bitmap_sig = Some(sig);

        Some(RouteConnBitmap {
            peer_ids: peer_id_versions,
            bitmap,
        })
    }
}

/// Parse a RouteConnBitmap and extract the set of peer IDs connected to the peer at `peer_idx`.
fn get_connected_peers_from_bitmap(bitmap: &RouteConnBitmap, peer_idx: usize) -> BTreeSet<PeerId> {
    let n = bitmap.peer_ids.len();
    let mut connected = BTreeSet::new();
    for (idx, pid_ver) in bitmap.peer_ids.iter().enumerate() {
        let bit_idx = peer_idx * n + idx;
        let byte_idx = bit_idx / 8;
        let bit_offset = bit_idx % 8;
        if byte_idx < bitmap.bitmap.len() && (bitmap.bitmap[byte_idx] >> bit_offset) & 1 == 1 {
            connected.insert(pid_ver.peer_id);
        }
    }
    connected
}

fn make_stub_peer_info(peer_id: PeerId, network_length: u32) -> RoutePeerInfo {
    RoutePeerInfo {
        peer_id,
        version: 1,
        last_update: Some(crate::proto::Timestamp {
            seconds: (worker::Date::now().as_millis() as i64) / 1000,
            nanos: 0,
        }),
        inst_id: Some(crate::proto::common::Uuid {
            part1: 0,
            part2: 0,
            part3: 0,
            part4: 0,
        }),
        cost: 1,
        hostname: None,
        easytier_version: "cf-2.6".to_string(),
        feature_flag: None,
        network_length,
        peer_route_id: 0,
        groups: vec![],
        ..Default::default()
    }
}
