use crate::codec;
use crate::constants::{PacketType, MAGIC, MY_PEER_ID, VERSION};
use crate::packet::create_header;
use crate::route_state::PeerId;

/// Outcome of a handshake: the response bytes to send back.
#[derive(Debug)]
pub struct HandshakeOutcome {
    /// The peer_id assigned to this websocket.
    pub peer_id: PeerId,
    /// The group key (network_name:digest_hex).
    pub group_key: String,
    /// The domain (network) name.
    pub domain_name: String,
    /// Full response packet bytes (header + body) to send back to client.
    pub response_bytes: Vec<u8>,
}

/// Handle a handshake request from a client.
/// Returns Some(HandshakeOutcome) on success, None if the connection should be closed.
pub fn handle_handshake(
    payload: &[u8],
    network_digest_registry: &mut std::collections::HashMap<String, String>,
) -> Option<HandshakeOutcome> {
    let req = codec::decode_handshake_request(payload).ok()?;

    if req.magic != MAGIC {
        web_sys::console::error_1(&"Invalid magic".into());
        return None;
    }

    let client_network_name = req.network_name.clone();
    let client_digest = hex::encode(&req.network_secret_digest);

    // Check digest consistency for this network name
    let existing_digest = network_digest_registry.get(&client_network_name);
    if let Some(existing) = existing_digest {
        if *existing != client_digest {
            web_sys::console::error_1(
                &format!(
                    "Rejecting handshake from {}: digest mismatch for network \"{}\" (existing={}, incoming={})",
                    req.my_peer_id, client_network_name, existing, client_digest
                )
                .into(),
            );
            return None;
        }
    } else {
        network_digest_registry.insert(client_network_name.clone(), client_digest.clone());
    }

    let group_digest = network_digest_registry
        .get(&client_network_name)
        .cloned()
        .unwrap_or_default();
    let group_key = format!("{}:{}", client_network_name, group_digest);

    // Build handshake response
    let resp_payload = crate::proto::peer_rpc::HandshakeRequest {
        magic: MAGIC,
        my_peer_id: MY_PEER_ID,
        version: VERSION,
        features: vec!["node-server-v1".to_string()],
        network_name: "public_server".to_string(),
        network_secret_digest: vec![0u8; 32],
        ..Default::default()
    };

    let resp_bytes = codec::encode_handshake_request(&resp_payload);
    let resp_header = create_header(MY_PEER_ID, req.my_peer_id, PacketType::HandShake, resp_bytes.len() as u32);

    let mut full_response = resp_header;
    full_response.extend_from_slice(&resp_bytes);

    Some(HandshakeOutcome {
        peer_id: req.my_peer_id,
        group_key,
        domain_name: client_network_name,
        response_bytes: full_response,
    })
}

/// Handle a ping request. Returns the pong response bytes.
pub fn handle_ping(
    from_peer_id: PeerId,
    payload: &[u8],
) -> Vec<u8> {
    let header = create_header(MY_PEER_ID, from_peer_id, PacketType::Pong, payload.len() as u32);
    let mut response = header;
    response.extend_from_slice(payload);
    response
}
