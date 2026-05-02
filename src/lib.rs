pub mod codec;
pub mod compress;
pub mod constants;
pub mod crypto;
pub mod handlers;
pub mod packet;
pub mod peer_center;
pub mod peer_manager;
pub mod proto;
pub mod relay_room;
pub mod route_state;
pub mod rpc_handler;

use worker::*;

use relay_room::RelayRoom;

#[event(fetch)]
async fn fetch(req: Request, env: Env, _ctx: Context) -> Result<Response> {
    let url = req.url()?;
    let path = url.path();

    // Health check endpoint
    if path == "/healthz" {
        return Response::ok("ok");
    }

    // WebSocket upgrade endpoint
    let ws_path = env
        .var("WS_PATH")
        .map(|v| v.to_string())
        .unwrap_or_else(|_| "ws".to_string());
    let ws_path = format!("/{}", ws_path.trim_start_matches('/'));

    if path == ws_path || path == format!("{}/", ws_path) {
        // Verify WebSocket upgrade header
        let headers = req.headers();
        let upgrade = headers.get("Upgrade")?;
        if upgrade != Some("websocket".to_string()) {
            return Response::error("Expected WebSocket upgrade", 400);
        }

        // Get room ID from query parameter
        let room_id = url
            .query_pairs()
            .find(|(k, _)| k == "room")
            .map(|(_, v)| v.into_owned())
            .unwrap_or_else(|| "default".to_string());

        // Route to Durable Object
        let ns = env.durable_object("RELAY_ROOM")?;
        let stub = ns.id_from_name(&room_id)?.get_stub()?;
        return stub.fetch_with_request(req).await;
    }

    Response::error("Not found", 404)
}
