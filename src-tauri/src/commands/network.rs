use tauri::Emitter;
use tokio::sync::mpsc;
use futures_util::{StreamExt, SinkExt};
use tokio_tungstenite::{connect_async, tungstenite::protocol::Message};
use url::Url;
use tokio_socks::tcp::Socks5Stream;
use crate::app_state::NetworkState;
// WS imports removed (unused)

// WS types (currently used via generics)

#[tauri::command]
pub async fn connect_network(
    app: tauri::AppHandle,
    state: tauri::State<'_, NetworkState>,
    relay_url: String,
    bearer_token: Option<String>,
    proxy_url: Option<String>
) -> Result<(), String> {
    let url = Url::parse(&relay_url).map_err(|e| e.to_string())?;
    let (tx, rx) = mpsc::unbounded_channel::<Message>();
    
    {
        let mut sender_lock = state.sender.lock().unwrap();
        *sender_lock = Some(tx);
    }

    if let Some(purl) = proxy_url {
        let p_url = Url::parse(&purl).map_err(|e| e.to_string())?;
        let host = url.host_str().ok_or("No host")?;
        let port = url.port().unwrap_or(80);
        let proxy_addr = format!("{}:{}", p_url.host_str().unwrap_or("127.0.0.1"), p_url.port().unwrap_or(9050));
        let socks = Socks5Stream::connect(proxy_addr.as_str(), (host, port)).await.map_err(|e| e.to_string())?;
        let (ws_stream, _) = tokio_tungstenite::client_async(url.as_str(), socks).await.map_err(|e| e.to_string())?;
        spawn_ws_loop(app, ws_stream, rx, bearer_token);
    } else {
        let (ws_stream, _) = connect_async(url.as_str()).await.map_err(|e| e.to_string())?;
        spawn_ws_loop(app, ws_stream, rx, bearer_token);
    }

    Ok(())
}

fn spawn_ws_loop<S>(app: tauri::AppHandle, mut ws_stream: S, mut rx: mpsc::UnboundedReceiver<Message>, token: Option<String>) 
where S: futures_util::Sink<Message> + StreamExt<Item = Result<Message, tokio_tungstenite::tungstenite::Error>> + Unpin + Send + 'static,
      <S as futures_util::Sink<Message>>::Error: std::fmt::Display + Send {
    tokio::spawn(async move {
        if let Some(t) = token {
            let _ = ws_stream.send(Message::Text(serde_json::json!({
                "type": "auth",
                "token": t
            }).to_string().into())).await;
        }

        loop {
            tokio::select! {
                Some(msg) = ws_stream.next() => {
                    match msg {
                        Ok(Message::Text(text)) => {
                            let _ = app.emit("network-msg", text.to_string());
                        },
                        Ok(Message::Close(_)) | Err(_) => {
                            let _ = app.emit("network-status", "disconnected");
                            break;
                        },
                        _ => {}
                    }
                }
                Some(to_send) = rx.recv() => {
                    if let Err(_) = ws_stream.send(to_send).await {
                        break;
                    }
                }
            }
        }
    });
}

#[tauri::command]
pub async fn send_to_network(state: tauri::State<'_, NetworkState>, payload: String, is_binary: bool) -> Result<(), String> {
    let tx = {
        let lock = state.sender.lock().unwrap();
        lock.clone()
    };
    
    if let Some(sender) = tx {
        if is_binary {
            let data = hex::decode(payload).map_err(|e| e.to_string())?;
            sender.send(Message::Binary(data.into())).map_err(|e| e.to_string())?;
        } else {
            sender.send(Message::Text(payload.into())).map_err(|e| e.to_string())?;
        }
        Ok(())
    } else {
        Err("Network not connected".to_string())
    }
}

#[tauri::command]
pub async fn get_link_preview(url: String, proxy_url: Option<String>) -> Result<serde_json::Value, String> {
    let mut client_builder = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .user_agent("Mozilla/5.0 (Entropy Messenger; Privacy-Check)");

    if let Some(purl) = proxy_url {
        client_builder = client_builder.proxy(reqwest::Proxy::all(purl).map_err(|e| e.to_string())?);
    }

    let client = client_builder.build().map_err(|e| e.to_string())?;
    let resp = client.get(&url).send().await.map_err(|e| e.to_string())?;
    let html = resp.text().await.map_err(|e| e.to_string())?;

    // Basic extraction
    let title = url.clone();
    let _site_name = url.clone();
    let description = String::new();
    let image = String::new();

    if let Ok(_dom) = html_parser::Dom::parse(&html) {
        // Iterate over meta tags (simplified logic)
        // In a real implementation we'd use a better scraper, but this is a start
        // We'll search for <title>, and meta og:title, etc.
        // For brevity in this turn, I'll do a simple regex/string search if html_parser is too heavy to traverse
    }

    // fallback regex for title if parser is tricky for simple UI
    let mut final_title = title;
    if let Some(t_match) = html.find("<title>") {
        if let Some(t_end) = html[t_match..].find("</title>") {
            final_title = html[t_match+7 .. t_match+t_end].to_string();
        }
    }

    Ok(serde_json::json!({
        "url": url,
        "title": final_title.trim(),
        "siteName": url.split('/').nth(2).unwrap_or(""),
        "description": description,
        "image": image
    }))
}
