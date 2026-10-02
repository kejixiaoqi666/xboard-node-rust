use node_core::{NodeSpec, UserSpec};
use node_panel::{Auth, Panel};
use serde_json::json;
use std::sync::{Arc, Mutex};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

pub struct PanelData {
    pub config: String,
    pub users: String,
    pub config_tag: u32,
    pub user_tag: u32,
}
pub struct TestPanel {
    pub state: Arc<Mutex<PanelData>>,
    pub base: String,
    task: tokio::task::JoinHandle<()>,
}
impl TestPanel {
    pub async fn new(node: &NodeSpec, users: &[UserSpec]) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let mut config = serde_json::to_value(node).unwrap();
        config["node_id"] = json!(7);
        config["base_config"] = json!({"pull_interval":30,"push_interval":60});
        config["listen_ip"] = json!(node.listen_ip.as_deref().unwrap_or(""));
        config["network"] = json!(node.network.as_deref().unwrap_or(""));
        if node.routes.is_empty() {
            config["routes"] = serde_json::Value::Null;
        }
        let state = Arc::new(Mutex::new(PanelData {
            config: config.to_string(),
            users: json!({"users":users}).to_string(),
            config_tag: 1,
            user_tag: 1,
        }));
        let shared = Arc::clone(&state);
        let task = tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = Vec::new();
                let mut buffer = [0u8; 1024];
                loop {
                    let count = stream.read(&mut buffer).await.unwrap();
                    if count == 0 {
                        break;
                    }
                    request.extend_from_slice(&buffer[..count]);
                    if request.windows(4).any(|part| part == b"\r\n\r\n") {
                        break;
                    }
                    assert!(request.len() < 8192);
                }
                let request = String::from_utf8(request).unwrap().to_ascii_lowercase();
                let (body, tag) = {
                    let data = shared.lock().unwrap();
                    if request.starts_with("get /api/v2/server/config?") {
                        (
                            data.config.clone(),
                            format!("\"config-{}\"", data.config_tag),
                        )
                    } else {
                        assert!(request.starts_with("get /api/v2/server/user?"));
                        (data.users.clone(), format!("\"users-{}\"", data.user_tag))
                    }
                };
                let response = if request.contains(&format!("if-none-match: {tag}")) {
                    "HTTP/1.1 304 Not Modified\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        .to_owned()
                } else {
                    format!(
                        "HTTP/1.1 200 OK\r\nETag: {tag}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    )
                };
                let _ = stream.write_all(response.as_bytes()).await;
            }
        });
        Self { state, base, task }
    }
    pub fn client(&self) -> Panel {
        Panel::new_for_test(&self.base, Auth::machine("fixture-only-token", 1, 7)).unwrap()
    }
    pub fn users(&self, users: &[UserSpec]) {
        let mut data = self.state.lock().unwrap();
        data.users = json!({"users":users}).to_string();
        data.user_tag += 1;
    }
}
impl Drop for TestPanel {
    fn drop(&mut self) {
        self.task.abort();
    }
}
