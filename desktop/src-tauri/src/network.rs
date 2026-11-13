use reqwest::{Client, Proxy, Url};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, sync::{Arc, Mutex, OnceLock, atomic::{AtomicBool, Ordering}}, time::{Duration, Instant}};
use tauri::ipc::Channel;

#[derive(Clone, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Route { pub mode: String, pub url: Option<String>, pub username: Option<String>, pub password: Option<String> }
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Failure { code: &'static str, message: &'static str, retryable: bool }
fn failure(code: &'static str, message: &'static str, retryable: bool) -> Failure { Failure { code, message, retryable } }
fn classify(error: reqwest::Error) -> Failure {
    if error.is_connect() { failure("PROXY_CONNECT", "无法建立网络连接，请检查代理、网络和证书", true) }
    else if error.is_timeout() { failure("NETWORK_TIMEOUT", "网络请求超时", false) }
    else { failure("NETWORK_FAILED", "网络请求中断", false) }
}
pub fn validate_route(route: &Route) -> Result<(), Failure> {
    match route.mode.as_str() {
        "system" | "direct" => Ok(()),
        "proxy" => {
            let url = Url::parse(route.url.as_deref().unwrap_or("")).map_err(|_| failure("PROXY_CONFIG", "代理地址无效", false))?;
            if !["http", "https", "socks5", "socks5h"].contains(&url.scheme()) || url.host_str().is_none()
                || !url.username().is_empty() || url.password().is_some() || url.query().is_some() || url.fragment().is_some()
                || !["", "/"].contains(&url.path()) {
                return Err(failure("PROXY_CONFIG", "代理地址只允许协议、主机和端口", false));
            }
            Ok(())
        }
        _ => Err(failure("PROXY_CONFIG", "未知代理策略", false)),
    }
}
fn client(route: &Route, timeout: Option<Duration>) -> Result<Client, Failure> {
    validate_route(route)?;
    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut builder = Client::builder().redirect(reqwest::redirect::Policy::limited(5));
    if let Some(timeout) = timeout { builder = builder.timeout(timeout); }
    match route.mode.as_str() {
        "direct" => builder = builder.no_proxy(),
        "proxy" => {
            let mut proxy = Proxy::all(route.url.as_deref().unwrap_or("")).map_err(|_| failure("PROXY_CONFIG", "代理地址无效", false))?;
            if let Some(user) = route.username.as_deref().filter(|value| !value.is_empty()) { proxy = proxy.basic_auth(user, route.password.as_deref().unwrap_or("")); }
            builder = builder.no_proxy().proxy(proxy);
        }
        _ => {}
    }
    builder.build().map_err(classify)
}
fn target(url: &str) -> Result<Url, Failure> {
    let parsed = Url::parse(url).map_err(|_| failure("NETWORK_URL", "请求地址无效", false))?;
    if !["http", "https"].contains(&parsed.scheme()) || !parsed.username().is_empty() || parsed.password().is_some() { return Err(failure("NETWORK_URL", "请求地址仅支持 HTTP 和 HTTPS", false)); }
    Ok(parsed)
}
#[derive(Deserialize)]
pub struct Request { id: String, url: String, method: String, headers: HashMap<String, String>, body: Option<String>, route: Route }
#[derive(Clone, Serialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum Event { Started, Headers { status: u16, headers: HashMap<String, String> }, Chunk { data: Vec<u8> }, End }
static ACTIVE: OnceLock<Mutex<HashMap<String, Arc<AtomicBool>>>> = OnceLock::new();
pub fn has_active_requests() -> bool { ACTIVE.get().and_then(|map| map.lock().ok()).is_some_and(|map| !map.is_empty()) }

#[tauri::command]
pub fn network_cancel(id: String) {
    if let Ok(active) = ACTIVE.get_or_init(Default::default).lock() { if let Some(cancel) = active.get(&id) { cancel.store(true, Ordering::SeqCst); } }
}

async fn send(request: Request, on_event: Channel<Event>) -> Result<(), Failure> {
    let url = target(&request.url)?;
    let method = request.method.parse::<reqwest::Method>().map_err(|_| failure("NETWORK_METHOD", "请求方式无效", false))?;
    let mut builder = client(&request.route, None)?.request(method, url);
    for (key, value) in request.headers {
        if ["host", "content-length", "proxy-authorization", "connection", "transfer-encoding", "accept-encoding"].contains(&key.to_lowercase().as_str()) { continue; }
        builder = builder.header(key, value);
    }
    if let Some(body) = request.body { builder = builder.body(body); }
    let mut response = builder.send().await.map_err(classify)?;
    if response.status().as_u16() == 407 { return Err(failure("PROXY_AUTH", "代理认证失败，请检查账号和密码", true)); }
    let headers = response.headers().iter().filter_map(|(name, value)| value.to_str().ok().map(|v| (name.to_string(), v.to_string()))).collect();
    on_event.send(Event::Headers { status: response.status().as_u16(), headers }).map_err(|_| failure("NETWORK_CANCELLED", "请求已关闭", false))?;
    while let Some(bytes) = response.chunk().await.map_err(classify)? {
        on_event.send(Event::Chunk { data: bytes.to_vec() }).map_err(|_| failure("NETWORK_CANCELLED", "请求已关闭", false))?;
    }
    on_event.send(Event::End).map_err(|_| failure("NETWORK_CANCELLED", "请求已关闭", false))?;
    Ok(())
}

#[tauri::command]
pub async fn network_request(request: Request, on_event: Channel<Event>) -> Result<(), Failure> {
    let id = request.id.clone();
    let cancelled = Arc::new(AtomicBool::new(false));
    {
        let mut active = ACTIVE.get_or_init(Default::default).lock().map_err(|_| failure("NETWORK_BUSY", "网络服务繁忙", false))?;
        if crate::updates::INSTALLING.load(Ordering::SeqCst) || active.contains_key(&id) { return Err(failure("NETWORK_BUSY", "网络服务繁忙", false)); }
        active.insert(id.clone(), cancelled.clone());
    }
    let result = tokio::select! {
        result = async {
            on_event.send(Event::Started).map_err(|_| failure("NETWORK_CANCELLED", "请求已关闭", false))?;
            send(request, on_event).await
        } => result,
        _ = async { loop { if cancelled.load(Ordering::SeqCst) { break; } tokio::time::sleep(Duration::from_millis(40)).await; } } => Err(failure("NETWORK_CANCELLED", "请求已取消", false)),
    };
    if let Ok(mut active) = ACTIVE.get_or_init(Default::default).lock() { active.remove(&id); }
    result
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Probe { latency_ms: u128, status: u16 }
#[tauri::command]
pub async fn network_probe(url: String, route: Route) -> Result<Probe, Failure> {
    let start = Instant::now();
    let response = client(&route, Some(Duration::from_secs(10)))?.get(target(&url)?).send().await.map_err(classify)?;
    if response.status().as_u16() == 407 { return Err(failure("PROXY_AUTH", "代理认证失败", false)); }
    if !response.status().is_success() { return Err(failure("PROXY_TEST_HTTP", "测试地址未返回成功状态，请更换测试地址后重试", false)); }
    Ok(Probe { latency_ms: start.elapsed().as_millis(), status: response.status().as_u16() })
}

// Set only this child process's route. Python scripts and other clients remain free to override it.
pub fn configure_python(command: &mut std::process::Command, route: &Route) -> Result<String, String> {
    validate_route(route).map_err(|err| format!("{}: {}", err.code, err.message))?;
    if route.mode == "system" { return Ok(String::new()); }
    for name in ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "all_proxy", "no_proxy"] { command.env_remove(name); }
    let proxies = if route.mode == "proxy" {
        let mut url = Url::parse(route.url.as_deref().unwrap_or("")).map_err(|_| "PROXY_CONFIG")?;
        if !["http", "https"].contains(&url.scheme()) { return Err("PROXY_CONFIG: Python target routing requires an HTTP(S) proxy".into()); }
        if let Some(user) = &route.username { url.set_username(user).map_err(|_| "PROXY_CONFIG")?; }
        if let Some(password) = route.password.as_ref().filter(|value| !value.is_empty()) { url.set_password(Some(password)).map_err(|_| "PROXY_CONFIG")?; }
        for name in ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"] { command.env(name, url.as_str()); }
        // Suppress registry fallback on Windows and inherited bypass lists.
        command.env("NO_PROXY", "").env("no_proxy", "");
        "{'http': _rl_os.environ['HTTP_PROXY'], 'https': _rl_os.environ['HTTPS_PROXY']}"
    } else { command.env("NO_PROXY", "*").env("no_proxy", "*"); "{}" };
    Ok(format!("import os as _rl_os, urllib.request as _rl_http\n_rl_http.install_opener(_rl_http.build_opener(_rl_http.ProxyHandler({proxies})))\n"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use tauri::ipc::InvokeResponseBody;

    fn proxy(status: &str, body: &str) -> (String, std::thread::JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = format!("http://{}", listener.local_addr().unwrap());
        let response = format!("HTTP/1.1 {status}\r\nContent-Length: {}\r\nContent-Type: text/event-stream\r\nConnection: close\r\n\r\n{body}", body.len());
        let handle = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            socket.set_read_timeout(Some(Duration::from_secs(4))).unwrap();
            let mut request = Vec::new();
            let mut byte = [0; 1];
            while !request.ends_with(b"\r\n\r\n") { socket.read_exact(&mut byte).unwrap(); request.push(byte[0]); }
            socket.write_all(response.as_bytes()).unwrap();
            String::from_utf8(request).unwrap()
        });
        (address, handle)
    }
    fn route(url: String) -> Route { Route { mode: "proxy".into(), url: Some(url), username: Some("test-user".into()), password: Some("test-password".into()) } }

    #[tokio::test]
    async fn sends_through_proxy_with_auth_and_streams_response() {
        let (url, server) = proxy("200 OK", "data: first\n\ndata: second\n\n");
        let received = Arc::new(Mutex::new(Vec::<serde_json::Value>::new()));
        let sink = received.clone();
        let channel = Channel::new(move |message| { if let InvokeResponseBody::Json(json) = message { sink.lock().unwrap().push(serde_json::from_str(&json).unwrap()); } Ok(()) });
        let request = Request { id: "test-stream".into(), url: "http://target.invalid/observe".into(), method: "GET".into(), headers: HashMap::new(), body: None, route: route(url) };
        assert!(network_request(request, channel).await.is_ok());
        let wire = server.join().unwrap();
        assert!(wire.starts_with("GET http://target.invalid/observe HTTP/1.1"));
        assert!(wire.to_lowercase().contains("proxy-authorization: basic "));
        let events = received.lock().unwrap();
        assert_eq!(events[0]["kind"], "started");
        assert_eq!(events[1]["kind"], "headers");
        assert_eq!(events.last().unwrap()["kind"], "end");
        let bytes: Vec<u8> = events.iter().filter_map(|event| event["data"].as_array()).flatten().map(|value| value.as_u64().unwrap() as u8).collect();
        assert_eq!(String::from_utf8(bytes).unwrap(), "data: first\n\ndata: second\n\n");
    }
    #[tokio::test]
    async fn proxy_auth_errors_are_classified_without_echoing_response_secrets() {
        let (url, server) = proxy("407 Proxy Authentication Required", "test-password");
        let result = network_probe("http://target.invalid/".into(), route(url)).await;
        let error = result.err().unwrap();
        assert_eq!(error.code, "PROXY_AUTH");
        assert!(!error.message.contains("test-password"));
        server.join().unwrap();
    }
    #[tokio::test]
    async fn cancellation_drops_an_in_flight_request() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let task = tauri::async_runtime::spawn(network_request(Request { id: "test-cancel".into(), url: "http://target.invalid/".into(), method: "GET".into(), headers: HashMap::new(), body: None, route: route(url) }, Channel::new(|_| Ok(()))));
        tokio::time::sleep(Duration::from_millis(80)).await;
        network_cancel("test-cancel".into());
        let error = task.await.unwrap().err().unwrap();
        assert_eq!(error.code, "NETWORK_CANCELLED");
        assert!(!ACTIVE.get().unwrap().lock().unwrap().contains_key("test-cancel"));
    }
    #[tokio::test]
    async fn more_than_thirty_two_requests_can_run_and_be_cancelled() {
        use std::sync::atomic::AtomicUsize;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let started = Arc::new(AtomicUsize::new(0));
        let mut tasks = Vec::new();
        for index in 0..48 {
            let counter = started.clone();
            let channel = Channel::new(move |message| {
                if let InvokeResponseBody::Json(json) = message {
                    if serde_json::from_str::<serde_json::Value>(&json).unwrap()["kind"] == "started" {
                        counter.fetch_add(1, Ordering::SeqCst);
                    }
                }
                Ok(())
            });
            tasks.push(tauri::async_runtime::spawn(network_request(Request {
                id: format!("test-many-{index}"), url: url.clone(), method: "GET".into(),
                headers: HashMap::new(), body: None,
                route: Route { mode: "direct".into(), ..Route::default() },
            }, channel)));
        }
        let registered = tokio::time::timeout(Duration::from_secs(5), async {
            while started.load(Ordering::SeqCst) < 48 { tokio::time::sleep(Duration::from_millis(10)).await; }
        }).await.is_ok();
        for index in 0..48 { network_cancel(format!("test-many-{index}")); }
        for task in tasks {
            let result = tokio::time::timeout(Duration::from_secs(5), task).await.expect("cancellation stalled").unwrap();
            assert_eq!(result.err().unwrap().code, "NETWORK_CANCELLED");
        }
        assert!(registered, "some requests were rejected before registration");
        assert!(!ACTIVE.get().unwrap().lock().unwrap().keys().any(|id| id.starts_with("test-many-")));
    }
    #[tokio::test]
    async fn large_request_and_response_are_not_truncated() {
        use std::io::BufRead;
        use std::sync::atomic::AtomicUsize;
        const INPUT: usize = 9 * 1024 * 1024;
        const OUTPUT: usize = 33 * 1024 * 1024;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let server = std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(10);
            let (mut socket, _) = loop {
                match listener.accept() {
                    Ok(connection) => break connection,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock && Instant::now() < deadline => std::thread::sleep(Duration::from_millis(10)),
                    Err(error) => panic!("local request did not arrive: {error}"),
                }
            };
            socket.set_nonblocking(false).unwrap();
            socket.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
            socket.set_write_timeout(Some(Duration::from_secs(30))).unwrap();
            let mut reader = std::io::BufReader::new(&mut socket);
            let mut length = 0;
            loop {
                let mut line = String::new();
                assert!(reader.read_line(&mut line).unwrap() > 0);
                if line == "\r\n" { break; }
                if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") { length = value.trim().parse::<usize>().unwrap(); }
            }
            assert_eq!(length, INPUT);
            let mut body = vec![0; length];
            reader.read_exact(&mut body).unwrap();
            assert!(body.iter().all(|byte| *byte == b'p'));
            drop(reader);
            write!(socket, "HTTP/1.1 200 OK\r\nContent-Length: {OUTPUT}\r\nConnection: close\r\n\r\n").unwrap();
            let chunk = vec![b'r'; 64 * 1024];
            for _ in 0..OUTPUT / chunk.len() { socket.write_all(&chunk).unwrap(); }
        });
        let received = Arc::new(AtomicUsize::new(0));
        let count = received.clone();
        let channel = Channel::new(move |message| {
            if let InvokeResponseBody::Json(json) = message {
                let event: serde_json::Value = serde_json::from_str(&json).unwrap();
                if let Some(data) = event["data"].as_array() {
                    assert!(data.iter().all(|byte| byte.as_u64() == Some(b'r' as u64)));
                    count.fetch_add(data.len(), Ordering::SeqCst);
                }
            }
            Ok(())
        });
        let result = tokio::time::timeout(Duration::from_secs(60), network_request(Request {
            id: "test-large".into(), url, method: "POST".into(), headers: HashMap::new(),
            body: Some("p".repeat(INPUT)), route: Route { mode: "direct".into(), ..Route::default() },
        }, channel)).await.expect("local transfer stalled");
        assert!(result.is_ok());
        server.join().unwrap();
        assert_eq!(received.load(Ordering::SeqCst), OUTPUT);
        assert!(!ACTIVE.get().unwrap().lock().unwrap().contains_key("test-large"));
    }
    #[test]
    fn python_routes_are_child_scoped_and_do_not_put_credentials_in_source() {
        let mut command = std::process::Command::new("python");
        let configured = route("http://localhost:8080".into());
        let source = configure_python(&mut command, &configured).unwrap();
        assert!(!source.contains("test-password"));
        let environment: HashMap<_, _> = command.get_envs().map(|(key, value)| (key.to_string_lossy().to_string(), value.map(|value| value.to_string_lossy().to_string()))).collect();
        assert!(environment["HTTP_PROXY"].as_ref().unwrap().contains("test-user:test-password"));
        assert_eq!(environment["NO_PROXY"].as_deref(), Some(""));
        let mut direct = std::process::Command::new("python");
        let source = configure_python(&mut direct, &Route { mode: "direct".into(), ..Route::default() }).unwrap();
        assert!(source.contains("ProxyHandler({})"));
        assert!(configure_python(&mut direct, &route("socks5://localhost:1080".into())).is_err());
    }
}
