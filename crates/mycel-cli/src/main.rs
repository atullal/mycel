//! `mycel` — run a Mycel device from the terminal.
//!
//! - `mycel serve`  : a full device + the Mycel web UI on http://127.0.0.1:7777
//! - `mycel keeper` : an always-on keeper (stores ciphertext, relays, never reads)
//! - `mycel id`     : print this device's contact code
//! - `mycel call`   : invoke one runtime command against a running `serve`

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use axum::{
    Json, Router,
    body::Bytes,
    extract::{Path as UrlPath, Query, State},
    http::{HeaderMap, StatusCode, header},
    response::{
        IntoResponse, Response,
        sse::{Event as SseEvent, KeepAlive, Sse},
    },
    routing::{get, post},
};
use clap::{Parser, Subcommand, ValueEnum};
use mycel_node::api::NetworkMode;
use mycel_node::{Runtime, RuntimeOptions, dispatch::dispatch};
use serde::Deserialize;
use serde_json::{Value, json};
use tokio_stream::{StreamExt, wrappers::BroadcastStream};
use tower_http::services::ServeDir;

#[derive(Parser)]
#[command(name = "mycel", about = "Peer-to-peer, end-to-end encrypted, serverless.")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Clone, Copy, ValueEnum)]
enum Net {
    /// Local network only (mDNS). No internet needed.
    Lan,
    /// LAN + internet relays and discovery.
    Internet,
    /// Loopback only (tests).
    Local,
}

impl From<Net> for NetworkMode {
    fn from(n: Net) -> Self {
        match n {
            Net::Lan => NetworkMode::Lan,
            Net::Internet => NetworkMode::Internet,
            Net::Local => NetworkMode::Local,
        }
    }
}

#[derive(clap::Args)]
struct DeviceArgs {
    /// Data directory (identity, messages, files).
    #[arg(long, default_value = "~/.mycel")]
    data: String,
    /// Display name (saved for next time).
    #[arg(long)]
    name: Option<String>,
    #[arg(long, value_enum, default_value = "lan")]
    net: Net,
    /// UDP port for peer connections (0 = random).
    #[arg(long, default_value_t = 0)]
    port: u16,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run a device and serve the web UI + API on localhost.
    Serve {
        #[command(flatten)]
        dev: DeviceArgs,
        /// Where to serve the UI/API. Loopback only.
        #[arg(long, default_value = "127.0.0.1:7777")]
        http: SocketAddr,
        /// Built UI to serve (apps/host/dist).
        #[arg(long)]
        ui: Option<PathBuf>,
    },
    /// Run an always-on keeper: stores and relays encrypted data, can't read it.
    Keeper {
        #[command(flatten)]
        dev: DeviceArgs,
    },
    /// Print this device's contact code.
    Id {
        #[arg(long, default_value = "~/.mycel")]
        data: String,
    },
    /// Call a runtime command on a running `mycel serve`.
    Call {
        command: String,
        /// JSON arguments, e.g. '{"id": "..."}'
        #[arg(default_value = "{}")]
        args: String,
        #[arg(long, default_value = "127.0.0.1:7777")]
        http: SocketAddr,
        /// Data dir of the running `serve` (to read its API token).
        #[arg(long, default_value = "~/.mycel")]
        data: String,
    },
}

fn expand(p: &str) -> PathBuf {
    match p.strip_prefix("~/") {
        Some(rest) => PathBuf::from(std::env::var("HOME").unwrap_or_default()).join(rest),
        None => PathBuf::from(p),
    }
}

async fn open(dev: &DeviceArgs, keeper: bool) -> Result<Arc<Runtime>> {
    Runtime::open_with(RuntimeOptions {
        data_dir: expand(&dev.data),
        mode: dev.net.into(),
        name: dev.name.clone(),
        keeper,
        port: dev.port,
    })
    .await
}

#[tokio::main]
async fn main() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::Serve { dev, http, ui } => serve(dev, http, ui).await,
        Cmd::Keeper { dev } => keeper(dev).await,
        Cmd::Id { data } => {
            let rt = Runtime::open_with(RuntimeOptions {
                data_dir: expand(&data),
                mode: NetworkMode::Local,
                name: None,
                keeper: false,
                port: 0,
            })
            .await?;
            let p = rt.profile();
            println!("name: {}\nid:   {}\ncode: {}", p.name, p.id, p.contact_code);
            rt.shutdown().await
        }
        Cmd::Call { command, args, http, data } => call(http, &expand(&data), &command, &args).await,
    }
}

async fn keeper(dev: DeviceArgs) -> Result<()> {
    let rt = open(&dev, true).await?;
    let p = rt.profile();
    println!("Mycel keeper running ({:?}).", rt.network_status().mode);
    println!("Add it to a conversation with this contact code:\n\n{}\n", p.contact_code);
    let mut events = rt.subscribe();
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => break,
            ev = events.recv() => {
                if let Ok(mycel_node::api::Event::ConversationAdded { conversation }) = ev {
                    println!("now keeping space {}", &conversation[..12]);
                }
            }
        }
    }
    rt.shutdown().await
}

// ─────────────────────────────── HTTP server ───────────────────────────────

struct App {
    rt: Arc<Runtime>,
    http: SocketAddr,
    /// Per-run secret, embedded in the served index.html (cross-origin pages
    /// can't read it) and required on every API route.
    token: String,
    /// index.html with the token injected.
    index: Option<String>,
}

type Shared = Arc<App>;

/// Defence for a localhost API that a browser can reach:
/// - Host must be loopback (blocks DNS rebinding);
/// - every API route needs the per-run token, either as the `X-Mycel` header
///   (fetch) or `?t=` (EventSource, <img>). Only our own page knows it.
#[allow(clippy::result_large_err)] // the Err is the HTTP response itself
fn guard(app: &App, headers: &HeaderMap, query_token: Option<&str>) -> Result<(), Response> {
    let host = headers.get(header::HOST).and_then(|h| h.to_str().ok()).unwrap_or("");
    let ok_host = host == app.http.to_string()
        || host == format!("localhost:{}", app.http.port())
        || host == format!("127.0.0.1:{}", app.http.port());
    if !ok_host {
        return Err((StatusCode::FORBIDDEN, "bad host").into_response());
    }
    let header_token = headers.get("x-mycel").and_then(|v| v.to_str().ok());
    let given = header_token.or(query_token).unwrap_or("");
    if !constant_time_eq(given.as_bytes(), app.token.as_bytes()) {
        return Err((StatusCode::FORBIDDEN, "missing or wrong token").into_response());
    }
    Ok(())
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[derive(Deserialize, Default)]
struct TokenQ {
    t: Option<String>,
}

async fn api_cmd(
    State(app): State<Shared>,
    headers: HeaderMap,
    UrlPath(cmd): UrlPath<String>,
    body: Bytes,
) -> Response {
    if let Err(r) = guard(&app, &headers, None) {
        return r;
    }
    let args: Value = if body.is_empty() {
        Value::Null
    } else {
        match serde_json::from_slice(&body) {
            Ok(v) => v,
            Err(e) => return (StatusCode::BAD_REQUEST, Json(json!({"error": e.to_string()}))).into_response(),
        }
    };
    // Browser-supplied attachment paths must come from our own upload folder.
    if cmd == "send_message"
        && let Some(paths) = args.get("attachments").and_then(|a| a.as_array())
    {
        let uploads = app.rt.data_dir().join("uploads");
        for p in paths {
            let ok = p
                .as_str()
                .and_then(|p| Path::new(p).canonicalize().ok())
                .zip(uploads.canonicalize().ok())
                .is_some_and(|(p, root)| p.starts_with(root));
            if !ok {
                return (StatusCode::BAD_REQUEST, Json(json!({"error": "attachments must be uploaded first"}))).into_response();
            }
        }
    }
    match dispatch(&app.rt, &cmd, args).await {
        Ok(v) => Json(v).into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, Json(json!({"error": e.to_string()}))).into_response(),
    }
}

async fn api_events(State(app): State<Shared>, headers: HeaderMap, Query(q): Query<TokenQ>) -> Response {
    if let Err(r) = guard(&app, &headers, q.t.as_deref()) {
        return r;
    }
    let stream = BroadcastStream::new(app.rt.subscribe()).filter_map(|ev| {
        let ev = ev.ok()?;
        let data = serde_json::to_string(&ev).ok()?;
        Some(Ok::<_, std::convert::Infallible>(SseEvent::default().data(data)))
    });
    Sse::new(stream).keep_alive(KeepAlive::default()).into_response()
}

#[derive(Deserialize)]
struct UploadQ {
    name: String,
}

/// Browser file picker → a file under the data dir the runtime can attach.
async fn api_upload(
    State(app): State<Shared>,
    headers: HeaderMap,
    Query(q): Query<UploadQ>,
    body: Bytes,
) -> Response {
    if let Err(r) = guard(&app, &headers, None) {
        return r;
    }
    let name: String = q
        .name
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or("file")
        .chars()
        .filter(|c| !c.is_control())
        .collect();
    let name = if name.is_empty() || name == "." || name == ".." { "file".into() } else { name };
    let dir = app.rt.data_dir().join("uploads").join(format!("{:016x}", mycel_node::crypto::random_u64()));
    let path = dir.join(name);
    let res = async {
        tokio::fs::create_dir_all(&dir).await?;
        tokio::fs::write(&path, &body).await
    }
    .await;
    match res {
        Ok(()) => Json(json!({"path": path.to_string_lossy()})).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e.to_string()}))).into_response(),
    }
}

#[derive(Deserialize)]
struct FileQ {
    path: String,
    t: Option<String>,
}

/// Serve a local file — only from inside the data dir.
async fn api_file(State(app): State<Shared>, headers: HeaderMap, Query(q): Query<FileQ>) -> Response {
    if let Err(r) = guard(&app, &headers, q.t.as_deref()) {
        return r;
    }
    let Ok(path) = Path::new(&q.path).canonicalize() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    // Only attachments: never identity.key, the database, or anything else.
    let allowed = ["files", "uploads"].iter().any(|d| {
        app.rt
            .data_dir()
            .join(d)
            .canonicalize()
            .is_ok_and(|root| path.starts_with(root))
    });
    if !allowed {
        return StatusCode::FORBIDDEN.into_response();
    }
    match tokio::fs::read(&path).await {
        Ok(bytes) => {
            let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
            let mime = mime_for(&name);
            (
                [
                    (header::CONTENT_TYPE, mime.to_string()),
                    (header::CONTENT_DISPOSITION, format!("inline; filename=\"{}\"", name.replace('"', ""))),
                    (header::X_CONTENT_TYPE_OPTIONS, "nosniff".to_string()),
                    (header::CONTENT_SECURITY_POLICY, "sandbox".to_string()),
                ],
                bytes,
            )
                .into_response()
        }
        Err(_) => StatusCode::NOT_FOUND.into_response(),
    }
}

fn write_private(path: &Path, contents: &str) -> Result<()> {
    std::fs::write(path, contents)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

fn mime_for(name: &str) -> &'static str {
    match name.rsplit('.').next().unwrap_or("").to_ascii_lowercase().as_str() {
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "pdf" => "application/pdf",
        "txt" | "md" => "text/plain; charset=utf-8",
        "mp4" => "video/mp4",
        "mp3" => "audio/mpeg",
        _ => "application/octet-stream",
    }
}

async fn health(State(app): State<Shared>, headers: HeaderMap) -> Response {
    if let Err(r) = guard(&app, &headers, None) {
        return r;
    }
    let p = app.rt.profile();
    Json(json!({"ok": true, "id": p.id, "name": p.name, "transport": "http"})).into_response()
}

/// The UI's index.html with the session token injected (no-store: never cached).
async fn serve_index(State(app): State<Shared>, headers: HeaderMap) -> Response {
    let host = headers.get(header::HOST).and_then(|h| h.to_str().ok()).unwrap_or("");
    if !(host == app.http.to_string() || host == format!("localhost:{}", app.http.port())) {
        return (StatusCode::FORBIDDEN, "bad host").into_response();
    }
    match &app.index {
        Some(html) => (
            [
                (header::CONTENT_TYPE, "text/html; charset=utf-8"),
                (header::CACHE_CONTROL, "no-store"),
            ],
            html.clone(),
        )
            .into_response(),
        None => (StatusCode::NOT_FOUND, "UI not built: run `npm run build`").into_response(),
    }
}

fn default_ui() -> Option<PathBuf> {
    // repo checkout: <repo>/apps/host/dist next to the binary's workspace
    let candidates = [
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../apps/host/dist"),
        PathBuf::from("apps/host/dist"),
    ];
    candidates.into_iter().find(|p| p.join("index.html").exists())
}

async fn serve(dev: DeviceArgs, http: SocketAddr, ui: Option<PathBuf>) -> Result<()> {
    if !http.ip().is_loopback() {
        bail!("refusing to serve the API on a non-loopback address ({http}): anyone on the network could use your account");
    }
    let rt = open(&dev, false).await?;
    let ui = ui.or_else(default_ui);
    let token = mycel_node::crypto::Hash32(mycel_node::crypto::random()).to_string();
    let index = ui.as_ref().and_then(|d| std::fs::read_to_string(d.join("index.html")).ok()).map(|html| {
        let boot = format!(
            "<script>window.__MYCEL_HTTP__=true;window.__MYCEL_TOKEN__=\"{token}\";</script>"
        );
        html.replace("<script src=\"/api/boot.js\"></script>", "").replacen("<head>", &format!("<head>{boot}"), 1)
    });
    let app: Shared = Arc::new(App { rt: rt.clone(), http, token, index });
    let mut router: Router<Shared> = Router::new()
        .route("/", get(serve_index))
        .route("/index.html", get(serve_index))
        .route("/api/health", get(health))
        .route("/api/cmd/{cmd}", post(api_cmd))
        .route("/api/events", get(api_events))
        .route("/api/upload", post(api_upload))
        .route("/api/file", get(api_file));
    if let Some(dir) = &ui {
        // static assets only; every HTML route goes through `serve_index` (token injection)
        // static files; unknown paths (SPA routes) get the token-injected index
        router = router.fallback_service(
            ServeDir::new(dir).not_found_service(axum::handler::Handler::with_state(serve_index, app.clone())),
        );
    }
    let router = router.with_state(app.clone());
    // let `mycel call` (same user) authenticate: token file readable only by us
    write_private(&rt.data_dir().join("http-token"), &format!("{} {}", http, app.token))?;
    let listener = tokio::net::TcpListener::bind(http)
        .await
        .with_context(|| format!("can't listen on {http}"))?;
    let p = rt.profile();
    println!("Mycel device \"{}\" ({:?}) — id {}", p.name, rt.network_status().mode, &p.id[..16]);
    match &ui {
        Some(_) => println!("Open http://{http}"),
        None => println!("API on http://{http}/api (no UI found: build apps/host first)"),
    }
    println!("Contact code:\n{}\n", p.contact_code);
    axum::serve(listener, router)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    rt.shutdown().await
}

async fn call(http: SocketAddr, data: &Path, command: &str, args: &str) -> Result<()> {
    let token_file = std::fs::read_to_string(data.join("http-token"))
        .with_context(|| format!("no running `mycel serve` for {}", data.display()))?;
    let token = token_file.split_whitespace().nth(1).unwrap_or("").to_string();
    // Minimal HTTP/1.1 client so the CLI doesn't need an HTTP client crate.
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let body: Value = serde_json::from_str(args).context("args must be JSON")?;
    let body = body.to_string();
    let mut s = tokio::net::TcpStream::connect(http)
        .await
        .with_context(|| format!("is `mycel serve` running on {http}?"))?;
    let req = format!(
        "POST /api/cmd/{command} HTTP/1.1\r\nHost: {http}\r\nX-Mycel: {token}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    s.write_all(req.as_bytes()).await?;
    let mut resp = String::new();
    s.read_to_string(&mut resp).await?;
    let (head, payload) = resp.split_once("\r\n\r\n").unwrap_or((&resp, ""));
    let ok = head.starts_with("HTTP/1.1 200");
    let pretty = serde_json::from_str::<Value>(payload)
        .map(|v| serde_json::to_string_pretty(&v).unwrap())
        .unwrap_or_else(|_| payload.to_string());
    println!("{pretty}");
    if !ok {
        std::process::exit(1);
    }
    Ok(())
}
