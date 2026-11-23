//! One-click setup links: `aria://provision?v=1&url=<redeem URL>`.
//!
//! The same contract as the desktop softphone (`src-tauri/src/provision.rs`
//! and `src/utils/provisionLink.ts`), so a link that works there works here
//! and one refused there is refused here.
//!
//! The flow is two calls against the redeem URL:
//! - `provision_preview` sends `GET`, which returns the line (tenant,
//!   extension, domain) and does not use the link up. The app shows it and
//!   asks the user to confirm.
//! - `provision_redeem`, only after the user confirms, sends `POST`, which
//!   returns the credentials and uses the link up. The line it returns must
//!   be the one the preview showed (`Mismatch` otherwise).
//!
//! Any web page or QR code can carry an `aria://` link, so nothing is redeemed
//! without the user's confirmation, and the redeem URL is checked here:
//! `https` only, no userinfo, path `/provision/softphone/<token>`, no
//! redirects, a 10 s timeout and a 16 KB cap on the reply.
//!
//! Never log the link or the URL (its last path segment is the one-time
//! token), the response body or the password.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

/// Every redeem URL's path starts with this; the token follows.
const PATH_PREFIX: &str = "/provision/softphone/";
/// Bigger than any real reply by two orders of magnitude.
const MAX_BODY_BYTES: usize = 16 * 1024;
const TIMEOUT: Duration = Duration::from_secs(10);

/// Why a setup link could not be used. The message (`Display`) is written
/// for the user and never contains the link or its token.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProvisionError {
    /// Not a version-1 `aria://provision` link, or its redeem URL breaks the
    /// rules (not https, userinfo, wrong path, no token).
    #[error("This setup link isn't valid.")]
    InvalidLink,
    /// The server answered 404: the link is unknown, already used or expired.
    #[error("This setup link has expired or was already used. Ask for a new one.")]
    Expired,
    /// The server could not be reached, or did not answer within 10 s.
    #[error("{0}")]
    Network(String),
    /// The redeem returned a different line (extension or domain) than the
    /// preview showed. The link has been used up; nothing should be saved.
    #[error("The setup server sent a different line than it showed. Nothing was changed.")]
    Mismatch,
    /// Any other answer: a non-200 status (including a redirect), a reply
    /// that is not JSON or is over 16 KB, an unsupported `v`, or a missing
    /// or unusable field.
    #[error("{0}")]
    Server(String),
}

/// The line a setup link would add, for the confirmation screen. Nothing
/// secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProvisionPreview {
    pub tenant_name: String,
    pub extension: String,
    pub display_name: String,
    pub domain: String,
    pub expires_at: Option<String>,
    /// `host[:port]` of the redeem URL: who is setting the line up. Show it
    /// on the confirmation screen.
    pub server_host: String,
}

/// The credentials a redeemed setup link returned.
#[derive(Clone, PartialEq, Eq)]
pub struct ProvisionedAccount {
    pub username: String,
    pub auth_username: Option<String>,
    pub password: String,
    pub domain: String,
    /// `"udp"`, `"tcp"`, `"tls"` or `"auto"`; `"tls"` when the server sent none.
    pub transport: String,
    /// 0 when the server sent none: resolve through DNS SRV.
    pub port: u16,
    /// `host` or `host:port`, lower-cased, without a `sip:`/`sips:` prefix.
    /// Carries the top-level `port` when the proxy itself had none.
    pub outbound_proxy: Option<String>,
    /// Digits and `*#+` only, at most 32 characters; otherwise absent.
    pub voicemail: Option<String>,
    /// `"sdes"` or `"disabled"`; absent when the server sent neither.
    pub srtp: Option<String>,
    pub tenant_name: String,
    /// The username when the server sent no display name.
    pub display_name: String,
    /// `host[:port]` of the redeem URL.
    pub server_host: String,
}

// Hand-written so the password can never reach a log line through `{:?}`.
impl std::fmt::Debug for ProvisionedAccount {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProvisionedAccount")
            .field("username", &self.username)
            .field("domain", &self.domain)
            .field("outbound_proxy", &self.outbound_proxy)
            .field("port", &self.port)
            .field("transport", &self.transport)
            .field("srtp", &self.srtp)
            .finish_non_exhaustive()
    }
}

/// How requests are made. Production uses [`Options::default`]; tests allow
/// plain http to a loopback stub and shorten the timeout.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Options {
    pub allow_local_http: bool,
    pub timeout: Duration,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            allow_local_http: false,
            timeout: TIMEOUT,
        }
    }
}

/// Fetch the preview of a setup link (`GET`). Does not use the link up.
pub fn provision_preview(link: String) -> Result<ProvisionPreview, ProvisionError> {
    preview_with(&link, Options::default())
}

/// Redeem a setup link (`POST`), using it up. Call only after the user
/// confirmed the preview.
pub fn provision_redeem(link: String) -> Result<ProvisionedAccount, ProvisionError> {
    redeem_with(&link, Options::default())
}

// ── Link parsing ────────────────────────────────────────────────────────────

/// Extract and check the redeem URL of an `aria://provision?v=1&url=...` link.
///
/// The rules of the desktop's `parseProvisionLink` and
/// `validate_redeem_url`: the `aria://provision` prefix (any case, an
/// optional `/`), exactly one `v` equal to `1`, exactly one non-empty `url`;
/// the URL `https` (plain `http` to `localhost`/`127.0.0.1` only when
/// `allow_local_http`), without userinfo, with the path
/// `/provision/softphone/<token>`.
pub(crate) fn redeem_url(
    link: &str,
    allow_local_http: bool,
) -> Result<reqwest::Url, ProvisionError> {
    let trimmed = link.trim();
    const SCHEME: &str = "aria://provision";
    if trimmed.len() < SCHEME.len() || !trimmed[..SCHEME.len()].eq_ignore_ascii_case(SCHEME) {
        return Err(invalid("not an aria://provision link"));
    }
    let mut rest = &trimmed[SCHEME.len()..];
    if let Some(r) = rest.strip_prefix('/') {
        rest = r;
    }
    if !(rest.is_empty() || rest.starts_with('?') || rest.starts_with('#')) {
        return Err(invalid("not an aria://provision link"));
    }
    let query = rest
        .strip_prefix('?')
        .map(|q| q.split('#').next().unwrap_or_default())
        .unwrap_or_default();

    let mut versions = Vec::new();
    let mut urls = Vec::new();
    for (key, value) in url::form_urlencoded::parse(query.as_bytes()) {
        match key.as_ref() {
            "v" => versions.push(value.into_owned()),
            "url" => urls.push(value.into_owned()),
            _ => {}
        }
    }
    if versions.len() != 1 || versions[0] != "1" {
        return Err(invalid("unsupported version"));
    }
    if urls.len() != 1 || urls[0].is_empty() {
        return Err(invalid("missing url"));
    }
    validate_redeem_url(&urls[0], allow_local_http)
}

fn invalid(reason: &'static str) -> ProvisionError {
    // The reason is safe to log: it never includes the link or the token.
    log::warn!("[provision] refused a setup link: {reason}");
    ProvisionError::InvalidLink
}

/// Check a redeem URL against the contract and return it parsed.
pub(crate) fn validate_redeem_url(
    raw: &str,
    allow_local_http: bool,
) -> Result<reqwest::Url, ProvisionError> {
    let url = reqwest::Url::parse(raw).map_err(|_| invalid("url does not parse"))?;
    let host = url.host_str().ok_or_else(|| invalid("url has no host"))?;
    match url.scheme() {
        "https" => {}
        "http" if allow_local_http && matches!(host, "localhost" | "127.0.0.1") => {}
        _ => return Err(invalid("url is not https")),
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(invalid("url has userinfo"));
    }
    match url.path().strip_prefix(PATH_PREFIX) {
        Some(token) if !token.is_empty() => {}
        _ => return Err(invalid("url has the wrong path")),
    }
    Ok(url)
}

/// `host[:port]` of a redeem URL.
pub(crate) fn server_host(url: &reqwest::Url) -> String {
    let host = url.host_str().unwrap_or_default();
    match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_string(),
    }
}

// ── HTTP ────────────────────────────────────────────────────────────────────

/// Run `fut` to completion from a plain (non-runtime) thread, as the
/// generated bindings call these functions. A private current-thread runtime
/// keeps this independent of `init_runtime`.
fn block_on<T>(fut: impl std::future::Future<Output = T>) -> Result<T, ProvisionError> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| ProvisionError::Network(unreachable_message()))?;
    Ok(rt.block_on(fut))
}

fn unreachable_message() -> String {
    "Couldn't reach the setup server. Check your connection and try again.".into()
}

fn timeout_message() -> String {
    "The setup server took too long to answer. Try again.".into()
}

fn unreadable() -> ProvisionError {
    ProvisionError::Server("The setup server sent a reply Aria can't read.".into())
}

fn client(timeout: Duration) -> Result<reqwest::Client, ProvisionError> {
    reqwest::Client::builder()
        // A redirect could send the request somewhere other than the host the
        // user was shown, so a 3xx is a failure like any other non-200.
        .redirect(reqwest::redirect::Policy::none())
        .timeout(timeout)
        .connect_timeout(timeout)
        .user_agent(concat!("AriaMobile/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|_| ProvisionError::Network(unreachable_message()))
}

/// Strip the URL from reqwest's error before it goes anywhere: its Display
/// would print the token.
fn net_error(e: reqwest::Error) -> ProvisionError {
    let e = e.without_url();
    if e.is_timeout() {
        ProvisionError::Network(timeout_message())
    } else {
        log::warn!("[provision] request failed: {e}");
        ProvisionError::Network(unreachable_message())
    }
}

type JsonMap = serde_json::Map<String, serde_json::Value>;

/// Send the request and return the parsed JSON object of a 200 reply.
async fn fetch_json(
    request: reqwest::RequestBuilder,
    host: &str,
) -> Result<JsonMap, ProvisionError> {
    let mut response = request
        .header(reqwest::header::ACCEPT, "application/json")
        .send()
        .await
        .map_err(net_error)?;
    let status = response.status().as_u16();
    if status != 200 {
        log::warn!("[provision] {host} answered HTTP {status}");
        return Err(if status == 404 {
            ProvisionError::Expired
        } else {
            ProvisionError::Server(format!(
                "The setup server returned an error (HTTP {status})."
            ))
        });
    }
    if response
        .content_length()
        .is_some_and(|n| n > MAX_BODY_BYTES as u64)
    {
        log::warn!("[provision] {host} announced more than {MAX_BODY_BYTES} bytes");
        return Err(unreadable());
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(net_error)? {
        if body.len() + chunk.len() > MAX_BODY_BYTES {
            log::warn!("[provision] {host} sent more than {MAX_BODY_BYTES} bytes");
            return Err(unreadable());
        }
        body.extend_from_slice(&chunk);
    }
    let value: serde_json::Value = serde_json::from_slice(&body).map_err(|_| unreadable())?;
    let serde_json::Value::Object(map) = value else {
        return Err(unreadable());
    };
    if map.get("v").and_then(serde_json::Value::as_u64) != Some(1) {
        return Err(ProvisionError::Server(
            "This setup link needs a newer version of Aria.".into(),
        ));
    }
    Ok(map)
}

// ── Field checks ────────────────────────────────────────────────────────────
//
// The server is the one the user agreed to, but what it returns still ends up
// in SIP headers and on screen, so anything that could break either is refused.

fn get_str<'a>(map: &'a JsonMap, key: &str) -> Option<&'a str> {
    map.get(key)
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
}

/// Display text: control characters, quotes, backslashes and angle brackets
/// dropped (a display name goes into a SIP quoted-string), length capped.
fn clean_text(s: &str, max_chars: usize) -> String {
    s.chars()
        .filter(|c| !c.is_control() && !matches!(c, '"' | '\\' | '<' | '>'))
        .take(max_chars)
        .collect::<String>()
        .trim()
        .to_string()
}

/// A DNS name or IPv4 address (no port).
fn is_host(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 253
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
        && !s.starts_with(['.', '-'])
}

/// The user part of a SIP URI, without anything that would need escaping.
fn is_sip_user(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || "-_.!~*'()&=+$,;".contains(c))
}

fn bad_field(field: &'static str) -> ProvisionError {
    log::warn!("[provision] unusable field in the reply: {field}");
    unreadable()
}

fn host_field(map: &JsonMap, key: &'static str) -> Result<String, ProvisionError> {
    match get_str(map, key) {
        Some(v) if is_host(v) => Ok(v.to_ascii_lowercase()),
        _ => Err(bad_field(key)),
    }
}

fn user_field(map: &JsonMap, key: &'static str) -> Result<String, ProvisionError> {
    match get_str(map, key) {
        Some(v) if is_sip_user(v) => Ok(v.to_string()),
        _ => Err(bad_field(key)),
    }
}

fn parse_preview(map: &JsonMap, server_host: String) -> Result<ProvisionPreview, ProvisionError> {
    Ok(ProvisionPreview {
        tenant_name: get_str(map, "tenant_name")
            .map(|s| clean_text(s, 100))
            .unwrap_or_default(),
        extension: user_field(map, "extension")?,
        display_name: get_str(map, "display_name")
            .map(|s| clean_text(s, 100))
            .unwrap_or_default(),
        domain: host_field(map, "domain")?,
        expires_at: get_str(map, "expires_at").map(|s| clean_text(s, 40)),
        server_host,
    })
}

/// `sip.example.com`, `sip.example.com:5061` or `sips:sip.example.com:5061`
/// -> host and the port, if one was given.
fn parse_proxy(raw: &str) -> Option<(String, Option<u16>)> {
    let lower = raw.to_ascii_lowercase();
    let rest = lower
        .strip_prefix("sips:")
        .or_else(|| lower.strip_prefix("sip:"))
        .unwrap_or(&lower);
    let (host, port) = match rest.split_once(':') {
        Some((h, p)) => (h, Some(p.parse::<u16>().ok().filter(|p| *p != 0)?)),
        None => (rest, None),
    };
    is_host(host).then(|| (host.to_string(), port))
}

fn parse_redeem(map: &JsonMap, server_host: String) -> Result<ProvisionedAccount, ProvisionError> {
    let username = user_field(map, "username")?;
    let auth_username = match get_str(map, "auth_username") {
        Some(_) => Some(user_field(map, "auth_username")?),
        None => None,
    };
    let password = map
        .get("password")
        .and_then(serde_json::Value::as_str)
        .filter(|s| !s.is_empty() && !s.chars().any(char::is_control))
        .ok_or_else(|| bad_field("password"))?
        .to_string();
    let domain = host_field(map, "domain")?;
    let transport = match get_str(map, "transport").map(str::to_ascii_lowercase) {
        None => "tls".to_string(),
        Some(t) if matches!(t.as_str(), "udp" | "tcp" | "tls" | "auto") => t,
        Some(_) => return Err(bad_field("transport")),
    };
    // Absent, null or 0 means no port: DNS SRV decides.
    let port = match map.get("port") {
        None | Some(serde_json::Value::Null) => 0,
        Some(v) => v
            .as_u64()
            .and_then(|p| u16::try_from(p).ok())
            .ok_or_else(|| bad_field("port"))?,
    };
    let outbound_proxy = match get_str(map, "outbound_proxy") {
        None => None,
        Some(raw) => {
            let (host, own_port) = parse_proxy(raw).ok_or_else(|| bad_field("outbound_proxy"))?;
            // `host` alone when there is no port to give it: a port in the
            // proxy string would switch SRV off.
            Some(match own_port.or(Some(port).filter(|p| *p != 0)) {
                Some(p) => format!("{host}:{p}"),
                None => host,
            })
        }
    };
    // Anything but the two known values counts as absent.
    let srtp = get_str(map, "srtp")
        .map(str::to_ascii_lowercase)
        .filter(|s| matches!(s.as_str(), "sdes" | "disabled"));
    let voicemail = get_str(map, "voicemail")
        .filter(|v| v.len() <= 32 && v.chars().all(|c| c.is_ascii_digit() || "*#+".contains(c)))
        .map(str::to_string);
    Ok(ProvisionedAccount {
        tenant_name: get_str(map, "tenant_name")
            .map(|s| clean_text(s, 100))
            .unwrap_or_default(),
        display_name: get_str(map, "display_name")
            .map(|s| clean_text(s, 100))
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| username.clone()),
        username,
        auth_username,
        password,
        domain,
        transport,
        port,
        outbound_proxy,
        voicemail,
        srtp,
        server_host,
    })
}

// ── Preview and redeem ──────────────────────────────────────────────────────

/// The line each previewed redeem URL showed, so the redeem can be held to
/// it. Keyed by the normalised redeem URL; only the extension and domain are
/// kept, never the token on its own or anything secret.
static PREVIEWED: once_cell::sync::Lazy<Mutex<HashMap<String, (String, String)>>> =
    once_cell::sync::Lazy::new(|| Mutex::new(HashMap::new()));

/// At most this many previews are remembered; the oldest go first.
const MAX_REMEMBERED_PREVIEWS: usize = 32;

fn remember_preview(url: &reqwest::Url, preview: &ProvisionPreview) {
    let mut seen = PREVIEWED
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if seen.len() >= MAX_REMEMBERED_PREVIEWS && !seen.contains_key(url.as_str()) {
        seen.clear();
    }
    seen.insert(
        url.as_str().to_string(),
        (preview.extension.clone(), preview.domain.clone()),
    );
}

fn take_previewed(url: &reqwest::Url) -> Option<(String, String)> {
    PREVIEWED
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .remove(url.as_str())
}

async fn fetch_preview(
    url: &reqwest::Url,
    timeout: Duration,
) -> Result<ProvisionPreview, ProvisionError> {
    let host = server_host(url);
    let map = fetch_json(client(timeout)?.get(url.clone()), &host).await?;
    let preview = parse_preview(&map, host.clone())?;
    log::info!("[provision] preview from {host}");
    Ok(preview)
}

pub(crate) fn preview_with(link: &str, opts: Options) -> Result<ProvisionPreview, ProvisionError> {
    let url = redeem_url(link, opts.allow_local_http)?;
    let preview = block_on(fetch_preview(&url, opts.timeout))??;
    remember_preview(&url, &preview);
    Ok(preview)
}

pub(crate) fn redeem_with(link: &str, opts: Options) -> Result<ProvisionedAccount, ProvisionError> {
    let url = redeem_url(link, opts.allow_local_http)?;
    block_on(async {
        // The line the user was shown. Without a preview in this process
        // (the app restarted in between), fetch one now, which uses nothing
        // up, so the redeem is still held to what the server says the link
        // is for.
        let expected = match take_previewed(&url) {
            Some(expected) => expected,
            None => {
                let p = fetch_preview(&url, opts.timeout).await?;
                (p.extension, p.domain)
            }
        };
        let host = server_host(&url);
        let map = fetch_json(client(opts.timeout)?.post(url.clone()), &host).await?;
        let account = parse_redeem(&map, host.clone())?;
        if account.username != expected.0 || !account.domain.eq_ignore_ascii_case(&expected.1) {
            // The line's identity stays out of the log, like everything else
            // the server sent.
            log::warn!("[provision] redeem returned a different line than the preview; refused");
            return Err(ProvisionError::Mismatch);
        }
        log::info!("[provision] redeemed at {host}: {account:?}");
        Ok(account)
    })?
}

#[cfg(test)]
mod tests;
