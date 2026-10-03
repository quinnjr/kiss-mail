//! Remote Admin API for KISS Mail Server.
//!
//! Provides a REST API for remote server administration.
//! Secured via API key or admin credentials.

use axum::{
    Json, Router,
    extract::{ConnectInfo, FromRequestParts, Path, State},
    http::{HeaderMap, StatusCode, header, request::Parts},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{delete, get, post},
};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use crate::admin_rules::{
    PlannedUserUpdate, SessionStore, apply_user_update, check_create_role,
    check_update_permissions, cleanup_deleted_user, client_ip, password_change_message,
    password_change_status, session_is_current,
};
use crate::config::{env_bool, env_nonempty, env_port};
use crate::crypto::CryptoManager;
use crate::groups::{Group, GroupError, GroupManager};
use crate::ldap::LdapClient;
use crate::sso::SsoManager;
use crate::storage::Storage;
use crate::users::{
    AccountStatus, BOOTSTRAP_ADMIN, PasswordChangeFailure, UserAccount, UserError, UserManager,
    UserRole,
};

/// Username recorded (for display only) for requests authenticated with the
/// static API key. Reserved: no account can be created with this name.
const API_KEY_USER: &str = "api-key";

/// Self-service password change endpoint (no auth token needed).
const ACCOUNT_PASSWORD_ROUTE: &str = "/api/account/password";

/// Error code returned by `/api/auth/login` when the password must be changed.
const PASSWORD_CHANGE_REQUIRED: &str = "password_change_required";

/// Lifetime of a session token issued by `/api/auth/login`.
const TOKEN_TTL: Duration = Duration::from_secs(3600);

/// Process-wide start time used for `uptime_seconds`.
static START_TIME: OnceLock<Instant> = OnceLock::new();

fn start_instant() -> Instant {
    *START_TIME.get_or_init(Instant::now)
}

/// Create a synthetic API admin actor for operations that require one
fn api_admin_actor() -> UserAccount {
    use crate::users::UserSettings;
    UserAccount {
        username: "api-admin".to_string(),
        password_hash: String::new(),
        domain: "localhost".to_string(),
        role: UserRole::SuperAdmin,
        status: AccountStatus::Active,
        quota: Default::default(),
        settings: UserSettings {
            display_name: Some("API Administrator".to_string()),
            ..Default::default()
        },
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
        last_login: None,
        failed_login_attempts: 0,
        last_failed_login: None,
        login_history: vec![],
        password_change_required: false,
        password_changed_at: chrono::Utc::now(),
        allowed_ips: vec![],
        admin_notes: None,
        external_auth: None,
    }
}

/// Admin API configuration
#[derive(Debug, Clone)]
pub struct AdminApiConfig {
    /// API key for authentication (optional, can use admin credentials)
    pub api_key: Option<String>,
    /// Port to listen on
    pub port: u16,
    /// Bind address
    pub bind_address: String,
    /// Enable API (default: true if a non-empty api_key is set)
    pub enabled: bool,
}

impl AdminApiConfig {
    /// Configuration from the environment. An invalid `KISS_MAIL_API_PORT`
    /// is an error, so a typo fails at startup instead of silently using the
    /// default port.
    pub fn from_env() -> Result<Self, String> {
        let api_key = env_nonempty("KISS_MAIL_API_KEY");
        Ok(Self {
            enabled: api_key.is_some() || env_bool("KISS_MAIL_API_ENABLED", false),
            api_key,
            port: env_port("KISS_MAIL_API_PORT", 8025)?,
            bind_address: env_nonempty("KISS_MAIL_API_BIND")
                .unwrap_or_else(|| "127.0.0.1".to_string()),
        })
    }
}

/// Shared state for API handlers
#[derive(Clone)]
pub struct ApiState {
    pub user_manager: Arc<UserManager>,
    pub group_manager: Arc<GroupManager>,
    pub storage: Arc<Storage>,
    pub ldap_client: Arc<LdapClient>,
    pub sso_manager: Arc<SsoManager>,
    /// Encryption key manager, so deleting a user also removes their keys
    /// (and reports failures).
    pub crypto_manager: Option<Arc<CryptoManager>>,
    pub config: AdminApiConfig,
    pub domain: String,
    /// Session tokens issued by `/api/auth/login`.
    pub tokens: SessionStore<ApiToken>,
}

/// What an API session token stands for.
#[derive(Debug, Clone)]
pub struct ApiToken {
    pub username: String,
    /// The account's `password_changed_at` when the token was issued; the
    /// token dies when the password changes.
    pub password_changed_at: chrono::DateTime<chrono::Utc>,
}

impl ApiToken {
    fn for_user(user: &UserAccount) -> Self {
        Self {
            username: user.username.clone(),
            password_changed_at: user.password_changed_at,
        }
    }
}

// ============================================================================
// Request/Response Types
// ============================================================================

#[derive(Debug, Serialize, Deserialize)]
pub struct ApiResponse<T> {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Optional advice on how to resolve `error`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hint: Option<String>,
}

impl<T: Serialize> ApiResponse<T> {
    pub fn success(data: T) -> Self {
        Self {
            success: true,
            data: Some(data),
            error: None,
            hint: None,
        }
    }
}

impl ApiResponse<()> {
    pub fn error(msg: impl Into<String>) -> Self {
        Self {
            success: false,
            data: None,
            error: Some(msg.into()),
            hint: None,
        }
    }

    pub fn with_hint(mut self, hint: impl Into<String>) -> Self {
        self.hint = Some(hint.into());
        self
    }
}

/// Build an error response with the given status.
fn api_error(status: StatusCode, msg: impl Into<String>) -> Response {
    (status, Json(ApiResponse::<()>::error(msg))).into_response()
}

/// Map a user-manager error to an HTTP error response.
fn user_error(e: UserError) -> Response {
    let status = match e {
        UserError::NotFound(_) => StatusCode::NOT_FOUND,
        UserError::AlreadyExists(_) => StatusCode::CONFLICT,
        UserError::PermissionDenied(_) => StatusCode::FORBIDDEN,
        UserError::StorageError(_) => StatusCode::INTERNAL_SERVER_ERROR,
        _ => StatusCode::BAD_REQUEST,
    };
    api_error(status, e.to_string())
}

/// Map a group-manager error to an HTTP error response.
fn group_error(e: GroupError) -> Response {
    let status = match e {
        GroupError::NotFound(_) => StatusCode::NOT_FOUND,
        GroupError::AlreadyExists(_) => StatusCode::CONFLICT,
        GroupError::StorageError(_) => StatusCode::INTERNAL_SERVER_ERROR,
        GroupError::InvalidName(_) | GroupError::UserNotFound(_) | GroupError::NotMember(_) => {
            StatusCode::BAD_REQUEST
        }
    };
    api_error(status, e.to_string())
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateUserRequest {
    pub username: String,
    pub password: String,
    #[serde(default)]
    pub role: Option<String>,
    #[serde(default)]
    pub display_name: Option<String>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct UpdateUserRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UserInfo {
    pub username: String,
    pub role: String,
    pub status: String,
    pub display_name: Option<String>,
    pub created_at: String,
    pub last_login: Option<String>,
    pub login_count: u32,
    /// Set by `PUT /api/users/{username}` when a password reset revoked the
    /// user's app passwords.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_app_passwords: Option<usize>,
}

impl From<&UserAccount> for UserInfo {
    fn from(u: &UserAccount) -> Self {
        Self {
            username: u.username.clone(),
            role: format!("{:?}", u.role),
            status: format!("{:?}", u.status),
            display_name: u.settings.display_name.clone(),
            created_at: u.created_at.to_rfc3339(),
            last_login: u.last_login.map(|t| t.to_rfc3339()),
            login_count: u.login_history.len() as u32,
            revoked_app_passwords: None,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateGroupRequest {
    pub name: String,
    /// Group email; defaults to `<name>@<server domain>` when omitted or not
    /// a full address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub members: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GroupMemberRequest {
    pub username: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GroupInfo {
    pub name: String,
    pub email: String,
    pub description: Option<String>,
    pub members: Vec<String>,
    pub managers: Vec<String>,
    pub owner: String,
    pub active: bool,
}

impl From<Group> for GroupInfo {
    fn from(g: Group) -> Self {
        let mut members: Vec<String> = g.members.into_iter().collect();
        members.sort();
        let mut managers: Vec<String> = g.managers.into_iter().collect();
        managers.sort();
        Self {
            name: g.name,
            email: g.email,
            description: if g.description.is_empty() {
                None
            } else {
                Some(g.description)
            },
            members,
            managers,
            owner: g.owner,
            active: g.active,
        }
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct AppPasswordRequest {
    pub label: Option<String>,
    pub expires_days: Option<u32>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AppPasswordResponse {
    pub password: String,
    pub label: String,
    pub expires_at: Option<String>,
}

/// App password metadata as returned by `GET /api/users/{user}/app-passwords`
/// (client-side mirror of `sso::AppPasswordInfo`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteAppPassword {
    pub id: String,
    pub label: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub last_used: Option<chrono::DateTime<chrono::Utc>>,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// SSO status as returned by `GET /api/sso/status`
/// (client-side mirror of the relevant `sso::SsoStatus` fields).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteSsoStatus {
    pub enabled: bool,
    pub provider_name: String,
    pub allow_app_passwords: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ServerStatus {
    pub version: String,
    pub uptime_seconds: u64,
    pub domain: String,
    pub users: usize,
    pub groups: usize,
    pub ldap_enabled: bool,
    pub sso_enabled: bool,
    pub sso_provider: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthRequest {
    pub username: String,
    pub password: String,
}

/// Body of `POST /api/account/password`.
#[derive(Debug, Serialize, Deserialize)]
pub struct ChangePasswordRequest {
    pub username: String,
    pub current_password: String,
    pub new_password: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthResponse {
    pub token: String,
    pub expires_in: u64,
}

// ============================================================================
// Authentication Middleware
// ============================================================================

/// Authentication state stored in request extensions
#[derive(Clone, Debug)]
pub struct AuthUser {
    pub username: String,
    pub is_admin: bool,
    /// Authenticated with the static API key (set only by that branch of
    /// [`authenticate_request`], never derived from the username).
    pub is_api_key: bool,
}

/// The client's IP address (see [`client_ip`]: the TCP peer from
/// `ConnectInfo`, or forwarding headers when the peer is a trusted proxy).
struct PeerIp(String);

impl<S: Send + Sync> FromRequestParts<S> for PeerIp {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let peer = parts
            .extensions
            .get::<ConnectInfo<SocketAddr>>()
            .map(|c| c.0.ip());
        let header = |name: &str| {
            let values: Vec<&str> = parts
                .headers
                .get_all(name)
                .iter()
                .filter_map(|v| v.to_str().ok())
                .collect();
            (!values.is_empty()).then(|| values.join(","))
        };
        Ok(PeerIp(client_ip(
            peer,
            header("x-real-ip").as_deref(),
            header("x-forwarded-for").as_deref(),
        )))
    }
}

/// Constant-time byte comparison (length is not hidden).
pub(crate) fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Check a presented key against the configured API key.
/// Never matches when either side is empty.
fn api_key_matches(provided: &str, configured: Option<&str>) -> bool {
    match configured {
        Some(key) if !key.trim().is_empty() && !provided.is_empty() => {
            ct_eq(provided.as_bytes(), key.as_bytes())
        }
        _ => false,
    }
}

fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .map(str::trim)
        .filter(|t| !t.is_empty())
}

/// Resolve the request's credentials to an [`AuthUser`].
async fn authenticate_request(state: &ApiState, headers: &HeaderMap) -> Result<AuthUser, String> {
    let configured = state.config.api_key.as_deref();
    let bearer = bearer_token(headers);

    // Static API key, via Authorization: Bearer or X-API-Key
    let x_api_key = headers.get("X-API-Key").and_then(|h| h.to_str().ok());
    if bearer.is_some_and(|t| api_key_matches(t, configured))
        || x_api_key.is_some_and(|k| api_key_matches(k.trim(), configured))
    {
        return Ok(AuthUser {
            username: API_KEY_USER.to_string(),
            is_admin: true,
            is_api_key: true,
        });
    }

    // Session token (expired tokens are removed by the lookup)
    let token = bearer.ok_or_else(|| "Unauthorized".to_string())?;
    let session = state
        .tokens
        .lookup(token)
        .await
        .ok_or_else(|| "Unauthorized".to_string())?;

    // Re-check the account on every use: still an active admin, and the
    // password has not changed (nor must be changed) since the token was
    // issued.
    match state.user_manager.get_user(&session.username).await {
        Some(user)
            if user.is_active_admin() && session_is_current(session.password_changed_at, &user) =>
        {
            Ok(AuthUser {
                username: user.username,
                is_admin: true,
                is_api_key: false,
            })
        }
        _ => {
            state.tokens.remove(token).await;
            Err("Unauthorized".to_string())
        }
    }
}

/// Extract auth info from request
async fn auth_middleware(
    State(state): State<ApiState>,
    mut req: axum::http::Request<axum::body::Body>,
    next: Next,
) -> Response {
    match authenticate_request(&state, req.headers()).await {
        Ok(user) => {
            req.extensions_mut().insert(user);
            next.run(req).await
        }
        Err(msg) => api_error(StatusCode::UNAUTHORIZED, msg),
    }
}

/// Require admin privileges
fn require_admin(auth: &AuthUser) -> Result<(), (StatusCode, Json<ApiResponse<()>>)> {
    if !auth.is_admin {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ApiResponse::error("Admin privileges required")),
        ));
    }
    Ok(())
}

/// The account on whose behalf user-management calls are made.
///
/// API-key requests act as a synthetic super admin; token requests act as the
/// logged-in admin so role restrictions (e.g. Admin vs SuperAdmin) apply.
async fn actor_for(state: &ApiState, auth: &AuthUser) -> Result<UserAccount, Response> {
    if auth.is_api_key {
        return Ok(api_admin_actor());
    }
    state
        .user_manager
        .get_user(&auth.username)
        .await
        .ok_or_else(|| api_error(StatusCode::UNAUTHORIZED, "Unauthorized"))
}

// ============================================================================
// API Handlers
// ============================================================================

/// POST /api/auth/login - Login with admin credentials
async fn login(
    State(state): State<ApiState>,
    PeerIp(ip): PeerIp,
    Json(req): Json<AuthRequest>,
) -> Response {
    // Prune expired tokens
    state.tokens.purge_expired().await;

    let user = match state
        .user_manager
        .authenticate(&req.username, &req.password, &ip, "admin-api")
        .await
    {
        Ok(user) => user,
        Err(UserError::PasswordChangeRequired) => {
            return (
                StatusCode::FORBIDDEN,
                Json(
                    ApiResponse::<()>::error(PASSWORD_CHANGE_REQUIRED).with_hint(format!(
                        "Change the password with POST {} (username, current_password, new_password), then log in again",
                        ACCOUNT_PASSWORD_ROUTE
                    )),
                ),
            )
                .into_response();
        }
        // Correct password, but the account's status or IP rules forbid it.
        Err(UserError::PermissionDenied(msg)) => return api_error(StatusCode::FORBIDDEN, msg),
        // Too many failed attempts (throttle).
        Err(UserError::AccountLocked(msg)) => {
            return api_error(StatusCode::TOO_MANY_REQUESTS, msg);
        }
        Err(_) => return api_error(StatusCode::UNAUTHORIZED, "Invalid credentials"),
    };

    if !user.is_active_admin() {
        return api_error(StatusCode::FORBIDDEN, "Admin privileges required");
    }

    let token = state
        .tokens
        .create(ApiToken::for_user(&user), TOKEN_TTL)
        .await;

    (
        StatusCode::OK,
        Json(ApiResponse::success(AuthResponse {
            token,
            expires_in: TOKEN_TTL.as_secs(),
        })),
    )
        .into_response()
}

/// POST /api/account/password - Change your own password (no token needed;
/// the current password is the credential). Throttled per username and peer
/// IP like a login. Works while a password change is required.
async fn change_own_password(
    State(state): State<ApiState>,
    PeerIp(ip): PeerIp,
    Json(req): Json<ChangePasswordRequest>,
) -> Response {
    match state
        .user_manager
        .change_password_from(&ip, &req.username, &req.current_password, &req.new_password)
        .await
    {
        Ok(()) => Json(ApiResponse::success(())).into_response(),
        Err(e) => {
            // Same mapping as the web page (credential failures are generic
            // so they do not reveal whether the account exists).
            let failure = PasswordChangeFailure::from(e);
            let status = StatusCode::from_u16(password_change_status(&failure))
                .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            api_error(status, password_change_message(&req.username, &failure))
        }
    }
}

/// POST /api/auth/logout - Logout
async fn logout(
    State(state): State<ApiState>,
    req: axum::http::Request<axum::body::Body>,
) -> impl IntoResponse {
    if let Some(token) = bearer_token(req.headers()) {
        state.tokens.remove(token).await;
    }
    Json(ApiResponse::success(()))
}

/// GET /api/status - Server status
async fn get_status(
    State(state): State<ApiState>,
    axum::Extension(auth): axum::Extension<AuthUser>,
) -> impl IntoResponse {
    let _ = auth; // Just verify authenticated

    let users = state.user_manager.list_users().await.len();
    let groups = state.group_manager.get_stats().await.total_groups;
    let ldap_status = state.ldap_client.status();
    let sso_status = state.sso_manager.status();

    Json(ApiResponse::success(ServerStatus {
        version: env!("CARGO_PKG_VERSION").to_string(),
        uptime_seconds: start_instant().elapsed().as_secs(),
        domain: state.domain.clone(),
        users,
        groups,
        ldap_enabled: ldap_status.enabled,
        sso_enabled: sso_status.enabled,
        sso_provider: if sso_status.enabled {
            Some(sso_status.provider_name)
        } else {
            None
        },
    }))
}

// ============================================================================
// User Management
// ============================================================================

/// GET /api/users - List all users
async fn list_users(
    State(state): State<ApiState>,
    axum::Extension(auth): axum::Extension<AuthUser>,
) -> impl IntoResponse {
    if let Err(e) = require_admin(&auth) {
        return e.into_response();
    }

    let users: Vec<UserInfo> = state
        .user_manager
        .list_users()
        .await
        .iter()
        .map(UserInfo::from)
        .collect();

    Json(ApiResponse::success(users)).into_response()
}

/// POST /api/users - Create user
async fn create_user(
    State(state): State<ApiState>,
    axum::Extension(auth): axum::Extension<AuthUser>,
    Json(req): Json<CreateUserRequest>,
) -> impl IntoResponse {
    if let Err(e) = require_admin(&auth) {
        return e.into_response();
    }

    let actor = match actor_for(&state, &auth).await {
        Ok(a) => a,
        Err(resp) => return resp,
    };

    let role = match req.role.as_deref().map(str::trim).filter(|r| !r.is_empty()) {
        None => UserRole::User,
        Some(r) => match r.parse::<UserRole>() {
            Ok(role) => role,
            Err(_) => return api_error(StatusCode::BAD_REQUEST, format!("Unknown role: {}", r)),
        },
    };
    if let Err(msg) = check_create_role(&actor, role) {
        return api_error(StatusCode::FORBIDDEN, msg);
    }

    // Display name and account are saved together.
    let mut plan = PlannedUserUpdate::default();
    plan.set_display_name(req.display_name.as_deref().unwrap_or(""), &None);
    let display_name = plan.display_name.flatten();
    match state
        .user_manager
        .create_user_with(&req.username, &req.password, Some(role), |u| {
            u.settings.display_name = display_name;
        })
        .await
    {
        Ok(user) => Json(ApiResponse::success(UserInfo::from(&user))).into_response(),
        Err(e) => user_error(e),
    }
}

/// GET /api/users/{username} - Get user details
async fn get_user(
    State(state): State<ApiState>,
    axum::Extension(auth): axum::Extension<AuthUser>,
    Path(username): Path<String>,
) -> impl IntoResponse {
    if let Err(e) = require_admin(&auth) {
        return e.into_response();
    }

    match state.user_manager.get_user(&username).await {
        Some(user) => Json(ApiResponse::success(UserInfo::from(&user))).into_response(),
        None => api_error(StatusCode::NOT_FOUND, "User not found"),
    }
}

/// PUT /api/users/{username} - Update user (password, role, display name, status)
async fn update_user(
    State(state): State<ApiState>,
    axum::Extension(auth): axum::Extension<AuthUser>,
    Path(username): Path<String>,
    Json(req): Json<UpdateUserRequest>,
) -> impl IntoResponse {
    if let Err(e) = require_admin(&auth) {
        return e.into_response();
    }

    // Check user exists
    let current = match state.user_manager.get_user(&username).await {
        Some(u) => u,
        None => return api_error(StatusCode::NOT_FOUND, "User not found"),
    };

    // Validate everything and check every permission before applying anything.
    let role = match req.role.as_deref() {
        None => None,
        Some(r) => match r.parse::<UserRole>() {
            Ok(role) => Some(role).filter(|r| *r != current.role),
            Err(_) => return api_error(StatusCode::BAD_REQUEST, format!("Unknown role: {}", r)),
        },
    };
    let status = match req.status.as_deref() {
        None => None,
        Some(s) => match s.parse::<AccountStatus>() {
            Ok(st) => Some(st).filter(|st| *st != current.status),
            Err(_) => {
                return api_error(StatusCode::BAD_REQUEST, format!("Unknown status: {}", s));
            }
        },
    };
    let actor = match actor_for(&state, &auth).await {
        Ok(a) => a,
        Err(resp) => return resp,
    };

    let mut plan = PlannedUserUpdate {
        password: req.password,
        role,
        status,
        ..Default::default()
    };
    if let Some(name) = &req.display_name {
        plan.set_display_name(name, &current.settings.display_name);
    }
    if let Err(msg) = check_update_permissions(&actor, &current, &plan) {
        return api_error(StatusCode::FORBIDDEN, msg);
    }

    let report = apply_user_update(
        &state.user_manager,
        &state.sso_manager,
        &actor,
        &current,
        &plan,
    )
    .await;
    if !report.errors.is_empty() {
        return api_error(StatusCode::BAD_REQUEST, report.errors.join("; "));
    }

    match state.user_manager.get_user(&username).await {
        Some(user) => {
            let mut info = UserInfo::from(&user);
            if plan.password.is_some() {
                info.revoked_app_passwords = Some(report.revoked_app_passwords);
            }
            Json(ApiResponse::success(info)).into_response()
        }
        None => api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to retrieve updated user",
        ),
    }
}

/// DELETE /api/users/{username} - Delete user
async fn delete_user(
    State(state): State<ApiState>,
    axum::Extension(auth): axum::Extension<AuthUser>,
    Path(username): Path<String>,
) -> impl IntoResponse {
    if let Err(e) = require_admin(&auth) {
        return e.into_response();
    }

    let actor = match actor_for(&state, &auth).await {
        Ok(a) => a,
        Err(resp) => return resp,
    };
    match state.user_manager.delete_user(&username, &actor).await {
        Ok(()) => {
            let failures = cleanup_deleted_user(
                &state.user_manager,
                &state.storage,
                &state.sso_manager,
                state.crypto_manager.as_deref(),
                &state.group_manager,
                &username,
            )
            .await;
            if failures.is_empty() {
                Json(ApiResponse::success(())).into_response()
            } else {
                api_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!(
                        "User {} was deleted, but cleanup failed: {}",
                        username,
                        failures.join("; ")
                    ),
                )
            }
        }
        Err(e) => user_error(e),
    }
}

// ============================================================================
// Group Management
// ============================================================================

/// GET /api/groups - List all groups
async fn list_groups(
    State(state): State<ApiState>,
    axum::Extension(auth): axum::Extension<AuthUser>,
) -> impl IntoResponse {
    if let Err(e) = require_admin(&auth) {
        return e.into_response();
    }

    let groups: Vec<GroupInfo> = state
        .group_manager
        .list()
        .await
        .into_iter()
        .map(GroupInfo::from)
        .collect();

    Json(ApiResponse::success(groups)).into_response()
}

/// Resolve the email for a new group: a full address is used as-is,
/// anything else falls back to `<name>@<domain>`.
fn resolve_group_email(name: &str, email: Option<&str>, domain: &str) -> String {
    match email.map(str::trim) {
        Some(e) if e.contains('@') => e.to_string(),
        _ => format!("{}@{}", name, domain),
    }
}

/// POST /api/groups - Create group
async fn create_group(
    State(state): State<ApiState>,
    axum::Extension(auth): axum::Extension<AuthUser>,
    Json(req): Json<CreateGroupRequest>,
) -> impl IntoResponse {
    if let Err(e) = require_admin(&auth) {
        return e.into_response();
    }

    let email = resolve_group_email(&req.name, req.email.as_deref(), &state.domain);
    // The synthetic API-key identity is not a real user; record the
    // bootstrap admin. Groups never add the owner as a member.
    let owner = if auth.is_api_key {
        BOOTSTRAP_ADMIN.to_string()
    } else {
        auth.username.clone()
    };

    // Description and members are validated and saved together with the
    // group, so a failure never leaves a half-created group behind.
    let description = req.description.as_deref().filter(|d| !d.is_empty());
    match state
        .group_manager
        .create_with_members(&req.name, &email, &owner, description, &req.members)
        .await
    {
        Ok(group) => Json(ApiResponse::success(GroupInfo::from(group))).into_response(),
        Err(e) => group_error(e),
    }
}

/// GET /api/groups/{name} - Get group details
async fn get_group(
    State(state): State<ApiState>,
    axum::Extension(auth): axum::Extension<AuthUser>,
    Path(name): Path<String>,
) -> impl IntoResponse {
    if let Err(e) = require_admin(&auth) {
        return e.into_response();
    }

    match state.group_manager.get(&name).await {
        Some(group) => Json(ApiResponse::success(GroupInfo::from(group))).into_response(),
        None => api_error(StatusCode::NOT_FOUND, "Group not found"),
    }
}

/// DELETE /api/groups/{name} - Delete group
async fn delete_group(
    State(state): State<ApiState>,
    axum::Extension(auth): axum::Extension<AuthUser>,
    Path(name): Path<String>,
) -> impl IntoResponse {
    if let Err(e) = require_admin(&auth) {
        return e.into_response();
    }

    match state.group_manager.delete(&name).await {
        Ok(_) => Json(ApiResponse::success(())).into_response(),
        Err(e) => group_error(e),
    }
}

/// POST /api/groups/{name}/members - Add member to group
async fn add_group_member(
    State(state): State<ApiState>,
    axum::Extension(auth): axum::Extension<AuthUser>,
    Path(name): Path<String>,
    Json(req): Json<GroupMemberRequest>,
) -> impl IntoResponse {
    if let Err(e) = require_admin(&auth) {
        return e.into_response();
    }

    match state.group_manager.add_member(&name, &req.username).await {
        Ok(_) => Json(ApiResponse::success(())).into_response(),
        Err(e) => group_error(e),
    }
}

/// DELETE /api/groups/{name}/members/{username} - Remove member from group
async fn remove_group_member(
    State(state): State<ApiState>,
    axum::Extension(auth): axum::Extension<AuthUser>,
    Path((name, username)): Path<(String, String)>,
) -> impl IntoResponse {
    if let Err(e) = require_admin(&auth) {
        return e.into_response();
    }

    match state.group_manager.remove_member(&name, &username).await {
        Ok(_) => Json(ApiResponse::success(())).into_response(),
        Err(e) => group_error(e),
    }
}

// ============================================================================
// SSO / App Passwords
// ============================================================================

/// GET /api/users/{username}/app-passwords - List app passwords
async fn list_app_passwords(
    State(state): State<ApiState>,
    axum::Extension(auth): axum::Extension<AuthUser>,
    Path(username): Path<String>,
) -> impl IntoResponse {
    if let Err(e) = require_admin(&auth) {
        return e.into_response();
    }

    let passwords = state.sso_manager.list_app_passwords(&username).await;
    Json(ApiResponse::success(passwords)).into_response()
}

/// POST /api/users/{username}/app-passwords - Generate app password
async fn create_app_password(
    State(state): State<ApiState>,
    axum::Extension(auth): axum::Extension<AuthUser>,
    Path(username): Path<String>,
    Json(req): Json<AppPasswordRequest>,
) -> impl IntoResponse {
    if let Err(e) = require_admin(&auth) {
        return e.into_response();
    }

    // App passwords for a super admin may only be issued by a super admin or
    // by that user themselves.
    let actor = match actor_for(&state, &auth).await {
        Ok(a) => a,
        Err(resp) => return resp,
    };
    let Some(target) = state.user_manager.get_user(&username).await else {
        return api_error(StatusCode::NOT_FOUND, "User not found");
    };
    if target.role == UserRole::SuperAdmin
        && actor.role != UserRole::SuperAdmin
        && actor.username != target.username
    {
        return api_error(
            StatusCode::FORBIDDEN,
            "Only super administrators can issue app passwords for super administrators",
        );
    }

    let label = req.label.unwrap_or_else(|| "Remote CLI".to_string());

    match state
        .sso_manager
        .generate_app_password(&target.username, &label, req.expires_days)
        .await
    {
        Ok(password) => Json(ApiResponse::success(AppPasswordResponse {
            password,
            label,
            expires_at: req
                .expires_days
                .map(|d| (chrono::Utc::now() + chrono::Duration::days(d as i64)).to_rfc3339()),
        }))
        .into_response(),
        Err(e) => api_error(StatusCode::BAD_REQUEST, e),
    }
}

/// DELETE /api/users/{username}/app-passwords/{id} - Revoke app password
async fn revoke_app_password(
    State(state): State<ApiState>,
    axum::Extension(auth): axum::Extension<AuthUser>,
    Path((username, id)): Path<(String, String)>,
) -> impl IntoResponse {
    if let Err(e) = require_admin(&auth) {
        return e.into_response();
    }

    match state.sso_manager.revoke_app_password(&username, &id).await {
        Ok(true) => Json(ApiResponse::success(())).into_response(),
        Ok(false) => api_error(StatusCode::NOT_FOUND, "App password not found"),
        Err(e) => {
            tracing::error!("Could not persist app password revocation: {}", e);
            api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Could not persist revocation",
            )
        }
    }
}

// ============================================================================
// LDAP
// ============================================================================

/// GET /api/ldap/status - Get LDAP status
async fn ldap_status(
    State(state): State<ApiState>,
    axum::Extension(auth): axum::Extension<AuthUser>,
) -> impl IntoResponse {
    if let Err(e) = require_admin(&auth) {
        return e.into_response();
    }

    let status = state.ldap_client.status();
    Json(ApiResponse::success(status)).into_response()
}

/// POST /api/ldap/test - Test LDAP connection
async fn ldap_test(
    State(state): State<ApiState>,
    axum::Extension(auth): axum::Extension<AuthUser>,
) -> impl IntoResponse {
    if let Err(e) = require_admin(&auth) {
        return e.into_response();
    }

    match state.ldap_client.test_connection().await {
        Ok(msg) => Json(ApiResponse::success(msg)).into_response(),
        Err(e) => api_error(StatusCode::BAD_REQUEST, e),
    }
}

// ============================================================================
// SSO Status
// ============================================================================

/// GET /api/sso/status - Get SSO status
async fn sso_status(
    State(state): State<ApiState>,
    axum::Extension(auth): axum::Extension<AuthUser>,
) -> impl IntoResponse {
    if let Err(e) = require_admin(&auth) {
        return e.into_response();
    }

    let status = state.sso_manager.status();
    Json(ApiResponse::success(status)).into_response()
}

// ============================================================================
// Router & Server
// ============================================================================

/// Create the admin API router. Serve it with
/// `into_make_service_with_connect_info::<SocketAddr>()` so logins see the
/// client IP.
pub fn create_router(state: ApiState) -> Router {
    let _ = start_instant();

    // Public routes (no auth required)
    let public_routes = Router::new()
        .route("/api/auth/login", post(login))
        .route("/api/auth/logout", post(logout))
        .route(ACCOUNT_PASSWORD_ROUTE, post(change_own_password))
        .with_state(state.clone());

    // Protected routes (auth required)
    let protected_routes = Router::new()
        // Status
        .route("/api/status", get(get_status))
        // Users
        .route("/api/users", get(list_users).post(create_user))
        .route(
            "/api/users/{username}",
            get(get_user).put(update_user).delete(delete_user),
        )
        // Groups
        .route("/api/groups", get(list_groups).post(create_group))
        .route("/api/groups/{name}", get(get_group).delete(delete_group))
        .route("/api/groups/{name}/members", post(add_group_member))
        .route(
            "/api/groups/{name}/members/{username}",
            delete(remove_group_member),
        )
        // App passwords
        .route(
            "/api/users/{username}/app-passwords",
            get(list_app_passwords).post(create_app_password),
        )
        .route(
            "/api/users/{username}/app-passwords/{id}",
            delete(revoke_app_password),
        )
        // LDAP
        .route("/api/ldap/status", get(ldap_status))
        .route("/api/ldap/test", post(ldap_test))
        // SSO
        .route("/api/sso/status", get(sso_status))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth_middleware,
        ))
        .with_state(state);

    public_routes.merge(protected_routes)
}

/// Start the admin API server.
///
/// When the API is disabled this logs once and then never completes, so it
/// can sit in a `select!` next to the mail servers without ending them.
pub async fn run_api_server(
    state: ApiState,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let _ = start_instant();

    if !state.config.enabled {
        tracing::info!("Admin API disabled (set KISS_MAIL_API_KEY to enable)");
        std::future::pending::<()>().await;
        return Ok(());
    }

    let addr = format!("{}:{}", state.config.bind_address, state.config.port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;

    tracing::info!("Admin API listening on http://{}", addr);
    if state.config.api_key.is_some() {
        tracing::info!("Admin API: API key authentication enabled");
    }

    let router = create_router(state);
    axum::serve(
        listener,
        router.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;

    Ok(())
}

// ============================================================================
// CLI Remote Client
// ============================================================================

/// Remote API client for CLI
pub struct RemoteClient {
    base_url: String,
    api_key: Option<String>,
    token: Option<String>,
    client: reqwest::Client,
}

/// Percent-encode a single URL path segment.
fn seg(s: &str) -> String {
    urlencoding::encode(s).into_owned()
}

/// Normalise a `--server` value into a base URL (see [`RemoteClient::new`]).
fn remote_base_url(server: &str, insecure: bool) -> Result<String, String> {
    let server = server.trim().trim_end_matches('/');
    if server.is_empty() {
        return Err("Server address is empty".to_string());
    }
    let base_url = if server.contains("://") {
        server.to_string()
    } else {
        format!("https://{}", server)
    };
    let url = reqwest::Url::parse(&base_url)
        .map_err(|e| format!("Invalid server address '{}': {}", server, e))?;
    match url.scheme() {
        "https" => {}
        "http" if insecure || is_loopback_host(url.host_str()) => {}
        "http" => {
            return Err(format!(
                "Refusing to send credentials over plain http:// to {}; use https:// \
                 (e.g. behind a TLS proxy) or pass --insecure",
                url.host_str().unwrap_or(server)
            ));
        }
        other => return Err(format!("Unsupported URL scheme '{}://'", other)),
    }
    Ok(base_url)
}

/// Whether a URL host (as given by `Url::host_str`) is the local machine.
fn is_loopback_host(host: Option<&str>) -> bool {
    let Some(host) = host else {
        return false;
    };
    let host = host.trim_start_matches('[').trim_end_matches(']');
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return ip.to_canonical().is_loopback();
    }
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    host == "localhost" || host.ends_with(".localhost")
}

impl RemoteClient {
    /// Client for `server` (`host[:port]` or a full `http(s)://` URL).
    ///
    /// Without a scheme `https://` is assumed. Plain `http://` is only
    /// allowed to loopback hosts unless `insecure` is set, because the API key
    /// and passwords would otherwise cross the network in clear text.
    pub fn new(server: &str, insecure: bool) -> Result<Self, String> {
        let base_url = remote_base_url(server, insecure)?;

        let client = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| format!("Could not build HTTP client: {}", e))?;

        Ok(Self {
            base_url,
            api_key: None,
            token: None,
            client,
        })
    }

    pub fn with_api_key(mut self, key: String) -> Self {
        if !key.trim().is_empty() {
            self.api_key = Some(key);
        }
        self
    }

    #[cfg(test)]
    pub async fn login(&mut self, username: &str, password: &str) -> Result<(), String> {
        let req = self
            .client
            .post(format!("{}/api/auth/login", self.base_url))
            .json(&AuthRequest {
                username: username.to_string(),
                password: password.to_string(),
            });
        let data: AuthResponse = Self::expect_data(Self::send(req).await?)?;
        if data.token.is_empty() {
            return Err("No token in response".to_string());
        }
        self.token = Some(data.token);
        Ok(())
    }

    /// Change `username`'s own password (needs no API key or token).
    pub async fn change_password(
        &self,
        username: &str,
        current_password: &str,
        new_password: &str,
    ) -> Result<(), String> {
        let req = self
            .client
            .post(format!("{}{}", self.base_url, ACCOUNT_PASSWORD_ROUTE))
            .json(&ChangePasswordRequest {
                username: username.to_string(),
                current_password: current_password.to_string(),
                new_password: new_password.to_string(),
            });
        Self::send::<serde_json::Value>(req).await.map(|_| ())
    }

    fn auth_header(&self) -> Option<String> {
        self.api_key
            .as_ref()
            .or(self.token.as_ref())
            .map(|t| format!("Bearer {}", t))
    }

    fn with_auth(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match self.auth_header() {
            Some(auth) => req.header("Authorization", auth),
            None => req,
        }
    }

    /// Send a request and decode the `ApiResponse` envelope, returning `data`
    /// (which may be absent) on success or the server's error message.
    async fn send<T: serde::de::DeserializeOwned>(
        req: reqwest::RequestBuilder,
    ) -> Result<Option<T>, String> {
        let resp = req
            .send()
            .await
            .map_err(|e| format!("Request failed: {}", e))?;
        let status = resp.status();
        let text = resp
            .text()
            .await
            .map_err(|e| format!("Request failed: {}", e))?;
        let result: ApiResponse<T> = serde_json::from_str(&text).map_err(|e| {
            if status.is_success() {
                format!("Invalid response: {}", e)
            } else {
                format!("Request failed with HTTP {}", status)
            }
        })?;

        if result.success {
            Ok(result.data)
        } else {
            let error = result
                .error
                .unwrap_or_else(|| format!("Request failed with HTTP {}", status));
            Err(match result.hint {
                Some(hint) => format!("{} ({})", error, hint),
                None => error,
            })
        }
    }

    fn expect_data<T>(data: Option<T>) -> Result<T, String> {
        data.ok_or_else(|| "No data in response".to_string())
    }

    async fn get<T: serde::de::DeserializeOwned>(&self, path: &str) -> Result<T, String> {
        let req = self.with_auth(self.client.get(format!("{}{}", self.base_url, path)));
        Self::expect_data(Self::send(req).await?)
    }

    async fn post<T: serde::de::DeserializeOwned, B: serde::Serialize>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T, String> {
        let req = self.with_auth(
            self.client
                .post(format!("{}{}", self.base_url, path))
                .json(body),
        );
        Self::expect_data(Self::send(req).await?)
    }

    /// POST for endpoints that return `data: null`; only `success` is checked.
    async fn post_unit<B: serde::Serialize>(&self, path: &str, body: &B) -> Result<(), String> {
        let req = self.with_auth(
            self.client
                .post(format!("{}{}", self.base_url, path))
                .json(body),
        );
        Self::send::<serde_json::Value>(req).await.map(|_| ())
    }

    async fn put<T: serde::de::DeserializeOwned, B: serde::Serialize>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T, String> {
        let req = self.with_auth(
            self.client
                .put(format!("{}{}", self.base_url, path))
                .json(body),
        );
        Self::expect_data(Self::send(req).await?)
    }

    async fn delete(&self, path: &str) -> Result<(), String> {
        let req = self.with_auth(self.client.delete(format!("{}{}", self.base_url, path)));
        Self::send::<serde_json::Value>(req).await.map(|_| ())
    }

    // User operations
    pub async fn list_users(&self) -> Result<Vec<UserInfo>, String> {
        self.get("/api/users").await
    }

    pub async fn create_user(
        &self,
        username: &str,
        password: &str,
        role: Option<&str>,
    ) -> Result<UserInfo, String> {
        self.post(
            "/api/users",
            &CreateUserRequest {
                username: username.to_string(),
                password: password.to_string(),
                role: role.map(String::from),
                display_name: None,
            },
        )
        .await
    }

    pub async fn delete_user(&self, username: &str) -> Result<(), String> {
        self.delete(&format!("/api/users/{}", seg(username))).await
    }

    pub async fn get_user(&self, username: &str) -> Result<UserInfo, String> {
        self.get(&format!("/api/users/{}", seg(username))).await
    }

    /// PUT /api/users/{username} with any combination of fields.
    pub async fn update_user(
        &self,
        username: &str,
        update: &UpdateUserRequest,
    ) -> Result<UserInfo, String> {
        self.put(&format!("/api/users/{}", seg(username)), update)
            .await
    }

    /// Reset a user's password (admin reset via PUT /api/users/{username}).
    pub async fn set_password(&self, username: &str, password: &str) -> Result<UserInfo, String> {
        self.update_user(
            username,
            &UpdateUserRequest {
                password: Some(password.to_string()),
                ..Default::default()
            },
        )
        .await
    }

    // Group operations
    pub async fn list_groups(&self) -> Result<Vec<GroupInfo>, String> {
        self.get("/api/groups").await
    }

    /// Create a group. An empty `email` lets the server default it to
    /// `<name>@<domain>`.
    pub async fn create_group(&self, name: &str, email: &str) -> Result<GroupInfo, String> {
        self.post(
            "/api/groups",
            &CreateGroupRequest {
                name: name.to_string(),
                email: Some(email.to_string()).filter(|e| !e.trim().is_empty()),
                description: None,
                members: vec![],
            },
        )
        .await
    }

    pub async fn get_group(&self, name: &str) -> Result<GroupInfo, String> {
        self.get(&format!("/api/groups/{}", seg(name))).await
    }

    pub async fn delete_group(&self, name: &str) -> Result<(), String> {
        self.delete(&format!("/api/groups/{}", seg(name))).await
    }

    pub async fn add_group_member(&self, group: &str, username: &str) -> Result<(), String> {
        self.post_unit(
            &format!("/api/groups/{}/members", seg(group)),
            &GroupMemberRequest {
                username: username.to_string(),
            },
        )
        .await
    }

    pub async fn remove_group_member(&self, group: &str, username: &str) -> Result<(), String> {
        self.delete(&format!(
            "/api/groups/{}/members/{}",
            seg(group),
            seg(username)
        ))
        .await
    }

    // App passwords
    pub async fn list_app_passwords(
        &self,
        username: &str,
    ) -> Result<Vec<RemoteAppPassword>, String> {
        self.get(&format!("/api/users/{}/app-passwords", seg(username)))
            .await
    }

    pub async fn create_app_password(
        &self,
        username: &str,
        label: Option<&str>,
        expires_days: Option<u32>,
    ) -> Result<AppPasswordResponse, String> {
        self.post(
            &format!("/api/users/{}/app-passwords", seg(username)),
            &AppPasswordRequest {
                label: label.map(String::from),
                expires_days,
            },
        )
        .await
    }

    pub async fn revoke_app_password(&self, username: &str, id: &str) -> Result<(), String> {
        self.delete(&format!(
            "/api/users/{}/app-passwords/{}",
            seg(username),
            seg(id)
        ))
        .await
    }

    // Status
    pub async fn status(&self) -> Result<ServerStatus, String> {
        self.get("/api/status").await
    }

    // SSO
    pub async fn sso_status(&self) -> Result<RemoteSsoStatus, String> {
        self.get("/api/sso/status").await
    }

    // LDAP
    pub async fn ldap_test(&self) -> Result<String, String> {
        self.post("/api/ldap/test", &()).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ldap::LdapConfig;
    use crate::sso::SsoConfig;
    use tempfile::tempdir;

    #[test]
    fn remote_base_url_defaults_to_https_and_guards_plain_http() {
        assert_eq!(
            remote_base_url("mail.example.com:8025/", false),
            Ok("https://mail.example.com:8025".to_string())
        );
        // A host that merely starts with "http" is not a scheme.
        assert_eq!(
            remote_base_url("httpbin.example.com", false),
            Ok("https://httpbin.example.com".to_string())
        );
        for loopback in [
            "http://localhost:8025",
            "http://127.0.0.1:8025",
            "http://[::1]:8025",
            "http://api.localhost",
        ] {
            assert!(remote_base_url(loopback, false).is_ok(), "{}", loopback);
        }
        let err = remote_base_url("http://mail.example.com:8025", false).unwrap_err();
        assert!(err.contains("--insecure"), "{}", err);
        assert!(remote_base_url("http://10.0.0.5:8025", false).is_err());
        assert!(remote_base_url("http://mail.example.com:8025", true).is_ok());
        assert!(remote_base_url("ftp://mail.example.com", true).is_err());
        assert!(remote_base_url("  ", false).is_err());
    }

    async fn test_state(dir: &std::path::Path, api_key: Option<&str>) -> ApiState {
        let data_dir = dir.to_path_buf();
        let user_manager = Arc::new(UserManager::new("example.com".into(), data_dir.clone()));
        let storage = Arc::new(Storage::new(data_dir.clone(), Arc::clone(&user_manager)));
        ApiState {
            user_manager,
            group_manager: Arc::new(GroupManager::new(data_dir.clone())),
            storage,
            ldap_client: Arc::new(LdapClient::new(LdapConfig::default())),
            sso_manager: Arc::new(SsoManager::new(SsoConfig::default(), data_dir.clone())),
            crypto_manager: Some(Arc::new(CryptoManager::with_enabled(data_dir, true))),
            config: AdminApiConfig {
                api_key: api_key.map(String::from),
                port: 0,
                bind_address: "127.0.0.1".into(),
                enabled: true,
            },
            domain: "example.com".into(),
            tokens: SessionStore::new(),
        }
    }

    /// Serve the router on an ephemeral port and return its base URL.
    async fn serve(state: ApiState) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let router = create_router(state);
        tokio::spawn(async move {
            axum::serve(
                listener,
                router.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .unwrap();
        });
        format!("http://{}", addr)
    }

    #[test]
    fn test_ct_eq_and_key_matching() {
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"abcd"));
        assert!(api_key_matches("secret", Some("secret")));
        assert!(!api_key_matches("", Some("")));
        assert!(!api_key_matches("", Some("   ")));
        assert!(!api_key_matches("", None));
        assert!(!api_key_matches("x", None));
        assert!(!api_key_matches("", Some("secret")));
    }

    #[test]
    fn test_resolve_group_email() {
        assert_eq!(
            resolve_group_email("dev", None, "example.com"),
            "dev@example.com"
        );
        assert_eq!(
            resolve_group_email("dev", Some(""), "example.com"),
            "dev@example.com"
        );
        assert_eq!(
            resolve_group_email("dev", Some("dev"), "example.com"),
            "dev@example.com"
        );
        assert_eq!(
            resolve_group_email("dev", Some("team@other.org"), "example.com"),
            "team@other.org"
        );
    }

    #[tokio::test]
    async fn test_router_builds_and_param_routes_work() {
        let dir = tempdir().unwrap();
        let state = test_state(dir.path(), Some("secret-key")).await;
        state
            .group_manager
            .create("devs", "devs@example.com", "admin")
            .await
            .unwrap();
        let base = serve(state).await;
        let client = reqwest::Client::new();

        // Parameterised route resolves (would 404/panic with `:param` syntax)
        let resp = client
            .get(format!("{}/api/groups/devs", base))
            .header("X-API-Key", "secret-key")
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let body: ApiResponse<GroupInfo> = resp.json().await.unwrap();
        assert_eq!(body.data.unwrap().name, "devs");

        let resp = client
            .get(format!("{}/api/users/nobody", base))
            .header("Authorization", "Bearer secret-key")
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 404);
    }

    #[tokio::test]
    async fn test_empty_api_key_rejected() {
        let dir = tempdir().unwrap();
        // Even if an empty key slipped into config, it must never match.
        let state = test_state(dir.path(), Some("")).await;
        let base = serve(state).await;
        let client = reqwest::Client::new();

        for req in [
            client
                .get(format!("{}/api/status", base))
                .header("X-API-Key", ""),
            client
                .get(format!("{}/api/status", base))
                .header("Authorization", "Bearer "),
            client.get(format!("{}/api/status", base)),
        ] {
            assert_eq!(req.send().await.unwrap().status(), 401);
        }
    }

    #[tokio::test]
    async fn test_create_group_persists_description_and_members() {
        let dir = tempdir().unwrap();
        let state = test_state(dir.path(), Some("k")).await;
        let gm = Arc::clone(&state.group_manager);
        let base = serve(state).await;

        let resp = reqwest::Client::new()
            .post(format!("{}/api/groups", base))
            .header("X-API-Key", "k")
            .json(&serde_json::json!({
                "name": "ops",
                "description": "Operations",
                "members": ["bob"]
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);

        let g = gm.get("ops").await.unwrap();
        assert_eq!(g.description, "Operations");
        assert_eq!(g.email, "ops@example.com");
        assert_eq!(g.owner, "admin");
        assert!(g.is_member("bob"));
        assert!(!g.is_member(API_KEY_USER));
        // The real "admin" account is not forced in as a member.
        assert!(!g.is_member("admin"));
        assert_eq!(g.members.len(), 1);

        // Remote client unit endpoints (data: null) succeed
        let client = RemoteClient::new(&base, false)
            .unwrap()
            .with_api_key("k".into());
        client.add_group_member("ops", "carol").await.unwrap();
        assert!(gm.get("ops").await.unwrap().is_member("carol"));
        client.remove_group_member("ops", "carol").await.unwrap();
        client.delete_group("ops").await.unwrap();
        assert!(gm.get("ops").await.is_none());
    }

    #[tokio::test]
    async fn login_with_password_change_required_is_403_with_hint() {
        let dir = tempdir().unwrap();
        let state = test_state(dir.path(), None).await;
        state
            .user_manager
            .create_user("adm", "password123", Some(UserRole::Admin))
            .await
            .unwrap();
        state
            .user_manager
            .update_user("adm", |u| u.password_change_required = true)
            .await
            .unwrap();
        let base = serve(state.clone()).await;

        let resp = reqwest::Client::new()
            .post(format!("{}/api/auth/login", base))
            .json(&serde_json::json!({"username": "adm", "password": "password123"}))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 403);
        let body: ApiResponse<()> = resp.json().await.unwrap();
        assert_eq!(body.error.as_deref(), Some("password_change_required"));
        assert!(body.hint.unwrap().contains("POST /api/account/password"));

        // The remote client surfaces the hint; no token was issued.
        let mut client = RemoteClient::new(&base, false).unwrap();
        let err = client.login("adm", "password123").await.unwrap_err();
        assert!(err.starts_with("password_change_required ("), "{}", err);
        assert!(client.token.is_none());

        // Changing the password (no token) unlocks login.
        client
            .change_password("adm", "password123", "newpassword1")
            .await
            .unwrap();
        client.login("adm", "newpassword1").await.unwrap();
    }

    #[tokio::test]
    async fn account_password_endpoint_needs_no_auth_and_maps_errors() {
        let dir = tempdir().unwrap();
        // An API key is configured, but the endpoint does not need it.
        let state = test_state(dir.path(), Some("k")).await;
        state
            .user_manager
            .create_user("alice", "password123", None)
            .await
            .unwrap();
        let um = Arc::clone(&state.user_manager);
        let base = serve(state).await;
        let http = reqwest::Client::new();
        let post = |body: serde_json::Value| {
            http.post(format!("{}/api/account/password", base))
                .json(&body)
                .send()
        };

        // Wrong current password and unknown user: the same generic 401.
        let mut messages = Vec::new();
        for (user, current) in [("alice", "wrongpass"), ("nobody", "password123")] {
            let resp = post(serde_json::json!({
                "username": user, "current_password": current, "new_password": "newpassword1"
            }))
            .await
            .unwrap();
            assert_eq!(resp.status(), 401);
            let body: ApiResponse<()> = resp.json().await.unwrap();
            messages.push(body.error.unwrap());
        }
        assert_eq!(messages[0], messages[1]);

        // Policy violation: 400.
        let resp = post(serde_json::json!({
            "username": "alice", "current_password": "password123", "new_password": "short"
        }))
        .await
        .unwrap();
        assert_eq!(resp.status(), 400);

        // Success: 200, and the new password works.
        let resp = post(serde_json::json!({
            "username": "alice", "current_password": "password123", "new_password": "newpassword1"
        }))
        .await
        .unwrap();
        assert_eq!(resp.status(), 200);
        assert!(
            um.get_user("alice")
                .await
                .unwrap()
                .verify_password("newpassword1")
        );

        // Repeated wrong guesses lock this peer out: 429 (as on the web page).
        let mut last = 0;
        for _ in 0..6 {
            last = post(serde_json::json!({
                "username": "alice", "current_password": "wrongpass", "new_password": "newpassword2"
            }))
            .await
            .unwrap()
            .status()
            .as_u16();
        }
        assert_eq!(last, 429);
    }

    #[tokio::test]
    async fn create_group_with_unknown_member_leaves_no_group() {
        let dir = tempdir().unwrap();
        let state = test_state(dir.path(), Some("k")).await;
        state
            .group_manager
            .attach_user_manager(Arc::clone(&state.user_manager));
        state
            .user_manager
            .create_user("bob", "password123", None)
            .await
            .unwrap();
        let gm = Arc::clone(&state.group_manager);
        let base = serve(state).await;
        let http = reqwest::Client::new();

        let resp = http
            .post(format!("{}/api/groups", base))
            .header("X-API-Key", "k")
            .json(&serde_json::json!({"name": "ops", "members": ["bob", "ghost"]}))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 400);
        let body: ApiResponse<()> = resp.json().await.unwrap();
        assert_eq!(body.error.as_deref(), Some("user ghost does not exist"));
        assert!(gm.get("ops").await.is_none());

        // Adding an unknown member to an existing group fails the same way.
        let client = RemoteClient::new(&base, false)
            .unwrap()
            .with_api_key("k".into());
        client.create_group("ops", "ops@example.com").await.unwrap();
        let err = client.add_group_member("ops", "ghost").await.unwrap_err();
        assert_eq!(err, "user ghost does not exist");
        client.add_group_member("ops", "bob").await.unwrap();

        // Deleting the user removes them from the group.
        client.delete_user("bob").await.unwrap();
        assert!(!gm.get("ops").await.unwrap().is_member("bob"));
    }

    #[tokio::test]
    async fn test_login_failure_is_error() {
        let dir = tempdir().unwrap();
        let state = test_state(dir.path(), None).await;
        let base = serve(state).await;
        let mut client = RemoteClient::new(&base, false).unwrap();
        let err = client.login("nobody", "wrong-password").await.unwrap_err();
        assert!(err.contains("Invalid credentials"), "{}", err);
    }

    #[tokio::test]
    async fn test_update_user_rejects_unknown_role() {
        let dir = tempdir().unwrap();
        let state = test_state(dir.path(), Some("k")).await;
        state
            .user_manager
            .create_user("alice", "password123", None)
            .await
            .unwrap();
        let base = serve(state).await;
        let client = RemoteClient::new(&base, false)
            .unwrap()
            .with_api_key("k".into());
        let err = client
            .update_user(
                "alice",
                &UpdateUserRequest {
                    role: Some("emperor".into()),
                    ..Default::default()
                },
            )
            .await
            .unwrap_err();
        assert!(err.contains("Unknown role"), "{}", err);
    }

    /// Create an account with `role` and an API session token for it.
    async fn session_for(state: &ApiState, username: &str, role: UserRole) -> String {
        let user = state
            .user_manager
            .create_user(username, "password123", Some(role))
            .await
            .unwrap();
        state
            .tokens
            .create(ApiToken::for_user(&user), TOKEN_TTL)
            .await
    }

    #[tokio::test]
    async fn expired_session_token_returns_401_and_is_removed() {
        let dir = tempdir().unwrap();
        let state = test_state(dir.path(), None).await;
        let adm = state
            .user_manager
            .create_user("adm", "password123", Some(UserRole::Admin))
            .await
            .unwrap();
        let token = state
            .tokens
            .create_expiring_at(ApiToken::for_user(&adm), Instant::now())
            .await;
        let tokens = state.tokens.clone();
        let base = serve(state).await;

        let resp = reqwest::Client::new()
            .get(format!("{}/api/status", base))
            .bearer_auth(&token)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 401);
        assert!(!tokens.contains(&token).await);
    }

    #[tokio::test]
    async fn session_token_rejected_after_role_demotion() {
        let dir = tempdir().unwrap();
        let state = test_state(dir.path(), None).await;
        let token = session_for(&state, "adm", UserRole::Admin).await;
        let um = Arc::clone(&state.user_manager);
        let tokens = state.tokens.clone();
        let base = serve(state).await;
        let client = reqwest::Client::new();

        let status = |c: &reqwest::Client| {
            c.get(format!("{}/api/status", base))
                .bearer_auth(&token)
                .send()
        };
        assert_eq!(status(&client).await.unwrap().status(), 200);

        um.update_user("adm", |u| u.role = UserRole::User)
            .await
            .unwrap();
        assert_eq!(status(&client).await.unwrap().status(), 401);
        assert!(!tokens.contains(&token).await);

        // Restoring the role does not revive the purged token.
        um.update_user("adm", |u| u.role = UserRole::Admin)
            .await
            .unwrap();
        assert_eq!(status(&client).await.unwrap().status(), 401);
    }

    #[tokio::test]
    async fn login_prunes_expired_tokens() {
        let dir = tempdir().unwrap();
        let state = test_state(dir.path(), None).await;
        let adm = state
            .user_manager
            .create_user("adm", "password123", Some(UserRole::Admin))
            .await
            .unwrap();
        let stale = state
            .tokens
            .create_expiring_at(ApiToken::for_user(&adm), Instant::now())
            .await;
        let tokens = state.tokens.clone();
        let base = serve(state).await;
        assert!(tokens.contains(&stale).await);

        let mut client = RemoteClient::new(&base, false).unwrap();
        client.login("adm", "password123").await.unwrap();
        assert!(!tokens.contains(&stale).await);
        // The new token works.
        client.status().await.unwrap();
    }

    #[tokio::test]
    async fn superadmin_creation_requires_superadmin() {
        let dir = tempdir().unwrap();
        let state = test_state(dir.path(), Some("k")).await;
        let admin_token = session_for(&state, "adm", UserRole::Admin).await;
        let super_token = session_for(&state, "root", UserRole::SuperAdmin).await;
        let um = Arc::clone(&state.user_manager);
        let base = serve(state).await;
        let client = reqwest::Client::new();
        let create = |token: &str, name: &str, role: &str| {
            client
                .post(format!("{}/api/users", base))
                .bearer_auth(token)
                .json(&serde_json::json!({
                    "username": name,
                    "password": "password123",
                    "role": role,
                }))
                .send()
        };

        // A plain admin cannot create admins or super admins...
        assert_eq!(
            create(&admin_token, "boss", "superadmin")
                .await
                .unwrap()
                .status(),
            403
        );
        assert_eq!(
            create(&admin_token, "boss", "admin")
                .await
                .unwrap()
                .status(),
            403
        );
        assert!(um.get_user("boss").await.is_none());
        // ...but can create regular users.
        assert_eq!(
            create(&admin_token, "carol", "user")
                .await
                .unwrap()
                .status(),
            200
        );

        // A super admin (or the API key) can.
        assert_eq!(
            create(&super_token, "boss", "superadmin")
                .await
                .unwrap()
                .status(),
            200
        );
        assert_eq!(
            create("k", "boss2", "superadmin").await.unwrap().status(),
            200
        );
        assert_eq!(
            um.get_user("boss").await.unwrap().role,
            UserRole::SuperAdmin
        );
    }

    #[tokio::test]
    async fn update_user_permission_checked_before_password_change() {
        let dir = tempdir().unwrap();
        let state = test_state(dir.path(), None).await;
        let admin_token = session_for(&state, "adm", UserRole::Admin).await;
        state
            .user_manager
            .create_user("bob", "password123", None)
            .await
            .unwrap();
        let um = Arc::clone(&state.user_manager);
        let base = serve(state).await;

        // Admins may not change roles, so the whole update is refused and
        // the password stays unchanged.
        let resp = reqwest::Client::new()
            .put(format!("{}/api/users/bob", base))
            .bearer_auth(&admin_token)
            .json(&serde_json::json!({
                "password": "new-password-456",
                "role": "admin",
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 403);
        let bob = um.get_user("bob").await.unwrap();
        assert!(bob.verify_password("password123"));
        assert!(!bob.verify_password("new-password-456"));
        assert_eq!(bob.role, UserRole::User);
    }

    #[tokio::test]
    async fn app_password_for_superadmin_requires_superadmin() {
        let dir = tempdir().unwrap();
        let state = test_state(dir.path(), None).await;
        let admin_token = session_for(&state, "adm", UserRole::Admin).await;
        state
            .user_manager
            .create_user("root", "password123", Some(UserRole::SuperAdmin))
            .await
            .unwrap();
        let base = serve(state).await;

        let resp = reqwest::Client::new()
            .post(format!("{}/api/users/root/app-passwords", base))
            .bearer_auth(&admin_token)
            .json(&serde_json::json!({}))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 403);
    }

    #[tokio::test]
    async fn revoke_unknown_app_password_is_404() {
        let dir = tempdir().unwrap();
        let state = test_state(dir.path(), Some("k")).await;
        let base = serve(state).await;
        let resp = reqwest::Client::new()
            .delete(format!("{}/api/users/bob/app-passwords/nope", base))
            .header("X-API-Key", "k")
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 404);
    }

    #[tokio::test]
    async fn create_app_password_for_unknown_user_is_404() {
        let dir = tempdir().unwrap();
        let state = test_state(dir.path(), Some("k")).await;
        let sso = Arc::clone(&state.sso_manager);
        let base = serve(state).await;
        let resp = reqwest::Client::new()
            .post(format!("{}/api/users/ghost/app-passwords", base))
            .header("X-API-Key", "k")
            .json(&serde_json::json!({}))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 404);
        assert!(sso.list_app_passwords("ghost").await.is_empty());
    }

    /// Write `users` (already created in a scratch manager) to `dir` as
    /// `users.json` with their usernames replaced by `rename` and return a
    /// manager loaded from it. Bypasses `create_user` (e.g. for reserved
    /// names an older version may have stored).
    async fn load_renamed_user(
        dir: &std::path::Path,
        role: UserRole,
        rename: &str,
    ) -> Arc<UserManager> {
        let scratch = UserManager::new("example.com".into(), dir.join("scratch"));
        let mut user = scratch
            .create_user("placeholder", "password123", Some(role))
            .await
            .unwrap();
        user.username = rename.to_string();
        let map: std::collections::HashMap<String, UserAccount> =
            [(rename.to_string(), user)].into_iter().collect();
        std::fs::write(dir.join("users.json"), serde_json::to_vec(&map).unwrap()).unwrap();
        let um = Arc::new(UserManager::new("example.com".into(), dir.to_path_buf()));
        um.load().await.unwrap();
        um
    }

    #[tokio::test]
    async fn account_named_like_the_api_key_does_not_get_api_key_powers() {
        let dir = tempdir().unwrap();
        let mut state = test_state(dir.path(), Some("k")).await;
        // An Admin (not super admin) account literally named "api-key".
        state.user_manager = load_renamed_user(dir.path(), UserRole::Admin, API_KEY_USER).await;
        let user = state.user_manager.get_user(API_KEY_USER).await.unwrap();
        let token = state
            .tokens
            .create(ApiToken::for_user(&user), TOKEN_TTL)
            .await;
        let um = Arc::clone(&state.user_manager);
        let base = serve(state).await;
        let create = |auth: &str| {
            reqwest::Client::new()
                .post(format!("{}/api/users", base))
                .bearer_auth(auth)
                .json(&serde_json::json!({
                    "username": "boss", "password": "password123", "role": "superadmin"
                }))
                .send()
        };

        // The token is accepted, but acts with the account's own (Admin)
        // role: creating a super admin is refused.
        assert_eq!(create(&token).await.unwrap().status(), 403);
        assert!(um.get_user("boss").await.is_none());
        // The real API key can.
        assert_eq!(create("k").await.unwrap().status(), 200);
    }

    #[tokio::test]
    async fn session_token_dies_on_password_change_or_required_change() {
        let dir = tempdir().unwrap();
        let state = test_state(dir.path(), Some("k")).await;
        let token = session_for(&state, "adm", UserRole::Admin).await;
        let token2 = session_for(&state, "adm2", UserRole::Admin).await;
        let um = Arc::clone(&state.user_manager);
        let tokens = state.tokens.clone();
        let base = serve(state).await;
        let client = reqwest::Client::new();
        let status = |t: &str| {
            client
                .get(format!("{}/api/status", base))
                .bearer_auth(t)
                .send()
        };
        assert_eq!(status(&token).await.unwrap().status(), 200);
        assert_eq!(status(&token2).await.unwrap().status(), 200);

        // Changing the password (here: an admin reset via the API key)
        // invalidates the old token.
        tokio::time::sleep(Duration::from_millis(5)).await;
        let client_k = RemoteClient::new(&base, false)
            .unwrap()
            .with_api_key("k".into());
        client_k
            .set_password("adm", "new-password-1")
            .await
            .unwrap();
        assert_eq!(status(&token).await.unwrap().status(), 401);
        assert!(!tokens.contains(&token).await);

        // A pending required change invalidates it too.
        um.update_user("adm2", |u| u.password_change_required = true)
            .await
            .unwrap();
        assert_eq!(status(&token2).await.unwrap().status(), 401);
    }

    #[tokio::test]
    async fn admin_password_reset_revokes_app_passwords_and_reports_count() {
        let dir = tempdir().unwrap();
        let state = test_state(dir.path(), Some("k")).await;
        state
            .user_manager
            .create_user("bob", "password123", None)
            .await
            .unwrap();
        let sso = Arc::clone(&state.sso_manager);
        let base = serve(state).await;
        let client = RemoteClient::new(&base, false)
            .unwrap()
            .with_api_key("k".into());
        client
            .create_app_password("bob", Some("phone"), None)
            .await
            .unwrap();
        client
            .create_app_password("bob", Some("mail"), None)
            .await
            .unwrap();

        let info = client.set_password("bob", "new-password-1").await.unwrap();
        assert_eq!(info.revoked_app_passwords, Some(2));
        assert!(sso.list_app_passwords("bob").await.is_empty());

        // A display-name-only update does not report revocations.
        let info = client
            .update_user(
                "bob",
                &UpdateUserRequest {
                    display_name: Some("  Bob  ".into()),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(info.revoked_app_passwords, None);
        assert_eq!(info.display_name.as_deref(), Some("Bob"));
    }

    #[tokio::test]
    async fn update_user_step_failure_is_400_with_joined_errors() {
        let dir = tempdir().unwrap();
        let state = test_state(dir.path(), Some("k")).await;
        state
            .user_manager
            .create_user("bob", "password123", None)
            .await
            .unwrap();
        let um = Arc::clone(&state.user_manager);
        let base = serve(state).await;
        let resp = reqwest::Client::new()
            .put(format!("{}/api/users/bob", base))
            .header("X-API-Key", "k")
            .json(&serde_json::json!({"password": "short", "display_name": "Bobby"}))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 400);
        let body: ApiResponse<()> = resp.json().await.unwrap();
        assert!(body.error.unwrap().starts_with("Password: "));
        // Later steps still ran.
        assert_eq!(
            um.get_user("bob")
                .await
                .unwrap()
                .settings
                .display_name
                .as_deref(),
            Some("Bobby")
        );
    }

    #[tokio::test]
    async fn api_delete_user_removes_mailbox_and_sso() {
        let dir = tempdir().unwrap();
        let state = test_state(dir.path(), Some("k")).await;
        state
            .group_manager
            .attach_user_manager(Arc::clone(&state.user_manager));
        state
            .user_manager
            .create_user("bob", "password123", None)
            .await
            .unwrap();
        state.storage.ensure_mailbox("bob").await;
        state
            .sso_manager
            .generate_app_password("bob", "phone", None)
            .await
            .unwrap();
        let crypto = Arc::clone(state.crypto_manager.as_ref().unwrap());
        crypto.generate_keypair("bob", "password123").await.unwrap();
        state
            .group_manager
            .create_with_members("team", "team@example.com", "admin", None, &["bob".into()])
            .await
            .unwrap();
        let (storage, sso, gm) = (
            Arc::clone(&state.storage),
            Arc::clone(&state.sso_manager),
            Arc::clone(&state.group_manager),
        );
        let base = serve(state).await;

        let client = RemoteClient::new(&base, false)
            .unwrap()
            .with_api_key("k".into());
        client.delete_user("bob").await.unwrap();
        assert!(storage.message_meta("bob").await.is_none());
        assert!(sso.get_user_data("bob").await.is_none());
        assert!(!crypto.has_keys("bob").await);
        assert!(!gm.get("team").await.unwrap().is_member("bob"));
    }
}
