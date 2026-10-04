//! KISS Admin Web Interface
//!
//! A simple web-based admin dashboard using Actix-web and Handlebars.
//! Styled with a pre-built Tailwind stylesheet served from `/static/app.css`
//! (no external resources; see [`CONTENT_SECURITY_POLICY`]).

use actix_web::{
    HttpRequest, HttpResponse,
    cookie::{Cookie, SameSite},
    http::StatusCode,
    middleware::DefaultHeaders,
    web,
};
use chrono::{DateTime, Utc};
use handlebars::Handlebars;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::Arc;
use std::time::Duration;

use crate::admin_api::ct_eq;
pub(crate) use crate::admin_rules::SessionStore;
use crate::admin_rules::{
    PlannedUserUpdate, apply_user_update, check_create_role, check_update_permissions,
    cleanup_deleted_user, client_ip, generate_session_token, password_change_message,
    password_change_status, session_is_current,
};
use crate::config::{env_bool, env_nonempty, env_port};
use crate::crypto::CryptoManager;
use crate::groups::{GroupError, GroupManager};
use crate::ldap::LdapClient;
use crate::sso::SsoManager;
use crate::storage::Storage;
use crate::users::{
    AccountStatus, PasswordChangeFailure, UserAccount, UserError, UserManager, UserRole,
};

/// Name of the session cookie.
const SESSION_COOKIE: &str = "kiss_session";

/// Name of the cookie carrying the login form's CSRF token (double submit).
const LOGIN_CSRF_COOKIE: &str = "kiss_login_csrf";

/// Name of the cookie carrying the password-change form's CSRF token
/// (double submit).
const ACCOUNT_CSRF_COOKIE: &str = "kiss_account_csrf";

/// Lifetime of a web admin session.
const SESSION_TTL: Duration = Duration::from_secs(8 * 3600);

/// Lifetime of the login form's CSRF cookie.
const LOGIN_CSRF_TTL: Duration = Duration::from_secs(3600);

/// Content-Security-Policy for every response: only same-origin
/// stylesheets and scripts, no framing, forms post only to this origin.
const CONTENT_SECURITY_POLICY: &str = "default-src 'self'; style-src 'self'; script-src 'self'; frame-ancestors 'none'; form-action 'self'";

/// Pre-built stylesheet (Tailwind, generated for exactly the classes used by
/// the templates below) served at `/static/app.css`.
const APP_CSS: &str = include_str!("admin_assets/app.css");

/// Script served at `/static/app.js` (confirmation dialogs; no inline JS so
/// `script-src 'self'` holds).
const APP_JS: &str = include_str!("admin_assets/app.js");

/// Is this bind address loopback-only (`127.0.0.0/8`, `::1`, `localhost`)?
fn is_loopback_bind(addr: &str) -> bool {
    let host = addr.trim().trim_start_matches('[').trim_end_matches(']');
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
}

/// Web admin configuration
#[derive(Debug, Clone)]
pub struct WebAdminConfig {
    pub enabled: bool,
    pub port: u16,
    pub bind_address: String,
    /// Mark the session cookie `Secure`. Defaults to true unless the bind
    /// address is loopback; `KISS_MAIL_WEB_SECURE_COOKIE` overrides either way.
    pub secure_cookie: bool,
    /// Let an admin account's first SSO login bind the identity provider
    /// subject automatically (`SSO_AUTO_BIND_ADMINS=true`; default false).
    /// Otherwise admin identities must be linked explicitly (`sso-link`).
    pub sso_auto_bind_admins: bool,
}

impl WebAdminConfig {
    /// Configuration from the environment. An invalid `KISS_MAIL_WEB_PORT`
    /// is an error, so a typo fails at startup instead of silently using the
    /// default port.
    pub fn from_env() -> Result<Self, String> {
        let bind_address =
            env_nonempty("KISS_MAIL_WEB_BIND").unwrap_or_else(|| "127.0.0.1".to_string());
        Ok(Self {
            secure_cookie: env_bool(
                "KISS_MAIL_WEB_SECURE_COOKIE",
                !is_loopback_bind(&bind_address),
            ),
            enabled: env_bool("KISS_MAIL_WEB_ENABLED", true),
            port: env_port("KISS_MAIL_WEB_PORT", 8080)?,
            bind_address,
            sso_auto_bind_admins: env_bool("SSO_AUTO_BIND_ADMINS", false),
        })
    }
}

/// The server components the web admin works on (see [`run_web_server`]).
pub struct WebServices {
    pub user_manager: Arc<UserManager>,
    pub group_manager: Arc<GroupManager>,
    pub ldap_client: Arc<LdapClient>,
    pub sso_manager: Arc<SsoManager>,
    pub storage: Arc<Storage>,
    pub crypto_manager: Option<Arc<CryptoManager>>,
}

/// Shared state for web handlers
pub struct WebState {
    pub user_manager: Arc<UserManager>,
    pub group_manager: Arc<GroupManager>,
    pub ldap_client: Arc<LdapClient>,
    pub sso_manager: Arc<SsoManager>,
    pub storage: Arc<Storage>,
    /// Encryption key manager, so deleting a user also removes their keys.
    pub crypto_manager: Option<Arc<CryptoManager>>,
    pub hbs: Handlebars<'static>,
    pub domain: String,
    /// Server-side session store (cookie holds only a random token)
    pub sessions: SessionStore<WebSession>,
    /// Whether to set the `Secure` flag on the session cookie
    pub secure_cookie: bool,
    /// See [`WebAdminConfig::sso_auto_bind_admins`].
    pub sso_auto_bind_admins: bool,
}

/// A server-side web admin session (also the logged-in admin of a request).
#[derive(Debug, Clone)]
pub struct WebSession {
    /// Logged-in admin.
    pub username: String,
    /// Synchronizer token every state-changing POST must echo back.
    pub csrf: String,
    /// The account's `password_changed_at` at login; the session dies when
    /// the password changes.
    pub password_changed_at: DateTime<Utc>,
}

impl WebSession {
    fn new(user: &UserAccount) -> Self {
        Self {
            username: user.username.clone(),
            csrf: generate_session_token(),
            password_changed_at: user.password_changed_at,
        }
    }
}

// ============================================================================
// Templates (embedded for simplicity)
// ============================================================================

const BASE_TEMPLATE: &str = r#"<!DOCTYPE html>
<html lang="en" class="h-full bg-gray-50">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{title}} - KISS Mail Admin</title>
    <link rel="stylesheet" href="/static/app.css">
    <script src="/static/app.js" defer></script>
</head>
<body class="h-full">
    <div class="min-h-full">
        <!-- Navigation -->
        <nav class="bg-white shadow-sm border-b border-gray-200">
            <div class="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
                <div class="flex h-16 justify-between">
                    <div class="flex">
                        <div class="flex flex-shrink-0 items-center">
                            <span class="text-xl font-bold text-gray-900">📧 KISS Mail</span>
                        </div>
                        {{#if username}}
                        <div class="hidden sm:ml-8 sm:flex sm:space-x-8">
                            <a href="/admin" class="{{#if nav_dashboard}}border-primary text-gray-900{{else}}border-transparent text-gray-500 hover:border-gray-300 hover:text-gray-700{{/if}} inline-flex items-center border-b-2 px-1 pt-1 text-sm font-medium">
                                Dashboard
                            </a>
                            <a href="/admin/users" class="{{#if nav_users}}border-primary text-gray-900{{else}}border-transparent text-gray-500 hover:border-gray-300 hover:text-gray-700{{/if}} inline-flex items-center border-b-2 px-1 pt-1 text-sm font-medium">
                                Users
                            </a>
                            <a href="/admin/groups" class="{{#if nav_groups}}border-primary text-gray-900{{else}}border-transparent text-gray-500 hover:border-gray-300 hover:text-gray-700{{/if}} inline-flex items-center border-b-2 px-1 pt-1 text-sm font-medium">
                                Groups
                            </a>
                        </div>
                        {{/if}}
                    </div>
                    {{#if username}}
                    <div class="flex items-center">
                        <span class="text-sm text-gray-500 mr-4">{{username}}</span>
                        <a href="{{account_url}}" class="text-sm text-gray-500 hover:text-gray-700 mr-4">Change my password</a>
                        <form action="/admin/logout" method="POST" class="inline">
                            <input type="hidden" name="csrf" value="{{csrf}}">
                            <button type="submit" class="text-sm text-gray-500 hover:text-gray-700">Logout</button>
                        </form>
                    </div>
                    {{/if}}
                </div>
            </div>
        </nav>

        <!-- Main content -->
        <main class="fade-in">
            <div class="mx-auto max-w-7xl py-6 px-4 sm:px-6 lg:px-8">
                {{#if flash_success}}
                <div class="mb-4 rounded-md bg-green-50 p-4">
                    <div class="flex">
                        <div class="flex-shrink-0">
                            <svg class="h-5 w-5 text-green-400" viewBox="0 0 20 20" fill="currentColor">
                                <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.857-9.809a.75.75 0 00-1.214-.882l-3.483 4.79-1.88-1.88a.75.75 0 10-1.06 1.061l2.5 2.5a.75.75 0 001.137-.089l4-5.5z" clip-rule="evenodd" />
                            </svg>
                        </div>
                        <div class="ml-3">
                            <p class="text-sm font-medium text-green-800">{{flash_success}}</p>
                        </div>
                    </div>
                </div>
                {{/if}}
                {{#if flash_error}}
                <div class="mb-4 rounded-md bg-red-50 p-4">
                    <div class="flex">
                        <div class="flex-shrink-0">
                            <svg class="h-5 w-5 text-red-400" viewBox="0 0 20 20" fill="currentColor">
                                <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.28 7.22a.75.75 0 00-1.06 1.06L8.94 10l-1.72 1.72a.75.75 0 101.06 1.06L10 11.06l1.72 1.72a.75.75 0 101.06-1.06L11.06 10l1.72-1.72a.75.75 0 00-1.06-1.06L10 8.94 8.28 7.22z" clip-rule="evenodd" />
                            </svg>
                        </div>
                        <div class="ml-3">
                            <p class="text-sm font-medium text-red-800">{{flash_error}}</p>
                        </div>
                    </div>
                </div>
                {{/if}}
                {{{content}}}
            </div>
        </main>
    </div>
</body>
</html>"#;

const LOGIN_TEMPLATE: &str = r#"<!DOCTYPE html>
<html lang="en" class="h-full bg-gray-50">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login - KISS Mail Admin</title>
    <link rel="stylesheet" href="/static/app.css">
</head>
<body class="h-full">
    <div class="flex min-h-full flex-col justify-center py-12 sm:px-6 lg:px-8">
        <div class="sm:mx-auto sm:w-full sm:max-w-md">
            <h1 class="text-center text-3xl font-bold text-gray-900">📧 KISS Mail</h1>
            <h2 class="mt-2 text-center text-xl text-gray-600">Admin Dashboard</h2>
        </div>

        <div class="mt-8 sm:mx-auto sm:w-full sm:max-w-md">
            <div class="bg-white py-8 px-4 shadow-lg sm:rounded-lg sm:px-10 border border-gray-200">
                {{#if error}}
                <div class="mb-4 rounded-md bg-red-50 p-4">
                    <p class="text-sm text-red-800">{{error}}</p>
                </div>
                {{/if}}
                
                <form class="space-y-6" action="/admin/login" method="POST">
                    <input type="hidden" name="csrf" value="{{csrf}}">
                    <div>
                        <label for="username" class="block text-sm font-medium text-gray-700">Username</label>
                        <div class="mt-1">
                            <input id="username" name="username" type="text" autocomplete="username" required
                                class="block w-full appearance-none rounded-md border border-gray-300 px-3 py-2 placeholder-gray-400 shadow-sm focus:border-blue-500 focus:outline-none focus:ring-blue-500 sm:text-sm">
                        </div>
                    </div>

                    <div>
                        <label for="password" class="block text-sm font-medium text-gray-700">Password</label>
                        <div class="mt-1">
                            <input id="password" name="password" type="password" autocomplete="current-password" required
                                class="block w-full appearance-none rounded-md border border-gray-300 px-3 py-2 placeholder-gray-400 shadow-sm focus:border-blue-500 focus:outline-none focus:ring-blue-500 sm:text-sm">
                        </div>
                    </div>

                    <div>
                        <button type="submit"
                            class="flex w-full justify-center rounded-md border border-transparent bg-blue-600 py-2 px-4 text-sm font-medium text-white shadow-sm hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2">
                            Sign in
                        </button>
                    </div>
                </form>

                {{#if sso_enabled}}
                <div class="mt-6">
                    <a href="/admin/sso/login"
                        class="flex w-full justify-center rounded-md border border-gray-300 bg-white py-2 px-4 text-sm font-medium text-gray-700 shadow-sm hover:bg-gray-50">
                        Sign in with {{sso_provider}}
                    </a>
                </div>
                {{/if}}
            </div>
        </div>
        
        <p class="mt-8 text-center text-sm text-gray-500">
            KISS Mail Server v{{version}}
        </p>
    </div>
</body>
</html>"#;

const ACCOUNT_PASSWORD_CONTENT: &str = r#"
<div class="mb-8">
    <h1 class="text-2xl font-bold text-gray-900">Change your password</h1>
    <p class="mt-1 text-sm text-gray-500">For any mail account on this server.</p>
</div>

{{#if changed}}
<div class="bg-white shadow-sm ring-1 ring-gray-900/5 sm:rounded-xl px-4 py-6 sm:p-8">
    <p class="text-sm text-gray-900">Your password has been changed.</p>
    {{#if is_admin}}
    <p class="mt-4"><a href="/admin/login" class="text-sm font-semibold text-blue-600 hover:text-blue-500">Sign in to the admin dashboard</a></p>
    {{else}}
    <p class="mt-2 text-sm text-gray-500">Use your new password in your mail client.</p>
    {{/if}}
</div>
{{else}}
<div class="bg-white shadow-sm ring-1 ring-gray-900/5 sm:rounded-xl">
    <form action="/account/password" method="POST" class="px-4 py-6 sm:p-8">
        <input type="hidden" name="csrf" value="{{form_csrf}}">
        <div class="grid max-w-2xl grid-cols-1 gap-x-6 gap-y-8 sm:grid-cols-6">
            <div class="sm:col-span-4">
                <label for="username" class="block text-sm font-medium leading-6 text-gray-900">Username</label>
                <div class="mt-2">
                    <input type="text" name="username" id="username" value="{{form_username}}" autocomplete="username" required
                        class="block w-full rounded-md border-0 py-1.5 text-gray-900 shadow-sm ring-1 ring-inset ring-gray-300 focus:ring-2 focus:ring-inset focus:ring-blue-600 sm:text-sm sm:leading-6">
                </div>
            </div>
            <div class="sm:col-span-4">
                <label for="current_password" class="block text-sm font-medium leading-6 text-gray-900">Current password</label>
                <div class="mt-2">
                    <input type="password" name="current_password" id="current_password" autocomplete="current-password" required
                        class="block w-full rounded-md border-0 py-1.5 text-gray-900 shadow-sm ring-1 ring-inset ring-gray-300 focus:ring-2 focus:ring-inset focus:ring-blue-600 sm:text-sm sm:leading-6">
                </div>
            </div>
            <div class="sm:col-span-4">
                <label for="new_password" class="block text-sm font-medium leading-6 text-gray-900">New password <span class="text-gray-400 font-normal">(at least {{min_length}} characters)</span></label>
                <div class="mt-2">
                    <input type="password" name="new_password" id="new_password" autocomplete="new-password" minlength="{{min_length}}" required
                        class="block w-full rounded-md border-0 py-1.5 text-gray-900 shadow-sm ring-1 ring-inset ring-gray-300 focus:ring-2 focus:ring-inset focus:ring-blue-600 sm:text-sm sm:leading-6">
                </div>
            </div>
            <div class="sm:col-span-4">
                <label for="confirm_password" class="block text-sm font-medium leading-6 text-gray-900">Confirm new password</label>
                <div class="mt-2">
                    <input type="password" name="confirm_password" id="confirm_password" autocomplete="new-password" minlength="{{min_length}}" required
                        class="block w-full rounded-md border-0 py-1.5 text-gray-900 shadow-sm ring-1 ring-inset ring-gray-300 focus:ring-2 focus:ring-inset focus:ring-blue-600 sm:text-sm sm:leading-6">
                </div>
            </div>
        </div>
        <div class="mt-6 flex items-center justify-end gap-x-6">
            <button type="submit"
                class="rounded-md bg-blue-600 px-3 py-2 text-sm font-semibold text-white shadow-sm hover:bg-blue-500 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-blue-600">
                Change password
            </button>
        </div>
    </form>
</div>
{{/if}}
"#;

const DASHBOARD_CONTENT: &str = r#"
<div class="mb-8">
    <h1 class="text-2xl font-bold text-gray-900">Dashboard</h1>
    <p class="mt-1 text-sm text-gray-500">Server overview for {{domain}}</p>
</div>

<!-- Stats -->
<div class="grid grid-cols-1 gap-5 sm:grid-cols-2 lg:grid-cols-4">
    <div class="overflow-hidden rounded-lg bg-white px-4 py-5 shadow border border-gray-200">
        <dt class="truncate text-sm font-medium text-gray-500">Total Users</dt>
        <dd class="mt-1 text-3xl font-semibold tracking-tight text-gray-900">{{stats.users}}</dd>
    </div>
    <div class="overflow-hidden rounded-lg bg-white px-4 py-5 shadow border border-gray-200">
        <dt class="truncate text-sm font-medium text-gray-500">Groups</dt>
        <dd class="mt-1 text-3xl font-semibold tracking-tight text-gray-900">{{stats.groups}}</dd>
    </div>
    <div class="overflow-hidden rounded-lg bg-white px-4 py-5 shadow border border-gray-200">
        <dt class="truncate text-sm font-medium text-gray-500">Active Users</dt>
        <dd class="mt-1 text-3xl font-semibold tracking-tight text-gray-900">{{stats.active_users}}</dd>
    </div>
    <div class="overflow-hidden rounded-lg bg-white px-4 py-5 shadow border border-gray-200">
        <dt class="truncate text-sm font-medium text-gray-500">Admins</dt>
        <dd class="mt-1 text-3xl font-semibold tracking-tight text-gray-900">{{stats.admins}}</dd>
    </div>
</div>

<!-- System Status -->
<div class="mt-8">
    <h2 class="text-lg font-medium text-gray-900 mb-4">System Status</h2>
    <div class="overflow-hidden rounded-lg bg-white shadow border border-gray-200">
        <ul role="list" class="divide-y divide-gray-200">
            <li class="px-4 py-4 sm:px-6">
                <div class="flex items-center justify-between">
                    <p class="text-sm font-medium text-gray-900">LDAP Authentication</p>
                    {{#if ldap_enabled}}
                    <span class="inline-flex items-center rounded-full bg-green-100 px-2.5 py-0.5 text-xs font-medium text-green-800">
                        Enabled
                    </span>
                    {{else}}
                    <span class="inline-flex items-center rounded-full bg-gray-100 px-2.5 py-0.5 text-xs font-medium text-gray-800">
                        Disabled
                    </span>
                    {{/if}}
                </div>
            </li>
            <li class="px-4 py-4 sm:px-6">
                <div class="flex items-center justify-between">
                    <p class="text-sm font-medium text-gray-900">SSO Provider</p>
                    {{#if sso_enabled}}
                    <span class="inline-flex items-center rounded-full bg-green-100 px-2.5 py-0.5 text-xs font-medium text-green-800">
                        {{sso_provider}}
                    </span>
                    {{else}}
                    <span class="inline-flex items-center rounded-full bg-gray-100 px-2.5 py-0.5 text-xs font-medium text-gray-800">
                        Disabled
                    </span>
                    {{/if}}
                </div>
            </li>
            <li class="px-4 py-4 sm:px-6">
                <div class="flex items-center justify-between">
                    <p class="text-sm font-medium text-gray-900">Server Version</p>
                    <span class="text-sm text-gray-500">{{version}}</span>
                </div>
            </li>
        </ul>
    </div>
</div>

<!-- Quick Actions -->
<div class="mt-8">
    <h2 class="text-lg font-medium text-gray-900 mb-4">Quick Actions</h2>
    <div class="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
        <a href="/admin/users/new" class="relative block rounded-lg border border-gray-300 bg-white px-6 py-4 shadow-sm hover:border-gray-400 focus:outline-none">
            <span class="text-lg">👤</span>
            <span class="ml-2 text-sm font-medium text-gray-900">Create User</span>
        </a>
        <a href="/admin/groups/new" class="relative block rounded-lg border border-gray-300 bg-white px-6 py-4 shadow-sm hover:border-gray-400 focus:outline-none">
            <span class="text-lg">👥</span>
            <span class="ml-2 text-sm font-medium text-gray-900">Create Group</span>
        </a>
        <a href="/admin/users" class="relative block rounded-lg border border-gray-300 bg-white px-6 py-4 shadow-sm hover:border-gray-400 focus:outline-none">
            <span class="text-lg">📋</span>
            <span class="ml-2 text-sm font-medium text-gray-900">Manage Users</span>
        </a>
    </div>
</div>
"#;

const USERS_CONTENT: &str = r#"
<div class="sm:flex sm:items-center">
    <div class="sm:flex-auto">
        <h1 class="text-2xl font-bold text-gray-900">Users</h1>
        <p class="mt-1 text-sm text-gray-500">Manage user accounts</p>
    </div>
    <div class="mt-4 sm:ml-16 sm:mt-0 sm:flex-none">
        <a href="/admin/users/new"
            class="block rounded-md bg-blue-600 px-3 py-2 text-center text-sm font-semibold text-white shadow-sm hover:bg-blue-500">
            Add User
        </a>
    </div>
</div>

<div class="mt-8 flow-root">
    <div class="-mx-4 -my-2 overflow-x-auto sm:-mx-6 lg:-mx-8">
        <div class="inline-block min-w-full py-2 align-middle sm:px-6 lg:px-8">
            <div class="overflow-hidden shadow ring-1 ring-black ring-opacity-5 sm:rounded-lg">
                <table class="min-w-full divide-y divide-gray-300">
                    <thead class="bg-gray-50">
                        <tr>
                            <th scope="col" class="py-3.5 pl-4 pr-3 text-left text-sm font-semibold text-gray-900 sm:pl-6">Username</th>
                            <th scope="col" class="px-3 py-3.5 text-left text-sm font-semibold text-gray-900">Role</th>
                            <th scope="col" class="px-3 py-3.5 text-left text-sm font-semibold text-gray-900">Status</th>
                            <th scope="col" class="px-3 py-3.5 text-left text-sm font-semibold text-gray-900">Last Login</th>
                            <th scope="col" class="relative py-3.5 pl-3 pr-4 sm:pr-6">
                                <span class="sr-only">Actions</span>
                            </th>
                        </tr>
                    </thead>
                    <tbody class="divide-y divide-gray-200 bg-white">
                        {{#each users}}
                        <tr>
                            <td class="whitespace-nowrap py-4 pl-4 pr-3 text-sm font-medium text-gray-900 sm:pl-6">
                                {{this.username}}
                                {{#if this.display_name}}
                                <span class="text-gray-500 font-normal">({{this.display_name}})</span>
                                {{/if}}
                            </td>
                            <td class="whitespace-nowrap px-3 py-4 text-sm">
                                {{#if this.is_admin}}
                                <span class="inline-flex items-center rounded-full bg-purple-100 px-2.5 py-0.5 text-xs font-medium text-purple-800">
                                    {{this.role}}
                                </span>
                                {{else}}
                                <span class="inline-flex items-center rounded-full bg-gray-100 px-2.5 py-0.5 text-xs font-medium text-gray-800">
                                    {{this.role}}
                                </span>
                                {{/if}}
                            </td>
                            <td class="whitespace-nowrap px-3 py-4 text-sm">
                                {{#if this.is_active}}
                                <span class="inline-flex items-center rounded-full bg-green-100 px-2.5 py-0.5 text-xs font-medium text-green-800">
                                    Active
                                </span>
                                {{else}}
                                <span class="inline-flex items-center rounded-full bg-red-100 px-2.5 py-0.5 text-xs font-medium text-red-800">
                                    {{this.status}}
                                </span>
                                {{/if}}
                            </td>
                            <td class="whitespace-nowrap px-3 py-4 text-sm text-gray-500">{{this.last_login}}</td>
                            <td class="relative whitespace-nowrap py-4 pl-3 pr-4 text-right text-sm font-medium sm:pr-6">
                                <a href="/admin/users/{{this.username}}" class="text-blue-600 hover:text-blue-900 mr-3">Edit</a>
                                {{#unless this.is_current_user}}
                                <form action="/admin/users/{{this.username}}/delete" method="POST" class="inline" data-confirm="Delete this user?">
                                    <input type="hidden" name="csrf" value="{{@root.csrf}}">
                                    <button type="submit" class="text-red-600 hover:text-red-900">Delete</button>
                                </form>
                                {{/unless}}
                            </td>
                        </tr>
                        {{/each}}
                        {{#unless users}}
                        <tr>
                            <td colspan="5" class="px-6 py-4 text-center text-sm text-gray-500">No users found</td>
                        </tr>
                        {{/unless}}
                    </tbody>
                </table>
            </div>
        </div>
    </div>
</div>
"#;

const USER_FORM_CONTENT: &str = r#"
<div class="mb-8">
    <h1 class="text-2xl font-bold text-gray-900">{{#if editing}}Edit User{{else}}Create User{{/if}}</h1>
    <p class="mt-1 text-sm text-gray-500">{{#if editing}}Update user settings{{else}}Add a new user account{{/if}}</p>
</div>

<div class="bg-white shadow-sm ring-1 ring-gray-900/5 sm:rounded-xl">
    <form action="{{form_action}}" method="POST" class="px-4 py-6 sm:p-8">
        <input type="hidden" name="csrf" value="{{csrf}}">
        <div class="grid max-w-2xl grid-cols-1 gap-x-6 gap-y-8 sm:grid-cols-6">
            <div class="sm:col-span-4">
                <label for="username" class="block text-sm font-medium leading-6 text-gray-900">Username</label>
                <div class="mt-2">
                    <input type="text" name="username" id="username" value="{{user.username}}" {{#if editing}}readonly{{/if}}
                        class="block w-full rounded-md border-0 py-1.5 text-gray-900 shadow-sm ring-1 ring-inset ring-gray-300 placeholder:text-gray-400 focus:ring-2 focus:ring-inset focus:ring-blue-600 sm:text-sm sm:leading-6 {{#if editing}}bg-gray-50{{/if}}"
                        required>
                </div>
            </div>

            <div class="sm:col-span-4">
                <label for="password" class="block text-sm font-medium leading-6 text-gray-900">
                    Password {{#if editing}}<span class="text-gray-400 font-normal">(leave blank to keep current)</span>{{/if}}
                </label>
                <div class="mt-2">
                    <input type="password" name="password" id="password"
                        class="block w-full rounded-md border-0 py-1.5 text-gray-900 shadow-sm ring-1 ring-inset ring-gray-300 placeholder:text-gray-400 focus:ring-2 focus:ring-inset focus:ring-blue-600 sm:text-sm sm:leading-6"
                        {{#unless editing}}required{{/unless}}>
                </div>
            </div>

            <div class="sm:col-span-4">
                <label for="display_name" class="block text-sm font-medium leading-6 text-gray-900">Display Name</label>
                <div class="mt-2">
                    <input type="text" name="display_name" id="display_name" value="{{user.display_name}}"
                        class="block w-full rounded-md border-0 py-1.5 text-gray-900 shadow-sm ring-1 ring-inset ring-gray-300 placeholder:text-gray-400 focus:ring-2 focus:ring-inset focus:ring-blue-600 sm:text-sm sm:leading-6">
                </div>
            </div>

            <div class="sm:col-span-3">
                <label for="role" class="block text-sm font-medium leading-6 text-gray-900">Role</label>
                <div class="mt-2">
                    <select id="role" name="role"
                        class="block w-full rounded-md border-0 py-1.5 text-gray-900 shadow-sm ring-1 ring-inset ring-gray-300 focus:ring-2 focus:ring-inset focus:ring-blue-600 sm:text-sm sm:leading-6">
                        <option value="user" {{#if user.is_user}}selected{{/if}}>User</option>
                        <option value="admin" {{#if user.is_admin}}selected{{/if}}>Admin</option>
                        <option value="superadmin" {{#if user.is_superadmin}}selected{{/if}}>Super Admin</option>
                    </select>
                </div>
            </div>

            {{#if editing}}
            <div class="sm:col-span-3">
                <label for="status" class="block text-sm font-medium leading-6 text-gray-900">Status</label>
                <div class="mt-2">
                    <input type="hidden" name="original_status" value="{{user.status}}">
                    <select id="status" name="status"
                        class="block w-full rounded-md border-0 py-1.5 text-gray-900 shadow-sm ring-1 ring-inset ring-gray-300 focus:ring-2 focus:ring-inset focus:ring-blue-600 sm:text-sm sm:leading-6">
                        {{#each statuses}}
                        <option value="{{this.value}}" {{#if this.selected}}selected{{/if}}>{{this.label}}</option>
                        {{/each}}
                    </select>
                </div>
            </div>
            {{/if}}
        </div>

        <div class="mt-6 flex items-center justify-end gap-x-6">
            <a href="/admin/users" class="text-sm font-semibold leading-6 text-gray-900">Cancel</a>
            <button type="submit"
                class="rounded-md bg-blue-600 px-3 py-2 text-sm font-semibold text-white shadow-sm hover:bg-blue-500 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-blue-600">
                {{#if editing}}Save Changes{{else}}Create User{{/if}}
            </button>
        </div>
    </form>
</div>
"#;

const GROUPS_CONTENT: &str = r#"
<div class="sm:flex sm:items-center">
    <div class="sm:flex-auto">
        <h1 class="text-2xl font-bold text-gray-900">Groups</h1>
        <p class="mt-1 text-sm text-gray-500">Manage distribution lists and groups</p>
    </div>
    <div class="mt-4 sm:ml-16 sm:mt-0 sm:flex-none">
        <a href="/admin/groups/new"
            class="block rounded-md bg-blue-600 px-3 py-2 text-center text-sm font-semibold text-white shadow-sm hover:bg-blue-500">
            Add Group
        </a>
    </div>
</div>

<div class="mt-8 flow-root">
    <div class="-mx-4 -my-2 overflow-x-auto sm:-mx-6 lg:-mx-8">
        <div class="inline-block min-w-full py-2 align-middle sm:px-6 lg:px-8">
            <div class="overflow-hidden shadow ring-1 ring-black ring-opacity-5 sm:rounded-lg">
                <table class="min-w-full divide-y divide-gray-300">
                    <thead class="bg-gray-50">
                        <tr>
                            <th scope="col" class="py-3.5 pl-4 pr-3 text-left text-sm font-semibold text-gray-900 sm:pl-6">Name</th>
                            <th scope="col" class="px-3 py-3.5 text-left text-sm font-semibold text-gray-900">Email</th>
                            <th scope="col" class="px-3 py-3.5 text-left text-sm font-semibold text-gray-900">Members</th>
                            <th scope="col" class="px-3 py-3.5 text-left text-sm font-semibold text-gray-900">Owner</th>
                            <th scope="col" class="relative py-3.5 pl-3 pr-4 sm:pr-6">
                                <span class="sr-only">Actions</span>
                            </th>
                        </tr>
                    </thead>
                    <tbody class="divide-y divide-gray-200 bg-white">
                        {{#each groups}}
                        <tr>
                            <td class="whitespace-nowrap py-4 pl-4 pr-3 text-sm font-medium text-gray-900 sm:pl-6">
                                {{this.name}}
                            </td>
                            <td class="whitespace-nowrap px-3 py-4 text-sm text-gray-500">{{this.email}}</td>
                            <td class="whitespace-nowrap px-3 py-4 text-sm text-gray-500">{{this.member_count}}</td>
                            <td class="whitespace-nowrap px-3 py-4 text-sm text-gray-500">{{this.owner}}</td>
                            <td class="relative whitespace-nowrap py-4 pl-3 pr-4 text-right text-sm font-medium sm:pr-6">
                                <a href="/admin/groups/{{this.name}}" class="text-blue-600 hover:text-blue-900 mr-3">Edit</a>
                                <form action="/admin/groups/{{this.name}}/delete" method="POST" class="inline" data-confirm="Delete this group?">
                                    <input type="hidden" name="csrf" value="{{@root.csrf}}">
                                    <button type="submit" class="text-red-600 hover:text-red-900">Delete</button>
                                </form>
                            </td>
                        </tr>
                        {{/each}}
                        {{#unless groups}}
                        <tr>
                            <td colspan="5" class="px-6 py-4 text-center text-sm text-gray-500">No groups found</td>
                        </tr>
                        {{/unless}}
                    </tbody>
                </table>
            </div>
        </div>
    </div>
</div>
"#;

const GROUP_FORM_CONTENT: &str = r#"
<div class="mb-8">
    <h1 class="text-2xl font-bold text-gray-900">{{#if editing}}Edit Group{{else}}Create Group{{/if}}</h1>
    <p class="mt-1 text-sm text-gray-500">{{#if editing}}Manage group settings and members{{else}}Add a new group or distribution list{{/if}}</p>
</div>

<div class="bg-white shadow-sm ring-1 ring-gray-900/5 sm:rounded-xl">
    <form action="{{form_action}}" method="POST" class="px-4 py-6 sm:p-8">
        <input type="hidden" name="csrf" value="{{csrf}}">
        <div class="grid max-w-2xl grid-cols-1 gap-x-6 gap-y-8 sm:grid-cols-6">
            <div class="sm:col-span-4">
                <label for="name" class="block text-sm font-medium leading-6 text-gray-900">Group Name</label>
                <div class="mt-2">
                    <input type="text" name="name" id="name" value="{{group.name}}" {{#if editing}}readonly{{/if}}
                        class="block w-full rounded-md border-0 py-1.5 text-gray-900 shadow-sm ring-1 ring-inset ring-gray-300 placeholder:text-gray-400 focus:ring-2 focus:ring-inset focus:ring-blue-600 sm:text-sm sm:leading-6 {{#if editing}}bg-gray-50{{/if}}"
                        required>
                </div>
            </div>

            <div class="sm:col-span-4">
                <label for="email" class="block text-sm font-medium leading-6 text-gray-900">Email Address</label>
                <div class="mt-2">
                    <input type="email" name="email" id="email" value="{{group.email}}"
                        class="block w-full rounded-md border-0 py-1.5 text-gray-900 shadow-sm ring-1 ring-inset ring-gray-300 placeholder:text-gray-400 focus:ring-2 focus:ring-inset focus:ring-blue-600 sm:text-sm sm:leading-6"
                        required>
                </div>
            </div>

            <div class="col-span-full">
                <label for="description" class="block text-sm font-medium leading-6 text-gray-900">Description</label>
                <div class="mt-2">
                    <textarea id="description" name="description" rows="3"
                        class="block w-full rounded-md border-0 py-1.5 text-gray-900 shadow-sm ring-1 ring-inset ring-gray-300 placeholder:text-gray-400 focus:ring-2 focus:ring-inset focus:ring-blue-600 sm:text-sm sm:leading-6">{{group.description}}</textarea>
                </div>
            </div>
        </div>

        <div class="mt-6 flex items-center justify-end gap-x-6">
            <a href="/admin/groups" class="text-sm font-semibold leading-6 text-gray-900">Cancel</a>
            <button type="submit"
                class="rounded-md bg-blue-600 px-3 py-2 text-sm font-semibold text-white shadow-sm hover:bg-blue-500 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-blue-600">
                {{#if editing}}Save Changes{{else}}Create Group{{/if}}
            </button>
        </div>
    </form>
</div>

{{#if editing}}
<!-- Members Section -->
<div class="mt-8 bg-white shadow-sm ring-1 ring-gray-900/5 sm:rounded-xl">
    <div class="px-4 py-6 sm:p-8">
        <h2 class="text-lg font-medium text-gray-900 mb-4">Members ({{group.member_count}})</h2>
        
        <!-- Add Member Form -->
        <form action="/admin/groups/{{group.name}}/members" method="POST" class="flex gap-2 mb-4">
            <input type="hidden" name="csrf" value="{{csrf}}">
            <input type="text" name="username" placeholder="Username to add"
                class="block w-64 rounded-md border-0 py-1.5 text-gray-900 shadow-sm ring-1 ring-inset ring-gray-300 placeholder:text-gray-400 focus:ring-2 focus:ring-inset focus:ring-blue-600 sm:text-sm sm:leading-6"
                required>
            <button type="submit"
                class="rounded-md bg-green-600 px-3 py-1.5 text-sm font-semibold text-white shadow-sm hover:bg-green-500">
                Add Member
            </button>
        </form>

        <!-- Members List -->
        <ul class="divide-y divide-gray-200">
            {{#each group.members}}
            <li class="flex items-center justify-between py-3">
                <span class="text-sm text-gray-900">{{this}}</span>
                <form action="/admin/groups/{{../group.name}}/members/{{this}}/remove" method="POST" class="inline">
                    <input type="hidden" name="csrf" value="{{@root.csrf}}">
                    <button type="submit" class="text-sm text-red-600 hover:text-red-900">Remove</button>
                </form>
            </li>
            {{/each}}
            {{#unless group.members}}
            <li class="py-3 text-sm text-gray-500">No members yet</li>
            {{/unless}}
        </ul>
    </div>
</div>
{{/if}}
"#;

// ============================================================================
// Handlers
// ============================================================================

#[derive(Deserialize)]
pub struct LoginForm {
    username: String,
    password: String,
    #[serde(default)]
    csrf: String,
}

#[derive(Deserialize)]
pub struct UserForm {
    username: String,
    password: Option<String>,
    display_name: Option<String>,
    role: Option<String>,
    status: Option<String>,
    /// Status the edit form was rendered with; status only changes when the
    /// submitted value differs from it.
    original_status: Option<String>,
    #[serde(default)]
    csrf: String,
}

#[derive(Deserialize)]
pub struct GroupForm {
    name: String,
    email: String,
    description: Option<String>,
    #[serde(default)]
    csrf: String,
}

#[derive(Deserialize)]
pub struct MemberForm {
    username: String,
    #[serde(default)]
    csrf: String,
}

/// Body of POST forms that carry nothing but the CSRF token.
#[derive(Deserialize)]
pub struct CsrfForm {
    #[serde(default)]
    csrf: String,
}

/// A flash message shown after a redirect. Only the known codes in
/// [`Flash::ALL`] are accepted in `?flash=`; anything else shows nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Flash {
    code: &'static str,
    text: &'static str,
    is_error: bool,
}

impl Flash {
    const fn ok(code: &'static str, text: &'static str) -> Self {
        Self {
            code,
            text,
            is_error: false,
        }
    }
    const fn err(code: &'static str, text: &'static str) -> Self {
        Self {
            code,
            text,
            is_error: true,
        }
    }

    const USER_CREATED: Flash = Flash::ok("user_created", "User created");
    const USER_UPDATED: Flash = Flash::ok("user_updated", "User updated");
    const USER_DELETED: Flash = Flash::ok("user_deleted", "User deleted");
    const USER_DELETED_CLEANUP_FAILED: Flash = Flash::err(
        "user_deleted_cleanup_failed",
        "User deleted, but removing their mailbox, SSO data, encryption keys or group memberships failed (see server log)",
    );
    const USER_NOT_FOUND: Flash = Flash::err("user_not_found", "User not found");
    const USER_DELETE_DENIED: Flash = Flash::err(
        "user_delete_denied",
        "You are not allowed to delete this user",
    );
    const USER_DELETE_FAILED: Flash = Flash::err(
        "user_delete_failed",
        "Could not delete user (see server log)",
    );
    const GROUP_CREATED: Flash = Flash::ok("group_created", "Group created");
    const GROUP_UPDATED: Flash = Flash::ok("group_updated", "Group updated");
    const GROUP_DELETED: Flash = Flash::ok("group_deleted", "Group deleted");
    const GROUP_NOT_FOUND: Flash = Flash::err("group_not_found", "Group not found");
    const GROUP_DELETE_FAILED: Flash = Flash::err(
        "group_delete_failed",
        "Could not delete group (see server log)",
    );
    const MEMBER_ADDED: Flash = Flash::ok("member_added", "Member added");
    const MEMBER_REMOVED: Flash = Flash::ok("member_removed", "Member removed");

    const ALL: &'static [Flash] = &[
        Flash::USER_CREATED,
        Flash::USER_UPDATED,
        Flash::USER_DELETED,
        Flash::USER_DELETED_CLEANUP_FAILED,
        Flash::USER_NOT_FOUND,
        Flash::USER_DELETE_DENIED,
        Flash::USER_DELETE_FAILED,
        Flash::GROUP_CREATED,
        Flash::GROUP_UPDATED,
        Flash::GROUP_DELETED,
        Flash::GROUP_NOT_FOUND,
        Flash::GROUP_DELETE_FAILED,
        Flash::MEMBER_ADDED,
        Flash::MEMBER_REMOVED,
    ];

    fn from_code(code: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|f| f.code == code)
    }
}

/// `?flash=<code>` parameter on list/edit pages.
#[derive(Deserialize, Default)]
pub struct FlashQuery {
    flash: Option<String>,
}

impl FlashQuery {
    fn get(&self) -> Option<Flash> {
        self.flash.as_deref().and_then(Flash::from_code)
    }
    fn success(&self) -> Option<&'static str> {
        self.get().filter(|f| !f.is_error).map(|f| f.text)
    }
    fn error(&self) -> Option<&'static str> {
        self.get().filter(|f| f.is_error).map(|f| f.text)
    }
}

/// Notice on the password-change page when the change is required.
const PASSWORD_CHANGE_REQUIRED_TEXT: &str = "You must change your password before you can sign in.";

/// OAuth2 callback parameters.
#[derive(Deserialize)]
pub struct SsoCallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

#[derive(Serialize)]
struct UserView {
    username: String,
    display_name: String,
    role: String,
    status: String,
    is_admin: bool,
    is_active: bool,
    is_current_user: bool,
    last_login: String,
}

#[derive(Serialize)]
struct GroupView {
    name: String,
    email: String,
    description: String,
    owner: String,
    member_count: usize,
    members: Vec<String>,
}

/// Which navigation tab is active.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Nav {
    Dashboard,
    Users,
    Groups,
}

/// Resolve the session cookie to a logged-in admin.
///
/// The cookie carries only a random token; the token is looked up in the
/// server-side store and the account is re-checked on every request (exists,
/// can log in, admin role, password unchanged since login and no change
/// pending). Invalid sessions are removed.
async fn get_session(data: &WebState, req: &HttpRequest) -> Option<WebSession> {
    let token = req.cookie(SESSION_COOKIE)?.value().to_string();
    if token.is_empty() {
        return None;
    }
    let session = data.sessions.lookup(&token).await?;
    match data.user_manager.get_user(&session.username).await {
        Some(user)
            if user.is_active_admin() && session_is_current(session.password_changed_at, &user) =>
        {
            Some(session)
        }
        _ => {
            data.sessions.remove(&token).await;
            None
        }
    }
}

/// Require a logged-in admin; otherwise redirect to the login page.
///
/// The rejection response is boxed: `HttpResponse` is large enough to trip
/// `clippy::result_large_err`.
async fn require_session(
    data: &WebState,
    req: &HttpRequest,
) -> Result<WebSession, Box<HttpResponse>> {
    get_session(data, req)
        .await
        .ok_or_else(|| Box::new(to_login()))
}

/// Require a logged-in admin and a matching CSRF token (for POSTs).
async fn require_session_csrf(
    data: &WebState,
    req: &HttpRequest,
    csrf: &str,
) -> Result<WebSession, Box<HttpResponse>> {
    let session = require_session(data, req).await?;
    if !csrf_matches(&session.csrf, csrf) {
        tracing::warn!("Rejected admin POST without a valid CSRF token");
        return Err(Box::new(csrf_rejected()));
    }
    Ok(session)
}

fn csrf_matches(expected: &str, provided: &str) -> bool {
    !expected.is_empty() && ct_eq(expected.as_bytes(), provided.as_bytes())
}

fn csrf_rejected() -> HttpResponse {
    HttpResponse::Forbidden()
        .content_type("text/plain; charset=utf-8")
        .body("Invalid or missing CSRF token")
}

/// Host part of an absolute URL (`scheme://host[:port]/...`).
fn url_host(url: &str) -> Option<&str> {
    let rest = url.split_once("://")?.1;
    rest.split(['/', '?', '#']).next()
}

/// When the browser sent `Origin` (or else `Referer`), it must name this host.
fn same_origin(req: &HttpRequest) -> bool {
    let header = |name| {
        req.headers()
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
    };
    let source = match header(actix_web::http::header::ORIGIN) {
        Some(origin) => origin,
        None => match header(actix_web::http::header::REFERER) {
            Some(referer) => referer,
            None => return true,
        },
    };
    let conn = req.connection_info();
    url_host(&source).is_some_and(|h| h.eq_ignore_ascii_case(conn.host()))
}

/// The client's IP address (see [`client_ip`]: the TCP peer, or forwarding
/// headers when the peer is a trusted proxy).
fn peer_ip(req: &HttpRequest) -> String {
    let header = |name: &str| {
        let values: Vec<&str> = req
            .headers()
            .get_all(name)
            .filter_map(|v| v.to_str().ok())
            .collect();
        (!values.is_empty()).then(|| values.join(","))
    };
    client_ip(
        req.peer_addr().map(|a| a.ip()),
        header("x-real-ip").as_deref(),
        header("x-forwarded-for").as_deref(),
    )
}

/// An HttpOnly, SameSite=Strict cookie. `ttl: None` builds a removal
/// cookie (empty value, expired).
fn strict_cookie(
    name: &'static str,
    value: &str,
    path: &'static str,
    ttl: Option<Duration>,
    secure: bool,
) -> Cookie<'static> {
    let mut cookie = Cookie::build(name, value.to_string())
        .path(path)
        .http_only(true)
        .same_site(SameSite::Strict)
        .secure(secure)
        .finish();
    match ttl {
        Some(ttl) => cookie.set_max_age(actix_web::cookie::time::Duration::seconds(
            ttl.as_secs() as i64
        )),
        None => cookie.make_removal(),
    }
    cookie
}

/// The session cookie for a token (`None`: remove it).
fn session_cookie(token: Option<&str>, secure: bool) -> Cookie<'static> {
    strict_cookie(
        SESSION_COOKIE,
        token.unwrap_or(""),
        "/",
        token.map(|_| SESSION_TTL),
        secure,
    )
}

/// The login-form CSRF cookie (`None`: remove it).
fn login_csrf_cookie(token: Option<&str>, secure: bool) -> Cookie<'static> {
    strict_cookie(
        LOGIN_CSRF_COOKIE,
        token.unwrap_or(""),
        "/admin",
        token.map(|_| LOGIN_CSRF_TTL),
        secure,
    )
}

/// The password-change form's CSRF cookie (`None`: remove it).
fn account_csrf_cookie(token: Option<&str>, secure: bool) -> Cookie<'static> {
    strict_cookie(
        ACCOUNT_CSRF_COOKIE,
        token.unwrap_or(""),
        "/account",
        token.map(|_| LOGIN_CSRF_TTL),
        secure,
    )
}

/// Redirect helper.
fn redirect(location: impl Into<String>) -> HttpResponse {
    HttpResponse::Found()
        .append_header(("Location", location.into()))
        .finish()
}

/// Redirect to `path` with a known flash code.
fn redirect_flash(path: &str, flash: Flash) -> HttpResponse {
    redirect(format!("{}?flash={}", path, flash.code))
}

fn to_login() -> HttpResponse {
    redirect("/admin/login")
}

/// Replace a response's status code.
fn with_status(mut resp: HttpResponse, status: StatusCode) -> HttpResponse {
    *resp.status_mut() = status;
    resp
}

/// Render the login page with a fresh login CSRF token (also set as a
/// cookie), optionally with an error message.
fn render_login(data: &WebState, error: Option<&str>) -> HttpResponse {
    let sso = data.sso_manager.status();
    let csrf = generate_session_token();
    let body = data
        .hbs
        .render(
            "login",
            &json!({
                "version": env!("CARGO_PKG_VERSION"),
                "error": error,
                "sso_enabled": sso.enabled,
                "sso_provider": sso.provider_name,
                "csrf": csrf,
            }),
        )
        .unwrap_or_else(|e| format!("Template error: {}", e));

    HttpResponse::Ok()
        .cookie(login_csrf_cookie(Some(&csrf), data.secure_cookie))
        .content_type("text/html; charset=utf-8")
        .body(body)
}

/// Login page
pub async fn login_page(data: web::Data<WebState>, req: HttpRequest) -> HttpResponse {
    // Already logged in?
    if get_session(&data, &req).await.is_some() {
        return redirect("/admin");
    }
    render_login(&data, None)
}

/// Handle login
pub async fn login_submit(
    data: web::Data<WebState>,
    req: HttpRequest,
    form: web::Form<LoginForm>,
) -> HttpResponse {
    let cookie_csrf = req
        .cookie(LOGIN_CSRF_COOKIE)
        .map(|c| c.value().to_string())
        .unwrap_or_default();
    if !same_origin(&req) || !csrf_matches(&cookie_csrf, &form.csrf) {
        tracing::warn!("Rejected admin login POST: CSRF/origin check failed");
        return with_status(
            render_login(&data, Some("Your login form expired. Please try again.")),
            StatusCode::FORBIDDEN,
        );
    }

    let ip = peer_ip(&req);
    match data
        .user_manager
        .authenticate(&form.username, &form.password, &ip, "admin-web", false)
        .await
    {
        Ok(user) => {
            if !user.is_active_admin() {
                return render_login(&data, Some("Admin access required"));
            }

            let token = data
                .sessions
                .create(WebSession::new(&user), SESSION_TTL)
                .await;
            HttpResponse::Found()
                .cookie(session_cookie(Some(&token), data.secure_cookie))
                .cookie(login_csrf_cookie(None, data.secure_cookie))
                .append_header(("Location", "/admin"))
                .finish()
        }
        // Correct password, but it must be changed first: no admin session.
        Err(UserError::PasswordChangeRequired) => {
            redirect(account_password_url(&form.username, true))
        }
        // Correct password, but the account's status or IP rules forbid it.
        Err(UserError::PermissionDenied(msg)) => {
            with_status(render_login(&data, Some(&msg)), StatusCode::FORBIDDEN)
        }
        Err(UserError::AccountLocked(_)) => with_status(
            render_login(&data, Some("Too many failed attempts. Try again later.")),
            StatusCode::TOO_MANY_REQUESTS,
        ),
        Err(_) => render_login(&data, Some("Invalid username or password")),
    }
}

/// Logout (POST; removes the server-side session)
pub async fn logout(
    data: web::Data<WebState>,
    req: HttpRequest,
    form: web::Form<CsrfForm>,
) -> HttpResponse {
    if let Some(c) = req.cookie(SESSION_COOKIE)
        && let Some(session) = data.sessions.lookup(c.value()).await
    {
        if !csrf_matches(&session.csrf, &form.csrf) {
            return csrf_rejected();
        }
        data.sessions.remove(c.value()).await;
    }

    HttpResponse::Found()
        .cookie(session_cookie(None, data.secure_cookie))
        .append_header(("Location", "/admin/login"))
        .finish()
}

// ============================================================================
// Self-service password change (any local user; outside /admin)
// ============================================================================

/// URL of the password-change page with `username` prefilled; `required`
/// adds the "you must change your password" notice.
fn account_password_url(username: &str, required: bool) -> String {
    let mut url = format!(
        "{}?username={}",
        crate::config::ACCOUNT_PASSWORD_PATH,
        urlencoding::encode(&crate::users::canonical_username(username))
    );
    if required {
        url.push_str("&reason=required");
    }
    url
}

/// Query of `GET /account/password`.
#[derive(Deserialize, Default)]
pub struct AccountPasswordQuery {
    username: Option<String>,
    reason: Option<String>,
    flash: Option<String>,
}

/// Body of `POST /account/password`.
#[derive(Deserialize)]
pub struct AccountPasswordForm {
    #[serde(default)]
    username: String,
    #[serde(default)]
    current_password: String,
    #[serde(default)]
    new_password: String,
    #[serde(default)]
    confirm_password: String,
    #[serde(default)]
    csrf: String,
}

/// What the password-change page shows.
enum AccountPage<'a> {
    /// The form, with the username prefilled and an optional error.
    Form {
        username: &'a str,
        error: Option<&'a str>,
    },
    /// Confirmation after a successful change.
    Changed { is_admin: bool },
}

/// Render the password-change page in the base layout (without the admin
/// navigation). The form gets a fresh CSRF token, also set as a cookie.
fn render_account_page(data: &WebState, page: AccountPage<'_>, status: StatusCode) -> HttpResponse {
    let csrf = generate_session_token();
    let (content_data, error) = match page {
        AccountPage::Form { username, error } => (
            json!({
                "form_username": username,
                "form_csrf": csrf,
                "min_length": crate::users::MIN_PASSWORD_LEN,
            }),
            error,
        ),
        AccountPage::Changed { is_admin } => {
            (json!({ "changed": true, "is_admin": is_admin }), None)
        }
    };
    let changed = content_data.get("changed").is_some();
    let content = data
        .hbs
        .render("account_password", &content_data)
        .unwrap_or_else(|e| format!("Template error: {}", e));
    let body = data
        .hbs
        .render(
            "base",
            &json!({
                "title": "Change password",
                "content": content,
                "flash_error": error,
            }),
        )
        .unwrap_or_else(|e| format!("Template error: {}", e));

    let cookie = account_csrf_cookie((!changed).then_some(csrf.as_str()), data.secure_cookie);
    HttpResponse::build(status)
        .cookie(cookie)
        .content_type("text/html; charset=utf-8")
        .body(body)
}

/// GET /account/password - the password-change form.
pub async fn account_password_page(
    data: web::Data<WebState>,
    query: web::Query<AccountPasswordQuery>,
) -> HttpResponse {
    let error = if query.reason.as_deref() == Some("required") {
        Some(PASSWORD_CHANGE_REQUIRED_TEXT)
    } else {
        query
            .flash
            .as_deref()
            .and_then(Flash::from_code)
            .filter(|f| f.is_error)
            .map(|f| f.text)
    };
    let username = query.username.as_deref().unwrap_or("");
    render_account_page(&data, AccountPage::Form { username, error }, StatusCode::OK)
}

/// POST /account/password - change a local account password.
///
/// Stateless: the current password is the credential. Protected by a
/// double-submit CSRF cookie plus Origin/Referer checks, and throttled per
/// username and peer IP like a login. Credential failures get one generic
/// message, so the page does not reveal which accounts exist.
pub async fn account_password_submit(
    data: web::Data<WebState>,
    req: HttpRequest,
    form: web::Form<AccountPasswordForm>,
) -> HttpResponse {
    let username = form.username.trim();
    let form_page = |error: &str, status: StatusCode| {
        render_account_page(
            &data,
            AccountPage::Form {
                username,
                error: Some(error),
            },
            status,
        )
    };

    let cookie_csrf = req
        .cookie(ACCOUNT_CSRF_COOKIE)
        .map(|c| c.value().to_string())
        .unwrap_or_default();
    if !same_origin(&req) || !csrf_matches(&cookie_csrf, &form.csrf) {
        tracing::warn!("Rejected password change POST: CSRF/origin check failed");
        return form_page(
            "Your form expired. Please try again.",
            StatusCode::FORBIDDEN,
        );
    }
    if form.new_password != form.confirm_password {
        return form_page("The new passwords do not match.", StatusCode::BAD_REQUEST);
    }

    let ip = peer_ip(&req);
    match data
        .user_manager
        .change_password_from(
            &ip,
            username,
            &form.current_password,
            &form.new_password,
            false,
        )
        .await
    {
        Ok(()) => {
            let is_admin = data
                .user_manager
                .get_user(username)
                .await
                .is_some_and(|u| u.is_active_admin());
            render_account_page(&data, AccountPage::Changed { is_admin }, StatusCode::OK)
        }
        Err(e) => {
            // Same mapping as the admin API (credential failures are generic
            // so the page does not reveal which accounts exist).
            let failure = PasswordChangeFailure::from(e);
            let status = StatusCode::from_u16(password_change_status(&failure))
                .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            form_page(&password_change_message(username, &failure), status)
        }
    }
}

/// Start SSO login: redirect to the identity provider.
pub async fn sso_login(data: web::Data<WebState>) -> HttpResponse {
    if !data.sso_manager.is_enabled() {
        return render_login(&data, Some("SSO is not enabled"));
    }
    match data.sso_manager.start_auth().await {
        Ok((auth_url, _state)) => redirect(auth_url),
        Err(e) => render_login(&data, Some(&format!("SSO error: {}", e))),
    }
}

/// OAuth2 redirect target: complete SSO and create an admin session if the
/// identity maps to an existing local admin account.
///
/// Order: the provider round trip (`complete_auth`, which does not bind
/// anything), then the local account checks (exists, active admin, login
/// allowed from this IP, no pending password change), and only then the
/// identity binding (`bind_identity`). An admin account's first SSO login
/// only binds automatically with `SSO_AUTO_BIND_ADMINS=true`; otherwise the
/// identity must have been linked explicitly.
pub async fn sso_callback(
    data: web::Data<WebState>,
    req: HttpRequest,
    query: web::Query<SsoCallbackQuery>,
) -> HttpResponse {
    if let Some(err) = &query.error {
        return render_login(&data, Some(&format!("SSO error: {}", err)));
    }
    let (code, state) = match (&query.code, &query.state) {
        (Some(c), Some(s)) if !c.is_empty() && !s.is_empty() => (c, s),
        _ => return render_login(&data, Some("SSO error: missing code or state")),
    };

    let info = match data.sso_manager.complete_auth(code, state).await {
        Ok(info) => info,
        Err(e) => return render_login(&data, Some(&format!("SSO error: {}", e))),
    };

    let user = match data.user_manager.get_user(&info.username).await {
        Some(u) => u,
        None => {
            tracing::warn!(
                "SSO login for '{}' rejected: no matching local user",
                info.username
            );
            return render_login(&data, Some("No local account matches this SSO identity"));
        }
    };
    if !user.is_active_admin() {
        tracing::warn!(
            "SSO login for '{}' rejected: not an active admin",
            user.username
        );
        return render_login(&data, Some("Admin access required"));
    }
    let ip = peer_ip(&req);
    if let Err(e) = user.check_login_from(&ip) {
        tracing::warn!(
            "SSO login for '{}' from {} rejected: {}",
            user.username,
            ip,
            e
        );
        return render_login(
            &data,
            Some("Login is not allowed for this account or address"),
        );
    }
    if user.password_change_required {
        tracing::info!(
            "SSO login for '{}': password change required first",
            user.username
        );
        return redirect(account_password_url(&user.username, true));
    }

    // Only admins get this far, so a first binding needs the opt-in.
    let allow_first_bind = data.sso_auto_bind_admins;
    if let Err(e) = data
        .sso_manager
        .bind_identity(&info, allow_first_bind)
        .await
    {
        tracing::warn!("SSO login for '{}' rejected: {}", user.username, e);
        return render_login(&data, Some(&format!("SSO error: {}", e)));
    }

    let token = data
        .sessions
        .create(WebSession::new(&user), SESSION_TTL)
        .await;
    tracing::info!("Admin '{}' signed in via SSO from {}", user.username, ip);

    // Return a same-site page that forwards to /admin instead of a 302: with
    // SameSite=Strict the cookie would not be sent on a redirect chain that
    // started on the identity provider's site.
    HttpResponse::Ok()
        .cookie(session_cookie(Some(&token), data.secure_cookie))
        .content_type("text/html; charset=utf-8")
        .body(
            "<!DOCTYPE html><html><head><meta http-equiv=\"refresh\" content=\"0;url=/admin\">\
             <title>Signing in...</title></head><body>\
             <p>Signed in. <a href=\"/admin\">Continue to the dashboard</a>.</p></body></html>",
        )
}

/// Dashboard
pub async fn dashboard(data: web::Data<WebState>, req: HttpRequest) -> HttpResponse {
    let session = match require_session(&data, &req).await {
        Ok(s) => s,
        Err(resp) => return *resp,
    };

    let users = data.user_manager.list_users().await;
    let groups = data.group_manager.list().await;
    let ldap_status = data.ldap_client.status();
    let sso_status = data.sso_manager.status();

    let active_users = users
        .iter()
        .filter(|u| u.status == AccountStatus::Active)
        .count();
    let admins = users
        .iter()
        .filter(|u| matches!(u.role, UserRole::Admin | UserRole::SuperAdmin))
        .count();

    let content = data
        .hbs
        .render(
            "dashboard",
            &json!({
                "domain": data.domain,
                "stats": {
                    "users": users.len(),
                    "groups": groups.len(),
                    "active_users": active_users,
                    "admins": admins,
                },
                "ldap_enabled": ldap_status.enabled,
                "sso_enabled": sso_status.enabled,
                "sso_provider": sso_status.provider_name,
                "version": env!("CARGO_PKG_VERSION"),
            }),
        )
        .unwrap_or_default();

    render_page(
        &data.hbs,
        "Dashboard",
        &session,
        &content,
        Nav::Dashboard,
        None,
        None,
    )
}

/// Users list
pub async fn users_list(
    data: web::Data<WebState>,
    req: HttpRequest,
    flash: web::Query<FlashQuery>,
) -> HttpResponse {
    let session = match require_session(&data, &req).await {
        Ok(s) => s,
        Err(resp) => return *resp,
    };

    let users = data.user_manager.list_users().await;
    let user_views: Vec<UserView> = users
        .iter()
        .map(|u| UserView {
            username: u.username.clone(),
            display_name: u.settings.display_name.clone().unwrap_or_default(),
            role: format!("{:?}", u.role),
            status: format!("{:?}", u.status),
            is_admin: matches!(u.role, UserRole::Admin | UserRole::SuperAdmin),
            is_active: u.status == AccountStatus::Active,
            is_current_user: u.username == session.username,
            last_login: u
                .last_login
                .map(|t| t.format("%Y-%m-%d %H:%M").to_string())
                .unwrap_or_else(|| "Never".to_string()),
        })
        .collect();

    let content = data
        .hbs
        .render(
            "users",
            &json!({
                "users": user_views,
                "csrf": session.csrf,
            }),
        )
        .unwrap_or_default();

    render_page(
        &data.hbs,
        "Users",
        &session,
        &content,
        Nav::Users,
        flash.success(),
        flash.error(),
    )
}

/// Render the "new user" form, optionally pre-filled and with an error.
fn render_user_new(
    data: &WebState,
    session: &WebSession,
    form: Option<&UserForm>,
    error: Option<&str>,
) -> HttpResponse {
    let content = data
        .hbs
        .render(
            "user_form",
            &json!({
                "editing": false,
                "form_action": "/admin/users/new",
                "csrf": session.csrf,
                "user": {
                    "username": form.map(|f| f.username.as_str()),
                    "display_name": form.and_then(|f| f.display_name.as_deref()),
                },
            }),
        )
        .unwrap_or_default();

    render_page(
        &data.hbs,
        "New User",
        session,
        &content,
        Nav::Users,
        None,
        error,
    )
}

/// New user form
pub async fn user_new(data: web::Data<WebState>, req: HttpRequest) -> HttpResponse {
    match require_session(&data, &req).await {
        Ok(session) => render_user_new(&data, &session, None, None),
        Err(resp) => *resp,
    }
}

/// Create user
pub async fn user_create(
    data: web::Data<WebState>,
    req: HttpRequest,
    form: web::Form<UserForm>,
) -> HttpResponse {
    let session = match require_session_csrf(&data, &req, &form.csrf).await {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    let actor = match data.user_manager.get_user(&session.username).await {
        Some(u) => u,
        None => return to_login(),
    };

    let role = match form
        .role
        .as_deref()
        .map(str::trim)
        .filter(|r| !r.is_empty())
    {
        None => UserRole::User,
        Some(r) => match r.parse::<UserRole>() {
            Ok(role) => role,
            Err(_) => {
                return with_status(
                    render_user_new(&data, &session, Some(&form), Some("Unknown role")),
                    StatusCode::BAD_REQUEST,
                );
            }
        },
    };
    if let Err(msg) = check_create_role(&actor, role) {
        return with_status(
            render_user_new(&data, &session, Some(&form), Some(&msg)),
            StatusCode::FORBIDDEN,
        );
    }

    let password = form.password.as_deref().unwrap_or("");
    // Display name and account are saved together.
    let mut plan = PlannedUserUpdate::default();
    plan.set_display_name(form.display_name.as_deref().unwrap_or(""), &None);
    let display_name = plan.display_name.flatten();

    match data
        .user_manager
        .create_user_with(&form.username, password, Some(role), |u| {
            u.settings.display_name = display_name;
        })
        .await
    {
        Ok(_) => redirect_flash("/admin/users", Flash::USER_CREATED),
        Err(e) => with_status(
            render_user_new(&data, &session, Some(&form), Some(&e.to_string())),
            StatusCode::BAD_REQUEST,
        ),
    }
}

/// Every account status, in the order shown in the edit form.
const ALL_STATUSES: [AccountStatus; 5] = [
    AccountStatus::Active,
    AccountStatus::Suspended,
    AccountStatus::Locked,
    AccountStatus::Disabled,
    AccountStatus::PendingVerification,
];

fn status_label(status: AccountStatus) -> &'static str {
    match status {
        AccountStatus::Active => "Active",
        AccountStatus::Suspended => "Suspended",
        AccountStatus::Locked => "Locked",
        AccountStatus::Disabled => "Disabled",
        AccountStatus::PendingVerification => "Pending verification",
    }
}

/// Render the edit form for `user` (current values from the store).
fn render_user_edit(
    data: &WebState,
    session: &WebSession,
    user: &UserAccount,
    success: Option<&str>,
    error: Option<&str>,
) -> HttpResponse {
    let statuses: Vec<_> = ALL_STATUSES
        .iter()
        .map(|s| {
            json!({
                "value": s.to_string(),
                "label": status_label(*s),
                "selected": *s == user.status,
            })
        })
        .collect();

    let content = data
        .hbs
        .render(
            "user_form",
            &json!({
                "editing": true,
                "form_action": format!("/admin/users/{}", urlencoding::encode(&user.username)),
                "csrf": session.csrf,
                "statuses": statuses,
                "user": {
                    "username": user.username,
                    "display_name": user.settings.display_name.clone().unwrap_or_default(),
                    "is_user": matches!(user.role, UserRole::User),
                    "is_admin": matches!(user.role, UserRole::Admin),
                    "is_superadmin": matches!(user.role, UserRole::SuperAdmin),
                    "status": user.status.to_string(),
                },
            }),
        )
        .unwrap_or_default();

    render_page(
        &data.hbs,
        "Edit User",
        session,
        &content,
        Nav::Users,
        success,
        error,
    )
}

/// Edit user form
pub async fn user_edit(
    data: web::Data<WebState>,
    req: HttpRequest,
    path: web::Path<String>,
    flash: web::Query<FlashQuery>,
) -> HttpResponse {
    let session = match require_session(&data, &req).await {
        Ok(s) => s,
        Err(resp) => return *resp,
    };

    match data.user_manager.get_user(&path.into_inner()).await {
        Some(user) => render_user_edit(&data, &session, &user, flash.success(), flash.error()),
        None => redirect_flash("/admin/users", Flash::USER_NOT_FOUND),
    }
}

/// Work out which changes an edit-form submission asks for.
fn plan_user_update(form: &UserForm, target: &UserAccount) -> Result<PlannedUserUpdate, String> {
    let mut plan = PlannedUserUpdate {
        password: form.password.clone().filter(|p| !p.is_empty()),
        ..Default::default()
    };

    if let Some(name) = &form.display_name {
        plan.set_display_name(name, &target.settings.display_name);
    }

    if let Some(role_str) = form.role.as_deref().filter(|r| !r.is_empty()) {
        let role = role_str
            .parse::<UserRole>()
            .map_err(|_| format!("Role: unknown role '{}'", role_str))?;
        if role != target.role {
            plan.role = Some(role);
        }
    }

    if let Some(status_str) = form.status.as_deref().filter(|s| !s.is_empty()) {
        let submitted = status_str
            .parse::<AccountStatus>()
            .map_err(|_| format!("Status: unknown status '{}'", status_str))?;
        // Compare with what the form showed, not with the current value, so
        // an untouched select never changes the status (e.g. never
        // re-activates a locked account).
        let original = form
            .original_status
            .as_deref()
            .and_then(|s| s.parse::<AccountStatus>().ok())
            .unwrap_or(target.status);
        if submitted != original && submitted != target.status {
            plan.status = Some(submitted);
        }
    }

    Ok(plan)
}

/// Update user
pub async fn user_update(
    data: web::Data<WebState>,
    req: HttpRequest,
    path: web::Path<String>,
    form: web::Form<UserForm>,
) -> HttpResponse {
    let session = match require_session_csrf(&data, &req, &form.csrf).await {
        Ok(s) => s,
        Err(resp) => return *resp,
    };

    let target_username = path.into_inner();

    let actor = match data.user_manager.get_user(&session.username).await {
        Some(u) => u,
        None => return to_login(),
    };

    let target = match data.user_manager.get_user(&target_username).await {
        Some(u) => u,
        None => return redirect_flash("/admin/users", Flash::USER_NOT_FOUND),
    };

    // Validate and check every permission before applying anything.
    let plan = match plan_user_update(&form, &target) {
        Ok(p) => p,
        Err(msg) => {
            return with_status(
                render_user_edit(&data, &session, &target, None, Some(&msg)),
                StatusCode::BAD_REQUEST,
            );
        }
    };
    if let Err(msg) = check_update_permissions(&actor, &target, &plan) {
        return with_status(
            render_user_edit(&data, &session, &target, None, Some(&msg)),
            StatusCode::FORBIDDEN,
        );
    }

    let report = apply_user_update(
        &data.user_manager,
        &data.sso_manager,
        &actor,
        &target,
        &plan,
    )
    .await;
    let current = data
        .user_manager
        .get_user(&target.username)
        .await
        .unwrap_or(target);
    if !report.errors.is_empty() {
        return with_status(
            render_user_edit(
                &data,
                &session,
                &current,
                None,
                Some(&report.errors.join("; ")),
            ),
            StatusCode::BAD_REQUEST,
        );
    }
    if report.revoked_app_passwords > 0 {
        let notice = format!(
            "User updated; {} app password(s) revoked because the password was reset",
            report.revoked_app_passwords
        );
        return render_user_edit(&data, &session, &current, Some(&notice), None);
    }
    redirect_flash("/admin/users", Flash::USER_UPDATED)
}

/// Delete user (also removes their mailbox, SSO data, keys and group
/// memberships)
pub async fn user_delete(
    data: web::Data<WebState>,
    req: HttpRequest,
    path: web::Path<String>,
    form: web::Form<CsrfForm>,
) -> HttpResponse {
    let session = match require_session_csrf(&data, &req, &form.csrf).await {
        Ok(s) => s,
        Err(resp) => return *resp,
    };

    let target_username = path.into_inner();

    let actor = match data.user_manager.get_user(&session.username).await {
        Some(u) => u,
        None => return to_login(),
    };

    match data
        .user_manager
        .delete_user(&target_username, &actor)
        .await
    {
        Ok(()) => {
            let failures = cleanup_deleted_user(
                &data.user_manager,
                &data.storage,
                &data.sso_manager,
                data.crypto_manager.as_deref(),
                &data.group_manager,
                &target_username,
            )
            .await;
            if failures.is_empty() {
                redirect_flash("/admin/users", Flash::USER_DELETED)
            } else {
                redirect_flash("/admin/users", Flash::USER_DELETED_CLEANUP_FAILED)
            }
        }
        Err(e) => {
            tracing::warn!(
                "Admin {} could not delete user {}: {}",
                session.username,
                target_username,
                e
            );
            let flash = match e {
                UserError::NotFound(_) => Flash::USER_NOT_FOUND,
                UserError::PermissionDenied(_) => Flash::USER_DELETE_DENIED,
                _ => Flash::USER_DELETE_FAILED,
            };
            redirect_flash("/admin/users", flash)
        }
    }
}

/// Groups list
pub async fn groups_list(
    data: web::Data<WebState>,
    req: HttpRequest,
    flash: web::Query<FlashQuery>,
) -> HttpResponse {
    let session = match require_session(&data, &req).await {
        Ok(s) => s,
        Err(resp) => return *resp,
    };

    let groups = data.group_manager.list().await;
    let group_views: Vec<GroupView> = groups
        .iter()
        .map(|g| GroupView {
            name: g.name.clone(),
            email: g.email.clone(),
            description: g.description.clone(),
            owner: g.owner.clone(),
            member_count: g.members.len(),
            members: g.members.iter().cloned().collect(),
        })
        .collect();

    let content = data
        .hbs
        .render(
            "groups",
            &json!({
                "groups": group_views,
                "csrf": session.csrf,
            }),
        )
        .unwrap_or_default();

    render_page(
        &data.hbs,
        "Groups",
        &session,
        &content,
        Nav::Groups,
        flash.success(),
        flash.error(),
    )
}

/// Render the "new group" form, optionally pre-filled and with an error.
fn render_group_new(
    data: &WebState,
    session: &WebSession,
    form: Option<&GroupForm>,
    error: Option<&str>,
) -> HttpResponse {
    let content = data
        .hbs
        .render(
            "group_form",
            &json!({
                "editing": false,
                "form_action": "/admin/groups/new",
                "csrf": session.csrf,
                "group": {
                    "name": form.map(|f| f.name.as_str()),
                    "email": form.map(|f| f.email.as_str()),
                    "description": form.and_then(|f| f.description.as_deref()),
                },
            }),
        )
        .unwrap_or_default();

    render_page(
        &data.hbs,
        "New Group",
        session,
        &content,
        Nav::Groups,
        None,
        error,
    )
}

/// New group form
pub async fn group_new(data: web::Data<WebState>, req: HttpRequest) -> HttpResponse {
    match require_session(&data, &req).await {
        Ok(session) => render_group_new(&data, &session, None, None),
        Err(resp) => *resp,
    }
}

/// Create group. Admin-created groups record the admin as owner but do not
/// add them as a member.
pub async fn group_create(
    data: web::Data<WebState>,
    req: HttpRequest,
    form: web::Form<GroupForm>,
) -> HttpResponse {
    let session = match require_session_csrf(&data, &req, &form.csrf).await {
        Ok(s) => s,
        Err(resp) => return *resp,
    };

    let description = form.description.as_deref().filter(|d| !d.is_empty());
    match data
        .group_manager
        .create_with_members(&form.name, &form.email, &session.username, description, &[])
        .await
    {
        Ok(_) => redirect_flash("/admin/groups", Flash::GROUP_CREATED),
        Err(e) => with_status(
            render_group_new(&data, &session, Some(&form), Some(&e.to_string())),
            StatusCode::BAD_REQUEST,
        ),
    }
}

/// Render the edit page of a group, or redirect if it does not exist.
async fn render_group_edit(
    data: &WebState,
    session: &WebSession,
    group_name: &str,
    success: Option<&str>,
    error: Option<&str>,
) -> HttpResponse {
    let group = match data.group_manager.get(group_name).await {
        Some(g) => g,
        None => return redirect_flash("/admin/groups", Flash::GROUP_NOT_FOUND),
    };

    let mut members: Vec<String> = group.members.iter().cloned().collect();
    members.sort();

    let content = data
        .hbs
        .render(
            "group_form",
            &json!({
                "editing": true,
                "form_action": group_page(&group.name),
                "csrf": session.csrf,
                "group": {
                    "name": group.name,
                    "email": group.email,
                    "description": group.description,
                    "owner": group.owner,
                    "member_count": members.len(),
                    "members": members,
                },
            }),
        )
        .unwrap_or_default();

    render_page(
        &data.hbs,
        "Edit Group",
        session,
        &content,
        Nav::Groups,
        success,
        error,
    )
}

/// Edit group form
pub async fn group_edit(
    data: web::Data<WebState>,
    req: HttpRequest,
    path: web::Path<String>,
    flash: web::Query<FlashQuery>,
) -> HttpResponse {
    let session = match require_session(&data, &req).await {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    render_group_edit(
        &data,
        &session,
        &path.into_inner(),
        flash.success(),
        flash.error(),
    )
    .await
}

/// Path of a group's edit page (URL-encoded).
fn group_page(name: &str) -> String {
    format!("/admin/groups/{}", urlencoding::encode(name))
}

/// Update group
pub async fn group_update(
    data: web::Data<WebState>,
    req: HttpRequest,
    path: web::Path<String>,
    form: web::Form<GroupForm>,
) -> HttpResponse {
    let session = match require_session_csrf(&data, &req, &form.csrf).await {
        Ok(s) => s,
        Err(resp) => return *resp,
    };

    let group_name = path.into_inner();

    match data
        .group_manager
        .update_details(
            &group_name,
            Some(&form.email),
            Some(form.description.as_deref().unwrap_or("")),
        )
        .await
    {
        Ok(()) => redirect_flash(&group_page(&group_name), Flash::GROUP_UPDATED),
        Err(GroupError::NotFound(_)) => redirect_flash("/admin/groups", Flash::GROUP_NOT_FOUND),
        Err(e) => render_group_edit(&data, &session, &group_name, None, Some(&e.to_string())).await,
    }
}

/// Delete group (admins may delete any group)
pub async fn group_delete(
    data: web::Data<WebState>,
    req: HttpRequest,
    path: web::Path<String>,
    form: web::Form<CsrfForm>,
) -> HttpResponse {
    let session = match require_session_csrf(&data, &req, &form.csrf).await {
        Ok(s) => s,
        Err(resp) => return *resp,
    };

    let group_name = path.into_inner();

    match data.group_manager.delete(&group_name).await {
        Ok(()) => redirect_flash("/admin/groups", Flash::GROUP_DELETED),
        Err(GroupError::NotFound(_)) => redirect_flash("/admin/groups", Flash::GROUP_NOT_FOUND),
        Err(e) => {
            tracing::warn!(
                "Admin {} could not delete group {}: {}",
                session.username,
                group_name,
                e
            );
            redirect_flash("/admin/groups", Flash::GROUP_DELETE_FAILED)
        }
    }
}

/// Add group member (admins may manage any group)
pub async fn group_add_member(
    data: web::Data<WebState>,
    req: HttpRequest,
    path: web::Path<String>,
    form: web::Form<MemberForm>,
) -> HttpResponse {
    let session = match require_session_csrf(&data, &req, &form.csrf).await {
        Ok(s) => s,
        Err(resp) => return *resp,
    };

    let group_name = path.into_inner();

    match data
        .group_manager
        .add_member(&group_name, &form.username)
        .await
    {
        Ok(()) => redirect_flash(&group_page(&group_name), Flash::MEMBER_ADDED),
        Err(e) => render_group_edit(&data, &session, &group_name, None, Some(&e.to_string())).await,
    }
}

/// Remove group member (admins may manage any group)
pub async fn group_remove_member(
    data: web::Data<WebState>,
    req: HttpRequest,
    path: web::Path<(String, String)>,
    form: web::Form<CsrfForm>,
) -> HttpResponse {
    let session = match require_session_csrf(&data, &req, &form.csrf).await {
        Ok(s) => s,
        Err(resp) => return *resp,
    };

    let (group_name, member) = path.into_inner();

    match data.group_manager.remove_member(&group_name, &member).await {
        Ok(()) => redirect_flash(&group_page(&group_name), Flash::MEMBER_REMOVED),
        Err(e) => render_group_edit(&data, &session, &group_name, None, Some(&e.to_string())).await,
    }
}

// ============================================================================
// Helpers
// ============================================================================

/// Render a page inside the base layout. `flash_*` values are inserted with
/// Handlebars `{{...}}` and are therefore HTML-escaped.
fn render_page(
    hbs: &Handlebars,
    title: &str,
    session: &WebSession,
    content: &str,
    nav: Nav,
    flash_success: Option<&str>,
    flash_error: Option<&str>,
) -> HttpResponse {
    let body = hbs
        .render(
            "base",
            &json!({
                "title": title,
                "username": session.username,
                "csrf": session.csrf,
                "account_url": account_password_url(&session.username, false),
                "content": content,
                "nav_dashboard": nav == Nav::Dashboard,
                "nav_users": nav == Nav::Users,
                "nav_groups": nav == Nav::Groups,
                "flash_success": flash_success,
                "flash_error": flash_error,
            }),
        )
        .unwrap_or_else(|e| format!("Template error: {}", e));

    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(body)
}

/// Every embedded template, by registered name.
const TEMPLATES: &[(&str, &str)] = &[
    ("base", BASE_TEMPLATE),
    ("login", LOGIN_TEMPLATE),
    ("dashboard", DASHBOARD_CONTENT),
    ("users", USERS_CONTENT),
    ("user_form", USER_FORM_CONTENT),
    ("groups", GROUPS_CONTENT),
    ("group_form", GROUP_FORM_CONTENT),
    ("account_password", ACCOUNT_PASSWORD_CONTENT),
];

/// Create Handlebars instance with templates
pub fn create_handlebars() -> Handlebars<'static> {
    let mut hbs = Handlebars::new();
    hbs.set_strict_mode(false);
    for (name, source) in TEMPLATES {
        if let Err(e) = hbs.register_template_string(name, *source) {
            panic!("embedded template '{}' is invalid: {}", name, e);
        }
    }
    hbs
}

/// Security headers added to every response (unless a handler set them):
/// CSP, no caching (login, account and admin pages carry secrets), no
/// MIME sniffing.
pub fn security_headers() -> DefaultHeaders {
    DefaultHeaders::new()
        .add(("Content-Security-Policy", CONTENT_SECURITY_POLICY))
        .add(("Cache-Control", "no-store"))
        .add(("X-Content-Type-Options", "nosniff"))
}

/// A static asset (cacheable; overrides the default `no-store`).
fn static_asset(content_type: &'static str, body: &'static str) -> HttpResponse {
    HttpResponse::Ok()
        .content_type(content_type)
        .insert_header(("Cache-Control", "public, max-age=3600"))
        .body(body)
}

/// GET /static/app.css
pub async fn app_css() -> HttpResponse {
    static_asset("text/css; charset=utf-8", APP_CSS)
}

/// GET /static/app.js
pub async fn app_js() -> HttpResponse {
    static_asset("text/javascript; charset=utf-8", APP_JS)
}

/// Configure routes
pub fn configure_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/admin")
            .route("/login", web::get().to(login_page))
            .route("/login", web::post().to(login_submit))
            .route("/logout", web::post().to(logout))
            .route("/sso/login", web::get().to(sso_login))
            .route("", web::get().to(dashboard))
            .route("/", web::get().to(dashboard))
            .route("/users", web::get().to(users_list))
            .route("/users/new", web::get().to(user_new))
            .route("/users/new", web::post().to(user_create))
            .route("/users/{username}", web::get().to(user_edit))
            .route("/users/{username}", web::post().to(user_update))
            .route("/users/{username}/delete", web::post().to(user_delete))
            .route("/groups", web::get().to(groups_list))
            .route("/groups/new", web::get().to(group_new))
            .route("/groups/new", web::post().to(group_create))
            .route("/groups/{name}", web::get().to(group_edit))
            .route("/groups/{name}", web::post().to(group_update))
            .route("/groups/{name}/delete", web::post().to(group_delete))
            .route("/groups/{name}/members", web::post().to(group_add_member))
            .route(
                "/groups/{name}/members/{member}/remove",
                web::post().to(group_remove_member),
            ),
    );
    // Self-service password change for any local user.
    cfg.service(
        web::resource(crate::config::ACCOUNT_PASSWORD_PATH)
            .route(web::get().to(account_password_page))
            .route(web::post().to(account_password_submit)),
    );
    // OAuth2 redirect URI (SSO_REDIRECT_URI defaults to http://localhost:8080/callback)
    cfg.route("/callback", web::get().to(sso_callback));
    cfg.route("/static/app.css", web::get().to(app_css));
    cfg.route("/static/app.js", web::get().to(app_js));
}

/// Start the web admin server.
///
/// When disabled this logs once and then never completes, so it can sit in a
/// `select!` next to the mail servers without ending them.
pub async fn run_web_server(
    services: WebServices,
    domain: String,
    config: WebAdminConfig,
) -> std::io::Result<()> {
    use actix_web::{App, HttpServer};

    if !config.enabled {
        tracing::info!("Web admin disabled (set KISS_MAIL_WEB_ENABLED=true to enable)");
        std::future::pending::<()>().await;
        return Ok(());
    }

    let addr = format!("{}:{}", config.bind_address, config.port);

    let WebServices {
        user_manager,
        group_manager,
        ldap_client,
        sso_manager,
        storage,
        crypto_manager,
    } = services;
    let web_state = web::Data::new(WebState {
        user_manager,
        group_manager,
        ldap_client,
        sso_manager,
        storage,
        crypto_manager,
        hbs: create_handlebars(),
        domain,
        sessions: SessionStore::new(),
        secure_cookie: config.secure_cookie,
        sso_auto_bind_admins: config.sso_auto_bind_admins,
    });

    tracing::info!("Web admin listening on http://{}", addr);

    HttpServer::new(move || {
        App::new()
            .wrap(security_headers())
            .app_data(web_state.clone())
            .configure(configure_routes)
            .route(
                "/",
                web::get().to(|| async {
                    HttpResponse::Found()
                        .append_header(("Location", "/admin"))
                        .finish()
                }),
            )
    })
    // Shutdown signals are handled by the server supervisor in main.rs.
    .disable_signals()
    .bind(&addr)?
    .run()
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ldap::LdapConfig;
    use crate::sso::SsoConfig;
    use actix_web::App;
    use actix_web::test as actix_test;
    use std::collections::HashMap;
    use tempfile::tempdir;

    fn test_session() -> WebSession {
        WebSession {
            username: "admin".into(),
            csrf: "tok".into(),
            password_changed_at: Utc::now(),
        }
    }

    fn test_state_with_sso(dir: &std::path::Path, sso: SsoConfig) -> web::Data<WebState> {
        test_state_full(dir, sso, false)
    }

    fn test_state_full(
        dir: &std::path::Path,
        sso: SsoConfig,
        sso_auto_bind_admins: bool,
    ) -> web::Data<WebState> {
        let data_dir = dir.to_path_buf();
        let user_manager = Arc::new(UserManager::new("example.com".into(), data_dir.clone()));
        let storage = Arc::new(Storage::new(data_dir.clone(), Arc::clone(&user_manager)));
        let group_manager = Arc::new(GroupManager::new(data_dir.clone()));
        group_manager.attach_user_manager(Arc::clone(&user_manager));
        web::Data::new(WebState {
            user_manager,
            group_manager,
            ldap_client: Arc::new(LdapClient::new(LdapConfig::default())),
            sso_manager: Arc::new(SsoManager::new(sso, data_dir.clone())),
            storage,
            crypto_manager: Some(Arc::new(CryptoManager::with_enabled(data_dir, true))),
            hbs: create_handlebars(),
            domain: "example.com".into(),
            sessions: SessionStore::new(),
            secure_cookie: true,
            sso_auto_bind_admins,
        })
    }

    fn test_state(dir: &std::path::Path) -> web::Data<WebState> {
        test_state_with_sso(dir, SsoConfig::default())
    }

    /// The service under test, wrapped like the real server.
    macro_rules! app {
        ($data:expr) => {
            actix_test::init_service(
                App::new()
                    .wrap(security_headers())
                    .app_data($data.clone())
                    .configure(configure_routes),
            )
            .await
        };
    }

    /// Create an admin account and a server session for it; returns
    /// (session token, csrf token).
    async fn admin_session(data: &WebState, username: &str) -> (String, String) {
        let user = data
            .user_manager
            .create_user(username, "password123", Some(UserRole::Admin))
            .await
            .unwrap();
        let session = WebSession::new(&user);
        let csrf = session.csrf.clone();
        let token = data.sessions.create(session, SESSION_TTL).await;
        (token, csrf)
    }

    fn location(resp: &actix_web::dev::ServiceResponse) -> String {
        resp.headers()
            .get("Location")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string()
    }

    async fn body_of(resp: actix_web::dev::ServiceResponse) -> String {
        String::from_utf8(actix_test::read_body(resp).await.to_vec()).unwrap()
    }

    fn body_string(resp: HttpResponse) -> String {
        let bytes = futures_lite_block_on(actix_web::body::to_bytes(resp.into_body())).unwrap();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    fn futures_lite_block_on<F: std::future::Future>(f: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(f)
    }

    // ---- minimal HTML inspection (independent of whitespace, attribute
    // order and Handlebars' entity escaping) ------------------------------

    /// Decode the entities Handlebars produces.
    fn unescape(s: &str) -> String {
        s.replace("&#x3D;", "=")
            .replace("&#x27;", "'")
            .replace("&#x60;", "`")
            .replace("&quot;", "\"")
            .replace("&lt;", "<")
            .replace("&gt;", ">")
            .replace("&amp;", "&")
    }

    /// Attributes of every `<tag ...>` element, in document order.
    fn elements(html: &str, tag: &str) -> Vec<HashMap<String, String>> {
        let open = format!("<{}", tag);
        let mut out = Vec::new();
        let mut rest = html;
        while let Some(i) = rest.find(&open) {
            rest = &rest[i + open.len()..];
            if !rest.starts_with(|c: char| c.is_whitespace() || c == '>') {
                continue;
            }
            let end = rest.find('>').unwrap_or(rest.len());
            out.push(parse_attrs(&rest[..end]));
            rest = &rest[end..];
        }
        out
    }

    fn parse_attrs(mut s: &str) -> HashMap<String, String> {
        let mut attrs = HashMap::new();
        loop {
            s = s.trim_start();
            let name_end = s
                .find(|c: char| c.is_whitespace() || c == '=' || c == '/')
                .unwrap_or(s.len());
            if name_end == 0 {
                if s.is_empty() {
                    break;
                }
                s = &s[1..];
                continue;
            }
            let name = s[..name_end].to_ascii_lowercase();
            s = s[name_end..].trim_start();
            let value = if let Some(after) = s.strip_prefix('=') {
                let after = after.trim_start();
                if let Some(q) = after.strip_prefix('"') {
                    let end = q.find('"').unwrap_or(q.len());
                    s = &q[(end + 1).min(q.len())..];
                    unescape(&q[..end])
                } else {
                    let end = after.find(char::is_whitespace).unwrap_or(after.len());
                    s = &after[end..];
                    unescape(&after[..end])
                }
            } else {
                String::new()
            };
            attrs.insert(name, value);
        }
        attrs
    }

    /// Whether some `<tag>` has all the given attribute values.
    fn has_element(html: &str, tag: &str, want: &[(&str, &str)]) -> bool {
        elements(html, tag).iter().any(|attrs| {
            want.iter()
                .all(|(k, v)| attrs.get(*k).map(String::as_str) == Some(*v))
        })
    }

    /// The text content of the page (tags stripped, entities decoded,
    /// whitespace collapsed).
    fn text_of(html: &str) -> String {
        let mut out = String::new();
        let mut in_tag = false;
        for c in html.chars() {
            match c {
                '<' => {
                    in_tag = true;
                    out.push(' ');
                }
                '>' => in_tag = false,
                c if !in_tag => out.push(c),
                _ => {}
            }
        }
        unescape(&out)
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
    }

    // ---- unit tests ------------------------------------------------------

    #[test]
    fn test_loopback_bind() {
        assert!(is_loopback_bind("127.0.0.1"));
        assert!(is_loopback_bind("::1"));
        assert!(is_loopback_bind("[::1]"));
        assert!(is_loopback_bind("LocalHost"));
        assert!(!is_loopback_bind("0.0.0.0"));
        assert!(!is_loopback_bind("192.168.1.10"));
    }

    #[test]
    fn test_flash_codes() {
        for f in Flash::ALL {
            assert_eq!(Flash::from_code(f.code), Some(*f));
        }
        let mut codes: Vec<_> = Flash::ALL.iter().map(|f| f.code).collect();
        codes.sort();
        codes.dedup();
        assert_eq!(codes.len(), Flash::ALL.len());
        let q = FlashQuery {
            flash: Some("<script>alert(1)</script>".into()),
        };
        assert!(q.success().is_none() && q.error().is_none());
        let q = FlashQuery {
            flash: Some("user_not_found".into()),
        };
        assert_eq!(q.error(), Some("User not found"));
        assert!(q.success().is_none());
    }

    #[test]
    fn test_flash_is_escaped() {
        let hbs = create_handlebars();
        let resp = render_page(
            &hbs,
            "T",
            &test_session(),
            "",
            Nav::Dashboard,
            Some("<script>x</script>"),
            None,
        );
        assert_eq!(resp.status(), 200);
        let html = body_string(resp);
        assert!(!html.contains("<script>x</script>"));
        assert!(text_of(&html).contains("<script>x</script>"));
        // Logout is a CSRF-protected POST form.
        assert!(has_element(
            &html,
            "form",
            &[("action", "/admin/logout"), ("method", "POST")]
        ));
        assert!(has_element(
            &html,
            "input",
            &[("name", "csrf"), ("value", "tok")]
        ));
    }

    #[test]
    fn templates_have_no_inline_script_or_external_resources() {
        for (name, source) in TEMPLATES {
            assert!(!source.contains("onsubmit"), "{}", name);
            assert!(!source.contains("onclick"), "{}", name);
            assert!(!source.contains("<style"), "{}", name);
            assert!(!source.contains("style=\""), "{}", name);
            assert!(!source.contains("cdn."), "{}", name);
            assert!(!source.contains("https://"), "{}", name);
            for script in elements(source, "script") {
                assert!(
                    script.get("src").is_some_and(|s| s.starts_with('/')),
                    "{}",
                    name
                );
            }
        }
    }

    #[test]
    fn test_list_templates_have_generic_confirm_and_csrf() {
        let hbs = create_handlebars();
        let html = hbs
            .render(
                "users",
                &json!({"csrf": "tok", "users": [{"username": "x');alert(1);//"}]}),
            )
            .unwrap();
        assert!(has_element(
            &html,
            "form",
            &[("data-confirm", "Delete this user?")]
        ));
        assert!(has_element(
            &html,
            "input",
            &[("name", "csrf"), ("value", "tok")]
        ));
        let html = hbs
            .render("groups", &json!({"csrf": "tok", "groups": [{"name": "g"}]}))
            .unwrap();
        assert!(has_element(
            &html,
            "form",
            &[("data-confirm", "Delete this group?")]
        ));
        assert!(has_element(
            &html,
            "input",
            &[("name", "csrf"), ("value", "tok")]
        ));
    }

    #[test]
    fn test_login_template_sso_link() {
        let hbs = create_handlebars();
        let html = hbs
            .render(
                "login",
                &json!({"version": "x", "sso_enabled": true, "sso_provider": "Google"}),
            )
            .unwrap();
        assert!(has_element(&html, "a", &[("href", "/admin/sso/login")]));
        let html = hbs
            .render("login", &json!({"version": "x", "sso_enabled": false}))
            .unwrap();
        assert!(!has_element(&html, "a", &[("href", "/admin/sso/login")]));
    }

    #[test]
    fn admin_nav_links_to_own_password_change() {
        let hbs = create_handlebars();
        let resp = render_page(&hbs, "t", &test_session(), "", Nav::Dashboard, None, None);
        let html = body_string(resp);
        assert!(
            has_element(&html, "a", &[("href", "/account/password?username=admin")]),
            "{}",
            html
        );
        assert!(text_of(&html).contains("Change my password"));
    }

    // ---- static assets and headers ----------------------------------------

    #[actix_web::test]
    async fn static_assets_and_security_headers() {
        let dir = tempdir().unwrap();
        let data = test_state(dir.path());
        let app = app!(data);

        let resp = actix_test::call_service(
            &app,
            actix_test::TestRequest::get()
                .uri("/static/app.css")
                .to_request(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(
            resp.headers()
                .get("content-type")
                .unwrap()
                .to_str()
                .unwrap()
                .starts_with("text/css")
        );
        assert_eq!(
            resp.headers().get("cache-control").unwrap(),
            "public, max-age=3600"
        );
        let css = body_of(resp).await;
        assert!(css.contains(".bg-gray-50"));
        assert!(css.contains(".border-primary"));

        let resp = actix_test::call_service(
            &app,
            actix_test::TestRequest::get()
                .uri("/static/app.js")
                .to_request(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(body_of(resp).await.contains("data-confirm"));

        for uri in ["/admin/login", "/account/password"] {
            let resp = actix_test::call_service(
                &app,
                actix_test::TestRequest::get().uri(uri).to_request(),
            )
            .await;
            let h = resp.headers();
            assert_eq!(
                h.get("content-security-policy").unwrap(),
                CONTENT_SECURITY_POLICY,
                "{}",
                uri
            );
            assert_eq!(h.get("cache-control").unwrap(), "no-store", "{}", uri);
            assert_eq!(
                h.get("x-content-type-options").unwrap(),
                "nosniff",
                "{}",
                uri
            );
            let html = body_of(resp).await;
            assert!(
                has_element(&html, "link", &[("href", "/static/app.css")]),
                "{}",
                uri
            );
        }
    }

    // ---- sessions ---------------------------------------------------------

    #[actix_web::test]
    async fn forged_username_cookie_redirects_to_login() {
        let dir = tempdir().unwrap();
        let data = test_state(dir.path());
        admin_session(&data, "admin1").await;
        let app = app!(data);

        let req = actix_test::TestRequest::get()
            .uri("/admin")
            .cookie(Cookie::new(SESSION_COOKIE, "admin1"))
            .to_request();
        let resp = actix_test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::FOUND);
        assert_eq!(location(&resp), "/admin/login");
    }

    /// GET /admin with a session token; true if the dashboard was served.
    macro_rules! dashboard_ok {
        ($app:expr, $token:expr) => {{
            let req = actix_test::TestRequest::get()
                .uri("/admin")
                .cookie(Cookie::new(SESSION_COOKIE, $token.to_string()))
                .to_request();
            actix_test::call_service($app, req).await.status() == StatusCode::OK
        }};
    }

    #[actix_web::test]
    async fn demoted_admin_session_rejected_and_purged() {
        let dir = tempdir().unwrap();
        let data = test_state(dir.path());
        let (token, _) = admin_session(&data, "admin1").await;
        let app = app!(data);

        assert!(dashboard_ok!(&app, token));
        data.user_manager
            .update_user("admin1", |u| u.role = UserRole::User)
            .await
            .unwrap();
        assert!(!dashboard_ok!(&app, token));
        assert!(!data.sessions.contains(&token).await);
    }

    #[actix_web::test]
    async fn session_dies_on_password_change_or_required_change() {
        let dir = tempdir().unwrap();
        let data = test_state(dir.path());
        let (token, _) = admin_session(&data, "admin1").await;
        let (token2, _) = admin_session(&data, "admin2").await;
        let app = app!(data);
        assert!(dashboard_ok!(&app, token));
        assert!(dashboard_ok!(&app, token2));

        tokio::time::sleep(Duration::from_millis(5)).await;
        data.user_manager
            .change_password("admin1", "password123", "new-password-1")
            .await
            .unwrap();
        assert!(!dashboard_ok!(&app, token));
        assert!(!data.sessions.contains(&token).await);

        data.user_manager
            .update_user("admin2", |u| u.password_change_required = true)
            .await
            .unwrap();
        assert!(!dashboard_ok!(&app, token2));
    }

    #[actix_web::test]
    async fn logout_invalidates_server_session() {
        let dir = tempdir().unwrap();
        let data = test_state(dir.path());
        let (token, csrf) = admin_session(&data, "admin1").await;
        let app = app!(data);

        // Logout without the CSRF token is refused and keeps the session.
        let req = actix_test::TestRequest::post()
            .uri("/admin/logout")
            .cookie(Cookie::new(SESSION_COOKIE, token.clone()))
            .set_form([("csrf", "wrong")])
            .to_request();
        assert_eq!(
            actix_test::call_service(&app, req).await.status(),
            StatusCode::FORBIDDEN
        );
        assert!(data.sessions.contains(&token).await);

        let req = actix_test::TestRequest::post()
            .uri("/admin/logout")
            .cookie(Cookie::new(SESSION_COOKIE, token.clone()))
            .set_form([("csrf", csrf.as_str())])
            .to_request();
        let resp = actix_test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::FOUND);
        let cleared = resp
            .response()
            .cookies()
            .find(|c| c.name() == SESSION_COOKIE)
            .expect("removal cookie");
        assert_eq!(cleared.value(), "");
        assert!(!data.sessions.contains(&token).await);
        assert!(!dashboard_ok!(&app, token));
    }

    /// GET /admin/login; evaluates to the login CSRF token.
    macro_rules! login_csrf {
        ($app:expr) => {{
            let resp = actix_test::call_service(
                $app,
                actix_test::TestRequest::get()
                    .uri("/admin/login")
                    .to_request(),
            )
            .await;
            resp.response()
                .cookies()
                .find(|c| c.name() == LOGIN_CSRF_COOKIE)
                .expect("login csrf cookie")
                .value()
                .to_string()
        }};
    }

    #[actix_web::test]
    async fn login_sets_hardened_cookie() {
        let dir = tempdir().unwrap();
        let data = test_state(dir.path());
        data.user_manager
            .create_user("admin1", "password123", Some(UserRole::Admin))
            .await
            .unwrap();
        let app = app!(data);
        let login_csrf = login_csrf!(&app);

        // Missing token: rejected.
        let req = actix_test::TestRequest::post()
            .uri("/admin/login")
            .set_form([("username", "admin1"), ("password", "password123")])
            .to_request();
        let resp = actix_test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);

        // Cross-origin: rejected even with a valid token.
        let req = actix_test::TestRequest::post()
            .uri("/admin/login")
            .insert_header(("Host", "admin.example.com"))
            .insert_header(("Origin", "https://evil.example"))
            .cookie(Cookie::new(LOGIN_CSRF_COOKIE, login_csrf.clone()))
            .set_form([
                ("username", "admin1"),
                ("password", "password123"),
                ("csrf", login_csrf.as_str()),
            ])
            .to_request();
        assert_eq!(
            actix_test::call_service(&app, req).await.status(),
            StatusCode::FORBIDDEN
        );

        let req = actix_test::TestRequest::post()
            .uri("/admin/login")
            .insert_header(("Host", "admin.example.com"))
            .insert_header(("Origin", "https://admin.example.com"))
            .cookie(Cookie::new(LOGIN_CSRF_COOKIE, login_csrf.clone()))
            .set_form([
                ("username", "admin1"),
                ("password", "password123"),
                ("csrf", login_csrf.as_str()),
            ])
            .to_request();
        let resp = actix_test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::FOUND);
        let cookie = resp
            .response()
            .cookies()
            .find(|c| c.name() == SESSION_COOKIE)
            .expect("session cookie");
        assert_eq!(cookie.http_only(), Some(true));
        assert_eq!(cookie.same_site(), Some(SameSite::Strict));
        assert_eq!(cookie.secure(), Some(true));
        assert_eq!(cookie.path(), Some("/"));
        // The cookie holds a random token, not the username.
        assert_ne!(cookie.value(), "admin1");
        assert!(data.sessions.lookup(cookie.value()).await.is_some());
    }

    #[actix_web::test]
    async fn admin_login_with_change_required_redirects_without_session() {
        let dir = tempdir().unwrap();
        let data = test_state(dir.path());
        data.user_manager
            .create_user("admin1", "password123", Some(UserRole::Admin))
            .await
            .unwrap();
        data.user_manager
            .update_user("admin1", |u| u.password_change_required = true)
            .await
            .unwrap();
        let app = app!(data);
        let login_csrf = login_csrf!(&app);

        let req = actix_test::TestRequest::post()
            .uri("/admin/login")
            .cookie(Cookie::new(LOGIN_CSRF_COOKIE, login_csrf.clone()))
            .set_form([
                ("username", "Admin1"),
                ("password", "password123"),
                ("csrf", login_csrf.as_str()),
            ])
            .to_request();
        let resp = actix_test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::FOUND);
        assert_eq!(
            location(&resp),
            "/account/password?username=admin1&reason=required"
        );
        assert!(
            resp.response()
                .cookies()
                .all(|c| c.name() != SESSION_COOKIE)
        );
    }

    // ---- self-service password change -----------------------------------

    /// GET the password-change page; evaluates to (account CSRF token, HTML).
    macro_rules! account_form {
        ($app:expr, $uri:expr) => {{
            let resp = actix_test::call_service(
                $app,
                actix_test::TestRequest::get().uri($uri).to_request(),
            )
            .await;
            assert_eq!(resp.status(), StatusCode::OK);
            let cookie = resp
                .response()
                .cookies()
                .find(|c| c.name() == ACCOUNT_CSRF_COOKIE)
                .expect("account csrf cookie");
            assert_eq!(cookie.path(), Some("/account"));
            assert_eq!(cookie.http_only(), Some(true));
            let token = cookie.value().to_string();
            (token, body_of(resp).await)
        }};
    }

    /// Form fields for changing `user`'s password to "newpassword1".
    fn change_fields<'a>(
        csrf: &'a str,
        user: &'a str,
        current: &'a str,
    ) -> [(&'a str, &'a str); 5] {
        [
            ("username", user),
            ("current_password", current),
            ("new_password", "newpassword1"),
            ("confirm_password", "newpassword1"),
            ("csrf", csrf),
        ]
    }

    /// A same-origin POST to the password-change page with the CSRF cookie.
    fn account_post(csrf_cookie: &str, fields: &[(&str, &str)]) -> actix_test::TestRequest {
        actix_test::TestRequest::post()
            .uri("/account/password")
            .insert_header(("Host", "mail.example.com"))
            .insert_header(("Origin", "https://mail.example.com"))
            .cookie(Cookie::new(ACCOUNT_CSRF_COOKIE, csrf_cookie.to_string()))
            .set_form(fields)
    }

    #[actix_web::test]
    async fn account_password_get_renders_form_without_admin_nav() {
        let dir = tempdir().unwrap();
        let data = test_state(dir.path());
        let app = app!(data);

        let (token, html) = account_form!(&app, "/account/password?username=bob");
        assert!(has_element(
            &html,
            "input",
            &[("name", "username"), ("value", "bob")]
        ));
        assert!(has_element(
            &html,
            "input",
            &[("name", "csrf"), ("value", &token)]
        ));
        assert!(!has_element(&html, "form", &[("action", "/admin/logout")]));
        assert!(!text_of(&html).contains(PASSWORD_CHANGE_REQUIRED_TEXT));

        let (_, html) = account_form!(&app, "/account/password?username=bob&reason=required");
        assert!(text_of(&html).contains(PASSWORD_CHANGE_REQUIRED_TEXT));
    }

    #[actix_web::test]
    async fn account_password_post_changes_password_for_any_user() {
        let dir = tempdir().unwrap();
        let data = test_state(dir.path());
        data.user_manager
            .create_user("bob", "password123", None)
            .await
            .unwrap();
        data.user_manager
            .update_user("bob", |u| u.password_change_required = true)
            .await
            .unwrap();
        data.user_manager
            .create_user("admin1", "password123", Some(UserRole::Admin))
            .await
            .unwrap();
        let app = app!(data);

        // Mismatched confirmation.
        let (token, _) = account_form!(&app, "/account/password");
        let resp = actix_test::call_service(
            &app,
            account_post(
                &token,
                &[
                    ("username", "bob"),
                    ("current_password", "password123"),
                    ("new_password", "newpassword1"),
                    ("confirm_password", "newpassword2"),
                    ("csrf", token.as_str()),
                ],
            )
            .to_request(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        // A regular user with the must-change flag.
        let (token, _) = account_form!(&app, "/account/password");
        let resp = actix_test::call_service(
            &app,
            account_post(&token, &change_fields(&token, "bob", "password123")).to_request(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let text = text_of(&body_of(resp).await);
        assert!(text.contains("Your password has been changed"), "{}", text);
        assert!(text.contains("Use your new password in your mail client"));
        let bob = data.user_manager.get_user("bob").await.unwrap();
        assert!(bob.verify_password("newpassword1"));
        assert!(!bob.password_change_required);

        // An admin gets a link to the admin login.
        let (token, _) = account_form!(&app, "/account/password");
        let resp = actix_test::call_service(
            &app,
            account_post(&token, &change_fields(&token, "admin1", "password123")).to_request(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let html = body_of(resp).await;
        assert!(
            has_element(&html, "a", &[("href", "/admin/login")]),
            "{}",
            html
        );
    }

    #[actix_web::test]
    async fn account_password_post_rejects_bad_csrf_and_wrong_password() {
        let dir = tempdir().unwrap();
        let data = test_state(dir.path());
        data.user_manager
            .create_user("bob", "password123", None)
            .await
            .unwrap();
        let app = app!(data);

        let (token, _) = account_form!(&app, "/account/password");
        // Token in the form does not match the cookie.
        let resp = actix_test::call_service(
            &app,
            account_post(&token, &change_fields("wrong", "bob", "password123")).to_request(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        // Cross-origin, even with matching tokens.
        let req = actix_test::TestRequest::post()
            .uri("/account/password")
            .insert_header(("Host", "mail.example.com"))
            .insert_header(("Origin", "https://evil.example"))
            .cookie(Cookie::new(ACCOUNT_CSRF_COOKIE, token.clone()))
            .set_form(change_fields(&token, "bob", "password123"))
            .to_request();
        assert_eq!(
            actix_test::call_service(&app, req).await.status(),
            StatusCode::FORBIDDEN
        );
        assert!(
            data.user_manager
                .get_user("bob")
                .await
                .unwrap()
                .verify_password("password123")
        );

        // Wrong password and unknown user: the same generic message.
        let mut texts = Vec::new();
        for (user, current) in [("bob", "wrongpass"), ("nobody", "password123")] {
            let (token, _) = account_form!(&app, "/account/password");
            let resp = actix_test::call_service(
                &app,
                account_post(&token, &change_fields(&token, user, current)).to_request(),
            )
            .await;
            assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
            let html = body_of(resp).await;
            // The flash box: the page minus the (differing) prefilled form.
            let msg = PasswordChangeFailure::BadCredentials.user_message();
            assert!(text_of(&html).contains(&msg), "{}", html);
            texts.push(msg);
        }
        assert_eq!(texts[0], texts[1]);
    }

    // ---- admin pages --------------------------------------------------------

    #[actix_web::test]
    async fn post_without_csrf_rejected() {
        let dir = tempdir().unwrap();
        let data = test_state(dir.path());
        let (token, csrf) = admin_session(&data, "admin1").await;
        let app = app!(data);

        let req = actix_test::TestRequest::post()
            .uri("/admin/users/new")
            .cookie(Cookie::new(SESSION_COOKIE, token.clone()))
            .set_form([("username", "mallory"), ("password", "password123")])
            .to_request();
        let resp = actix_test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert!(data.user_manager.get_user("mallory").await.is_none());

        // Same request with the token succeeds (display name saved too).
        let req = actix_test::TestRequest::post()
            .uri("/admin/users/new")
            .cookie(Cookie::new(SESSION_COOKIE, token))
            .set_form([
                ("username", "mallory"),
                ("password", "password123"),
                ("display_name", "  Mal  "),
                ("csrf", csrf.as_str()),
            ])
            .to_request();
        let resp = actix_test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::FOUND);
        assert_eq!(location(&resp), "/admin/users?flash=user_created");
        let mallory = data.user_manager.get_user("mallory").await.unwrap();
        assert_eq!(mallory.settings.display_name.as_deref(), Some("Mal"));
    }

    #[actix_web::test]
    async fn admin_cannot_create_superadmin() {
        let dir = tempdir().unwrap();
        let data = test_state(dir.path());
        let (token, csrf) = admin_session(&data, "admin1").await;
        let app = app!(data);

        let req = actix_test::TestRequest::post()
            .uri("/admin/users/new")
            .cookie(Cookie::new(SESSION_COOKIE, token))
            .set_form([
                ("username", "boss"),
                ("password", "password123"),
                ("role", "superadmin"),
                ("csrf", csrf.as_str()),
            ])
            .to_request();
        let resp = actix_test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert!(data.user_manager.get_user("boss").await.is_none());
    }

    #[actix_web::test]
    async fn edit_form_preserves_locked_status() {
        let dir = tempdir().unwrap();
        let data = test_state(dir.path());
        let (token, csrf) = admin_session(&data, "admin1").await;
        data.user_manager
            .create_user("bob", "password123", None)
            .await
            .unwrap();
        data.user_manager
            .update_user("bob", |u| u.status = AccountStatus::Locked)
            .await
            .unwrap();
        let app = app!(data);

        // The form shows every status with the current one selected.
        let req = actix_test::TestRequest::get()
            .uri("/admin/users/bob")
            .cookie(Cookie::new(SESSION_COOKIE, token.clone()))
            .to_request();
        let resp = actix_test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let html = body_of(resp).await;
        let options = elements(&html, "option");
        let status_option = |v: &str| {
            options
                .iter()
                .find(|o| o.get("value").map(String::as_str) == Some(v))
        };
        assert!(
            status_option("locked").unwrap().contains_key("selected"),
            "{}",
            html
        );
        for v in ["active", "disabled", "pending"] {
            assert!(!status_option(v).unwrap().contains_key("selected"), "{}", v);
        }
        assert!(has_element(
            &html,
            "input",
            &[("name", "original_status"), ("value", "locked")]
        ));

        // Saving an unrelated change keeps the account locked.
        let req = actix_test::TestRequest::post()
            .uri("/admin/users/bob")
            .cookie(Cookie::new(SESSION_COOKIE, token.clone()))
            .set_form([
                ("username", "bob"),
                ("display_name", "Bob"),
                ("role", "user"),
                ("status", "locked"),
                ("original_status", "locked"),
                ("csrf", csrf.as_str()),
            ])
            .to_request();
        let resp = actix_test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::FOUND);
        let bob = data.user_manager.get_user("bob").await.unwrap();
        assert_eq!(bob.status, AccountStatus::Locked);
        assert_eq!(bob.settings.display_name.as_deref(), Some("Bob"));

        // A stale form (rendered while active) does not re-activate either.
        let req = actix_test::TestRequest::post()
            .uri("/admin/users/bob")
            .cookie(Cookie::new(SESSION_COOKIE, token))
            .set_form([
                ("username", "bob"),
                ("status", "active"),
                ("original_status", "active"),
                ("csrf", csrf.as_str()),
            ])
            .to_request();
        actix_test::call_service(&app, req).await;
        assert_eq!(
            data.user_manager.get_user("bob").await.unwrap().status,
            AccountStatus::Locked
        );
    }

    #[actix_web::test]
    async fn web_password_reset_revokes_app_passwords_and_shows_count() {
        let dir = tempdir().unwrap();
        let data = test_state(dir.path());
        let (token, csrf) = admin_session(&data, "admin1").await;
        data.user_manager
            .create_user("bob", "password123", None)
            .await
            .unwrap();
        data.sso_manager
            .generate_app_password("bob", "phone", None)
            .await
            .unwrap();
        let app = app!(data);

        let req = actix_test::TestRequest::post()
            .uri("/admin/users/bob")
            .cookie(Cookie::new(SESSION_COOKIE, token.clone()))
            .set_form([
                ("username", "bob"),
                ("password", "new-password-1"),
                ("csrf", csrf.as_str()),
            ])
            .to_request();
        let resp = actix_test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let text = text_of(&body_of(resp).await);
        assert!(text.contains("1 app password(s) revoked"), "{}", text);
        assert!(data.sso_manager.list_app_passwords("bob").await.is_empty());

        // A failing step is shown and answered with 400.
        let req = actix_test::TestRequest::post()
            .uri("/admin/users/bob")
            .cookie(Cookie::new(SESSION_COOKIE, token))
            .set_form([
                ("username", "bob"),
                ("password", "short"),
                ("csrf", csrf.as_str()),
            ])
            .to_request();
        let resp = actix_test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert!(text_of(&body_of(resp).await).contains("Password: "));
    }

    #[actix_web::test]
    async fn web_user_delete_cleans_mailbox_sso_and_groups() {
        let dir = tempdir().unwrap();
        let data = test_state(dir.path());
        let (token, csrf) = admin_session(&data, "admin1").await;
        data.user_manager
            .create_user("bob", "password123", None)
            .await
            .unwrap();
        data.storage.ensure_mailbox("bob").await;
        data.sso_manager
            .generate_app_password("bob", "phone", None)
            .await
            .unwrap();
        let crypto = Arc::clone(data.crypto_manager.as_ref().unwrap());
        crypto.generate_keypair("bob", "password123").await.unwrap();
        data.group_manager
            .create_with_members("team", "team@example.com", "bob", None, &["bob".into()])
            .await
            .unwrap();
        let app = app!(data);

        let req = actix_test::TestRequest::post()
            .uri("/admin/users/bob/delete")
            .cookie(Cookie::new(SESSION_COOKIE, token))
            .set_form([("csrf", csrf.as_str())])
            .to_request();
        let resp = actix_test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::FOUND);
        assert_eq!(location(&resp), "/admin/users?flash=user_deleted");
        assert!(data.user_manager.get_user("bob").await.is_none());
        assert!(data.storage.message_meta("bob").await.is_none());
        assert!(data.sso_manager.get_user_data("bob").await.is_none());
        assert!(!crypto.has_keys("bob").await);
        let g = data.group_manager.get("team").await.unwrap();
        assert!(!g.is_member("bob"));
        // No bootstrap admin or super admin can take the group over.
        assert!(!g.active);
    }

    #[actix_web::test]
    async fn web_add_unknown_member_shows_error() {
        let dir = tempdir().unwrap();
        let data = test_state(dir.path());
        let (token, csrf) = admin_session(&data, "admin1").await;
        data.group_manager
            .create("team", "team@example.com", "admin1")
            .await
            .unwrap();
        let app = app!(data);

        let req = actix_test::TestRequest::post()
            .uri("/admin/groups/team/members")
            .cookie(Cookie::new(SESSION_COOKIE, token))
            .set_form([("username", "ghost"), ("csrf", csrf.as_str())])
            .to_request();
        let resp = actix_test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(text_of(&body_of(resp).await).contains("user ghost does not exist"));
        assert!(
            data.group_manager
                .get("team")
                .await
                .unwrap()
                .members
                .is_empty()
        );
    }

    #[actix_web::test]
    async fn web_group_create_saves_description() {
        let dir = tempdir().unwrap();
        let data = test_state(dir.path());
        let (token, csrf) = admin_session(&data, "admin1").await;
        let app = app!(data);
        let req = actix_test::TestRequest::post()
            .uri("/admin/groups/new")
            .cookie(Cookie::new(SESSION_COOKIE, token))
            .set_form([
                ("name", "ops"),
                ("email", "ops@example.com"),
                ("description", "Operations"),
                ("csrf", csrf.as_str()),
            ])
            .to_request();
        let resp = actix_test::call_service(&app, req).await;
        assert_eq!(location(&resp), "/admin/groups?flash=group_created");
        let g = data.group_manager.get("ops").await.unwrap();
        assert_eq!(g.description, "Operations");
        assert_eq!(g.owner, "admin1");
        assert!(g.members.is_empty());
    }

    // ---- SSO callback (stub identity provider) ------------------------------

    /// Minimal OAuth2 IdP: `POST /token` returns the authorization code as
    /// the access token, and `GET /userinfo` maps that token (a username)
    /// to verified claims `<user>@example.com` with subject `sub-<user>`.
    struct StubIdp {
        base: String,
        task: tokio::task::JoinHandle<()>,
    }

    impl Drop for StubIdp {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    async fn stub_idp() -> StubIdp {
        use axum::{
            Form, Json, Router,
            http::HeaderMap,
            routing::{get, post},
        };
        let app = Router::new()
            .route(
                "/token",
                post(|Form(f): Form<HashMap<String, String>>| async move {
                    Json(json!({
                        "access_token": f.get("code").cloned().unwrap_or_default(),
                        "token_type": "Bearer",
                    }))
                }),
            )
            .route(
                "/userinfo",
                get(|headers: HeaderMap| async move {
                    let user = headers
                        .get("authorization")
                        .and_then(|v| v.to_str().ok())
                        .and_then(|v| v.strip_prefix("Bearer "))
                        .unwrap_or_default()
                        .to_string();
                    Json(json!({
                        "sub": format!("sub-{}", user),
                        "email": format!("{}@example.com", user),
                        "email_verified": true,
                    }))
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        StubIdp {
            base: format!("http://{}", addr),
            task,
        }
    }

    fn stub_sso_config(idp: &StubIdp) -> SsoConfig {
        SsoConfig {
            enabled: true,
            client_id: "cid".into(),
            client_secret: "secret".into(),
            auth_url: format!("{}/authorize", idp.base),
            token_url: format!("{}/token", idp.base),
            userinfo_url: Some(format!("{}/userinfo", idp.base)),
            allowed_domains: vec!["example.com".into()],
            ..Default::default()
        }
    }

    /// Run the callback for `user` (a fresh authorization state each time).
    macro_rules! sso_callback_for {
        ($app:expr, $data:expr, $user:expr) => {{
            let (_, state) = $data.sso_manager.start_auth().await.unwrap();
            let req = actix_test::TestRequest::get()
                .uri(&format!("/callback?code={}&state={}", $user, state))
                .to_request();
            actix_test::call_service($app, req).await
        }};
    }

    fn session_cookie_of(resp: &actix_web::dev::ServiceResponse) -> Option<String> {
        resp.response()
            .cookies()
            .find(|c| c.name() == SESSION_COOKIE && !c.value().is_empty())
            .map(|c| c.value().to_string())
    }

    #[actix_web::test]
    async fn sso_callback_missing_state_renders_error() {
        let dir = tempdir().unwrap();
        let data = test_state(dir.path());
        let app = app!(data);

        let req = actix_test::TestRequest::get()
            .uri("/callback?code=abc")
            .to_request();
        let resp = actix_test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(session_cookie_of(&resp).is_none());
        assert!(text_of(&body_of(resp).await).contains("SSO error: missing code or state"));
    }

    #[actix_web::test]
    async fn sso_callback_non_admin_gets_no_session() {
        let idp = stub_idp().await;
        let dir = tempdir().unwrap();
        let data = test_state_with_sso(dir.path(), stub_sso_config(&idp));
        data.user_manager
            .create_user("bob", "password123", None)
            .await
            .unwrap();
        let app = app!(data);

        let resp = sso_callback_for!(&app, data, "bob");
        assert!(session_cookie_of(&resp).is_none());
        assert!(text_of(&body_of(resp).await).contains("Admin access required"));
        // Nothing was bound for the rejected login.
        assert!(
            data.sso_manager
                .get_user_data("bob")
                .await
                .is_none_or(|d| d.provider_sub.is_none())
        );
    }

    #[actix_web::test]
    async fn sso_callback_admin_gets_session_cookie() {
        let idp = stub_idp().await;
        let dir = tempdir().unwrap();
        let data = test_state_with_sso(dir.path(), stub_sso_config(&idp));
        data.user_manager
            .create_user("admin1", "password123", Some(UserRole::Admin))
            .await
            .unwrap();
        let provider = data.sso_manager.status().provider_name;
        data.sso_manager
            .link_identity("admin1", &provider, "sub-admin1")
            .await
            .unwrap();
        let app = app!(data);

        let resp = sso_callback_for!(&app, data, "admin1");
        assert_eq!(resp.status(), StatusCode::OK);
        let token = session_cookie_of(&resp).expect("session cookie");
        assert_eq!(
            data.sessions.lookup(&token).await.unwrap().username,
            "admin1"
        );
        assert!(dashboard_ok!(&app, token));
    }

    #[actix_web::test]
    async fn sso_callback_unlinked_admin_refused() {
        let idp = stub_idp().await;
        let dir = tempdir().unwrap();
        let data = test_state_with_sso(dir.path(), stub_sso_config(&idp));
        data.user_manager
            .create_user("admin1", "password123", Some(UserRole::Admin))
            .await
            .unwrap();
        let app = app!(data);

        let resp = sso_callback_for!(&app, data, "admin1");
        assert!(session_cookie_of(&resp).is_none());
        assert!(text_of(&body_of(resp).await).contains("SSO error"));
        assert!(
            data.sso_manager
                .get_user_data("admin1")
                .await
                .is_none_or(|d| d.provider_sub.is_none())
        );
    }

    #[actix_web::test]
    async fn sso_callback_auto_binds_admin_when_enabled() {
        let idp = stub_idp().await;
        let dir = tempdir().unwrap();
        let data = test_state_full(dir.path(), stub_sso_config(&idp), true);
        data.user_manager
            .create_user("admin1", "password123", Some(UserRole::Admin))
            .await
            .unwrap();
        let app = app!(data);

        let resp = sso_callback_for!(&app, data, "admin1");
        assert!(session_cookie_of(&resp).is_some());
        assert_eq!(
            data.sso_manager
                .get_user_data("admin1")
                .await
                .unwrap()
                .provider_sub
                .as_deref(),
            Some("sub-admin1")
        );
    }

    #[actix_web::test]
    async fn sso_callback_change_required_redirects() {
        let idp = stub_idp().await;
        let dir = tempdir().unwrap();
        let data = test_state_with_sso(dir.path(), stub_sso_config(&idp));
        data.user_manager
            .create_user("admin1", "password123", Some(UserRole::Admin))
            .await
            .unwrap();
        data.user_manager
            .update_user("admin1", |u| u.password_change_required = true)
            .await
            .unwrap();
        let app = app!(data);

        let resp = sso_callback_for!(&app, data, "admin1");
        assert_eq!(resp.status(), StatusCode::FOUND);
        assert_eq!(
            location(&resp),
            "/account/password?username=admin1&reason=required"
        );
        assert!(session_cookie_of(&resp).is_none());
    }
}
