//! KISS Mail Server
//!
//! A dead-simple SMTP, IMAP, and POP3 mail server.
//! Just run it. That's it.

mod admin;
mod admin_api;
mod admin_rules;
mod admin_web;
mod antispam;
mod antivirus;
mod config;
mod crypto;
mod groups;
mod imap;
mod ldap;
mod mime;
mod pop3;
mod proto;
mod smtp;
mod spam_ai;
mod sso;
mod storage;
mod tls;
mod users;

use std::env;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use tokio::task::JoinSet;

use admin::{AdminHandler, format_result};
use admin_api::{AdminApiConfig, ApiState, RemoteClient};
use admin_web::{SessionStore, WebAdminConfig, WebServices};
use antispam::AntiSpam;
use antivirus::AntiVirus;
use config::{configured_ports, data_dir, default_ports, env_nonempty, mail_domain};
use groups::GroupManager;
use ldap::LdapClient;
use sso::SsoManager;
use storage::Storage;
use users::{BOOTSTRAP_ADMIN, PasswordChangeFailure, UserManager, UserRole};

/// File in the data directory that receives the bootstrap admin password.
const INITIAL_ADMIN_PASSWORD_FILE: &str = "initial-admin-password";

/// Length of the generated bootstrap admin password (base62 characters).
const INITIAL_ADMIN_PASSWORD_LEN: usize = 24;

/// Required mail server tasks: each yields its service name and outcome.
type MailServers = JoinSet<(&'static str, Result<(), String>)>;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();

    // Handle CLI commands, or start the server when no arguments are given
    let result = if args.len() > 1 {
        handle_cli(&args).await
    } else {
        run_server().await
    };

    if let Err(e) = result {
        cli_fail(e);
    }
    Ok(())
}

/// Log filter from `RUST_LOG`, falling back to `default`.
fn log_filter(default: &str) -> tracing_subscriber::EnvFilter {
    tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| default.into())
}

/// Server logging: `RUST_LOG`, defaulting to `kiss_mail=info`.
fn init_server_logging() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(log_filter("kiss_mail=info"))
        .try_init();
    config::log_config_warnings();
}

/// CLI logging: warnings and errors on stderr (honouring `RUST_LOG`) so
/// crypto/storage problems are visible without mixing into command output.
fn init_cli_logging() {
    let _ = tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(log_filter("kiss_mail=warn"))
        .try_init();
    config::log_config_warnings();
}

async fn run_server() -> Result<(), Box<dyn std::error::Error>> {
    init_server_logging();
    // Installed whatever the TLS mode and apart from shutdown_signal(), so a
    // HUP reloads certificates instead of terminating the process.
    tls::spawn_sighup_handler(None);

    // KISS_MAIL_DATA_DIR, then KISS_MAIL_DATA, then ./mail_data
    let data_dir = data_dir();
    let domain = mail_domain();

    // Resolve ports up front so a bad value fails fast with a clear message
    let (smtp_port, imap_port, pop3_port) = configured_ports()?;
    let api_config = AdminApiConfig::from_env()?;
    let web_config = WebAdminConfig::from_env()?;

    // Initialize LDAP (needed for storage auth)
    let ldap_client = Arc::new(LdapClient::from_env());

    // Initialize SSO early (needed for app password auth in storage)
    let sso_manager = Arc::new(SsoManager::from_env(data_dir.clone()));
    sso_manager
        .load()
        .await
        .map_err(|e| load_error("SSO data", &data_dir, "sso_data.json", e))?;

    // Initialize encryption manager (ProtonMail-style zero-knowledge encryption)
    let crypto_manager = load_crypto_manager(&data_dir)?;

    // Initialize user manager
    let user_manager = Arc::new(UserManager::new(domain.clone(), data_dir.clone()));
    user_manager
        .attach_crypto(Arc::clone(&crypto_manager))
        .await;
    // A missing users.json is a first run; any other error must abort so we
    // never treat unreadable data as "empty" and overwrite real accounts.
    user_manager
        .load()
        .await
        .map_err(|e| load_error("user accounts", &data_dir, "users.json", e))?;

    // Create storage with encryption support
    let storage = Arc::new(Storage::with_encryption(
        data_dir.clone(),
        Arc::clone(&user_manager),
        Arc::clone(&ldap_client),
        Arc::clone(&sso_manager),
        Arc::clone(&crypto_manager),
    ));
    storage
        .load()
        .await
        .map_err(|e| load_error("mailboxes", &data_dir, "mailboxes.json", e))?;

    // Auto-create admin on first run
    if let Some(created) = bootstrap_admin(&user_manager, &data_dir).await? {
        print_admin_created(&created, "First run detected! Created admin account:");
    }

    // Initialize groups
    let group_manager = Arc::new(GroupManager::new(data_dir.clone()));
    group_manager.attach_user_manager(Arc::clone(&user_manager));
    group_manager
        .load()
        .await
        .map_err(|e| load_error("groups", &data_dir, "groups.json", e))?;
    // Remove data left behind by users that no longer exist (e.g. a CLI
    // `del` while this server was running, which re-saved the old state).
    let purge = admin_rules::purge_orphans(
        &data_dir,
        &user_manager,
        &storage,
        &sso_manager,
        Some(&crypto_manager),
        &group_manager,
    )
    .await;
    if !purge.purged.is_empty() {
        tracing::info!(
            "Startup cleanup removed leftover data of {} deleted user(s)",
            purge.purged.len()
        );
    }
    for failure in &purge.failures {
        tracing::warn!("Startup cleanup: {}", failure);
    }

    // Test LDAP connection if enabled
    if ldap_client.is_enabled() {
        match ldap_client.test_connection().await {
            Ok(msg) => tracing::info!("LDAP: {}", msg),
            Err(e) => tracing::warn!("LDAP connection test failed: {}", e),
        }
    }

    // Log SSO status
    if sso_manager.is_enabled() {
        let status = sso_manager.status();
        tracing::info!("SSO: {} enabled", status.provider_name);
    }

    // Initialize spam detection (with AI)
    let antispam = Arc::new(AntiSpam::new(data_dir.clone()));
    if let Err(e) = antispam.load().await {
        tracing::warn!("Could not load spam classifier: {}", e);
    }

    let antivirus = Arc::new(AntiVirus::new());

    let smtp_server = smtp::SmtpServer::new(
        Arc::clone(&storage),
        Arc::clone(&group_manager),
        Arc::clone(&antispam),
        Arc::clone(&antivirus),
        domain.clone(),
    );
    let imap_server = imap::ImapServer::new(Arc::clone(&storage));
    let pop3_server = pop3::Pop3Server::new(Arc::clone(&storage));

    let smtp_addr = format!("0.0.0.0:{}", smtp_port);
    let imap_addr = format!("0.0.0.0:{}", imap_port);
    let pop3_addr = format!("0.0.0.0:{}", pop3_port);

    // Admin API configuration
    let api_port = api_config.port;
    let api_enabled = api_config.enabled;

    // Web admin configuration
    let web_port = web_config.port;
    let web_enabled = web_config.enabled;

    // Print startup info
    print_banner(
        &domain,
        smtp_port,
        imap_port,
        pop3_port,
        api_port,
        api_enabled,
        web_port,
        web_enabled,
        &user_manager,
        &group_manager,
        &ldap_client,
        &sso_manager,
        &antispam,
        &antivirus,
        &crypto_manager,
    )
    .await;

    // Create API state
    let api_state = ApiState {
        user_manager: Arc::clone(&user_manager),
        group_manager: Arc::clone(&group_manager),
        storage: Arc::clone(&storage),
        ldap_client: Arc::clone(&ldap_client),
        sso_manager: Arc::clone(&sso_manager),
        crypto_manager: Some(Arc::clone(&crypto_manager)),
        config: api_config,
        domain: domain.clone(),
        tokens: SessionStore::new(),
    };

    // SMTP/IMAP/POP3 are required (see `supervise`).
    let mut mail_servers: MailServers = JoinSet::new();
    mail_servers.spawn(async move {
        let r = smtp_server.run(&smtp_addr).await.map_err(|e| e.to_string());
        ("SMTP", r)
    });
    mail_servers.spawn(async move {
        let r = imap_server.run(&imap_addr).await.map_err(|e| e.to_string());
        ("IMAP", r)
    });
    mail_servers.spawn(async move {
        let r = pop3_server.run(&pop3_addr).await.map_err(|e| e.to_string());
        ("POP3", r)
    });

    let api_task = tokio::spawn(async move {
        match admin_api::run_api_server(api_state).await {
            Ok(()) => tracing::debug!("Admin API task finished"),
            Err(e) => tracing::error!("Admin API error (mail servers keep running): {}", e),
        }
    });

    // The web admin (actix-web) future is not Send, so it is driven on this task.
    let web_server = async {
        let services = WebServices {
            user_manager: Arc::clone(&user_manager),
            group_manager: Arc::clone(&group_manager),
            ldap_client: Arc::clone(&ldap_client),
            sso_manager: Arc::clone(&sso_manager),
            storage: Arc::clone(&storage),
            crypto_manager: Some(Arc::clone(&crypto_manager)),
        };
        match admin_web::run_web_server(services, domain.clone(), web_config).await {
            Ok(()) => tracing::debug!("Web admin task finished"),
            Err(e) => tracing::error!("Web admin error (mail servers keep running): {}", e),
        }
    };

    let outcome = supervise(mail_servers, web_server, shutdown_signal()).await;

    api_task.abort();

    // Persist debounced state so learned spam data and app-password
    // last_used timestamps are not lost on shutdown.
    if let Err(e) = antispam.flush().await {
        tracing::error!("Could not flush spam classifier data on shutdown: {}", e);
    }
    if let Err(e) = sso_manager.flush().await {
        tracing::error!("Could not flush SSO data on shutdown: {}", e);
    }

    outcome.map_err(Into::into)
}

/// Run until a required mail server stops or a shutdown signal arrives.
///
/// SMTP/IMAP/POP3 (`mail`) are required: if any of them stops or fails (e.g.
/// the port cannot be bound) this returns an error naming the service. The
/// `optional` future (admin web UI) finishing is logged and ignored, so the
/// mail servers keep running. `shutdown` completing returns `Ok(())`.
///
/// Remaining mail server tasks are aborted when `mail` is dropped on return.
async fn supervise(
    mut mail: MailServers,
    optional: impl Future<Output = ()>,
    shutdown: impl Future<Output = ()>,
) -> Result<(), String> {
    tokio::pin!(optional);
    tokio::pin!(shutdown);
    let mut optional_done = false;
    loop {
        tokio::select! {
            Some(joined) = mail.join_next() => {
                let msg = match joined {
                    Ok((name, Ok(()))) => format!("{} server stopped unexpectedly; shutting down", name),
                    Ok((name, Err(e))) => format!("{} server failed: {}; shutting down", name, e),
                    Err(e) => format!("Mail server task panicked: {}; shutting down", e),
                };
                tracing::error!("{}", msg);
                return Err(msg);
            }
            _ = &mut optional, if !optional_done => {
                optional_done = true;
                tracing::warn!("Optional admin server stopped; mail servers keep running");
            }
            _ = &mut shutdown => return Ok(()),
        }
    }
}

/// Completes on Ctrl+C (SIGINT) or, on Unix, SIGTERM.
async fn shutdown_signal() {
    let ctrl_c = async {
        match tokio::signal::ctrl_c().await {
            Ok(()) => tracing::info!("Received Ctrl+C, shutting down"),
            Err(e) => {
                // Keep running (SIGTERM still works) instead of shutting
                // down because the handler could not be installed.
                tracing::warn!("Could not listen for Ctrl+C: {}", e);
                std::future::pending::<()>().await
            }
        }
    };

    #[cfg(unix)]
    let terminate = async {
        use tokio::signal::unix::{SignalKind, signal};
        match signal(SignalKind::terminate()) {
            Ok(mut sigterm) => {
                sigterm.recv().await;
                tracing::info!("Received SIGTERM, shutting down");
            }
            Err(e) => {
                tracing::warn!("Could not listen for SIGTERM: {}", e);
                std::future::pending::<()>().await
            }
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {}
        _ = terminate => {}
    }
}

async fn handle_cli(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    // Parse global flags for remote mode
    let mut server: Option<String> = None;
    let mut api_key: Option<String> = None;
    let mut insecure = false;
    let mut remaining_args: Vec<String> = Vec::new();
    let mut skip_next = false;

    for (i, arg) in args.iter().enumerate().skip(1) {
        if skip_next {
            skip_next = false;
            continue;
        }
        if arg == "--server" || arg == "-s" {
            server = args.get(i + 1).cloned();
            skip_next = true;
        } else if let Some(value) = arg.strip_prefix("--server=") {
            server = Some(value.to_string());
        } else if arg == "--api-key" || arg == "-k" {
            api_key = args.get(i + 1).cloned();
            skip_next = true;
        } else if let Some(value) = arg.strip_prefix("--api-key=") {
            api_key = Some(value.to_string());
        } else if arg == "--insecure" {
            insecure = true;
        } else {
            remaining_args.push(arg.clone());
        }
    }

    // Fall back to env vars; empty values are the same as unset
    let server = server
        .filter(|s| !s.is_empty())
        .or_else(|| env_nonempty("KISS_MAIL_SERVER"));
    let api_key = api_key
        .filter(|k| !k.is_empty())
        .or_else(|| env_nonempty("KISS_MAIL_API_KEY"));

    let cmd = remaining_args.first().map(|s| s.as_str()).unwrap_or("");
    let cmd_args: Vec<String> = remaining_args.iter().skip(1).cloned().collect();

    // Commands that never need a remote server or API key
    match cmd {
        "help" | "--help" | "-h" => {
            print_help();
            return Ok(());
        }
        "version" | "--version" | "-v" => {
            println!("kiss-mail {}", env!("CARGO_PKG_VERSION"));
            return Ok(());
        }
        // Explicit server start (used by container images: `kiss-mail server`)
        "server" | "serve" | "run" => return run_server().await,
        _ => {}
    }

    init_cli_logging();

    // Remote mode
    if let Some(srv) = server {
        return handle_remote_cli(&srv, insecure, api_key, cmd, &cmd_args).await;
    }

    match cmd {
        // User management shortcuts
        "user" | "users" | "list" => run_admin("list", &cmd_args).await,
        "add" | "create" => run_admin("create", &cmd_args).await,
        "del" | "delete" | "rm" => run_delete(&cmd_args).await,
        "passwd" | "password" => {
            let cmd_args = with_stdin_password(&cmd_args).unwrap_or_else(|e| cli_fail(e));
            run_admin("passwd", &cmd_args).await
        }
        "change-password" => run_change_password(&cmd_args).await,
        "info" => run_admin("info", &cmd_args).await,
        "stats" | "status" => run_admin("stats", &[]).await,
        "purge-orphans" => run_purge_orphans(&cmd_args).await,
        // Group management
        "groups" | "group-list" => run_group_cmd("list", &cmd_args).await,
        "group-add" | "group-create" => run_group_cmd("create", &cmd_args).await,
        "group-del" | "group-delete" => run_group_cmd("delete", &cmd_args).await,
        "group-info" => run_group_cmd("info", &cmd_args).await,
        "group-members" => run_group_cmd("members", &cmd_args).await,
        "group-add-member" => run_group_cmd("add-member", &cmd_args).await,
        "group-rm-member" => run_group_cmd("rm-member", &cmd_args).await,
        // LDAP commands
        "ldap-test" => run_ldap_cmd("test", &cmd_args).await,
        "ldap-auth" => run_ldap_cmd("auth", &cmd_args).await,
        "ldap-search" => run_ldap_cmd("search", &cmd_args).await,
        "ldap-status" => run_ldap_cmd("status", &cmd_args).await,
        // SSO commands
        "sso-status" => run_sso_cmd("status", &cmd_args).await,
        "app-password" | "app-pass" => run_sso_cmd("generate", &cmd_args).await,
        "app-passwords" | "app-pass-list" => run_sso_cmd("list", &cmd_args).await,
        "app-pass-revoke" => run_sso_cmd("revoke", &cmd_args).await,
        "sso-link" => run_sso_cmd("link", &cmd_args).await,
        "sso-unbind" => run_sso_cmd("unbind", &cmd_args).await,
        _ => unknown_command(cmd, ""),
    }
}

async fn handle_remote_cli(
    server: &str,
    insecure: bool,
    api_key: Option<String>,
    cmd: &str,
    args: &[String],
) -> Result<(), Box<dyn std::error::Error>> {
    // Changing your own password needs no API key: the current password is
    // the credential.
    if cmd == "change-password" {
        let parsed = parse_change_password_args(args).unwrap_or_else(|e| usage_fail(e));
        let (current, new) =
            read_change_password_input(parsed.stdin).unwrap_or_else(|e| cli_fail(e));
        RemoteClient::new(server, insecure)
            .unwrap_or_else(|e| cli_fail(e))
            .change_password(&parsed.username, &current, &new)
            .await
            .unwrap_or_else(|e| cli_fail(e));
        println!("✓ Password changed for user '{}'", parsed.username);
        return Ok(());
    }

    let Some(key) = api_key else {
        eprintln!("No API key provided. Use --api-key or set KISS_MAIL_API_KEY");
        eprintln!("You can also set KISS_MAIL_SERVER for the server address.");
        std::process::exit(1);
    };
    let client = RemoteClient::new(server, insecure)
        .unwrap_or_else(|e| cli_fail(e))
        .with_api_key(key);

    match cmd {
        "status" | "stats" | "ldap-status" | "ldap-test" => remote_status_cmd(&client, cmd).await,
        "user" | "users" | "list" | "add" | "create" | "del" | "delete" | "rm" | "info"
        | "passwd" | "password" => remote_user_cmd(&client, cmd, args).await,
        "purge-orphans" | "sso-link" | "sso-unbind" => cli_fail(format!(
            "'{}' is a local command; run it on the server host",
            cmd
        )),
        "groups" | "group-list" | "group-add" | "group-create" | "group-del" | "group-delete"
        | "group-add-member" | "group-rm-member" | "group-info" | "group-members" => {
            remote_group_cmd(&client, cmd, args).await
        }
        "sso-status" | "app-password" | "app-pass" | "app-passwords" | "app-pass-list"
        | "app-pass-revoke" => remote_sso_cmd(&client, cmd, args).await,
        _ => unknown_command(cmd, " for remote mode"),
    }
}

/// Remote server status and LDAP commands.
async fn remote_status_cmd(
    client: &RemoteClient,
    cmd: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    match cmd {
        "status" | "stats" => {
            let status = client.status().await.unwrap_or_else(|e| cli_fail(e));
            println!("Server Status:");
            println!("  Version:     {}", status.version);
            println!("  Domain:      {}", status.domain);
            println!("  Users:       {}", status.users);
            println!("  Groups:      {}", status.groups);
            println!("  LDAP:        {}", enabled_label(status.ldap_enabled));
            if let Some(provider) = status.sso_provider {
                println!("  SSO:         {} enabled", provider);
            } else {
                println!("  SSO:         {}", enabled_label(status.sso_enabled));
            }
        }
        "ldap-status" => {
            let status = client.status().await.unwrap_or_else(|e| cli_fail(e));
            println!("LDAP Status:");
            println!(
                "  Enabled:   {}",
                if status.ldap_enabled { "Yes" } else { "No" }
            );
        }
        "ldap-test" => {
            let msg = client.ldap_test().await.unwrap_or_else(|e| cli_fail(e));
            println!("✓ LDAP: {}", msg);
        }
        _ => unknown_command(cmd, " for remote mode"),
    }
    Ok(())
}

/// Remote user management commands.
async fn remote_user_cmd(
    client: &RemoteClient,
    cmd: &str,
    args: &[String],
) -> Result<(), Box<dyn std::error::Error>> {
    match cmd {
        "user" | "users" | "list" => {
            let users = client.list_users().await.unwrap_or_else(|e| cli_fail(e));
            if users.is_empty() {
                println!("No users found.");
            } else {
                println!("Users:");
                for u in users {
                    println!("  {} ({}) - {}", u.username, u.role, u.status);
                }
            }
        }
        "add" | "create" => {
            let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
            let (username, password, role) =
                admin::parse_create_args(&arg_refs).unwrap_or_else(|e| {
                    eprintln!("Error: {}", e);
                    usage_fail("kiss-mail --server <srv> add <user> <pass> [--role <role>]")
                });
            let role = role.map(|r| r.to_string());
            let user = client
                .create_user(username, password, role.as_deref())
                .await
                .unwrap_or_else(|e| cli_fail(e));
            println!("✓ Created user '{}'", user.username);
        }
        "del" | "delete" | "rm" => {
            let Some(username) = args.first() else {
                usage_fail("kiss-mail --server <srv> del <user>")
            };
            client
                .delete_user(username)
                .await
                .unwrap_or_else(|e| cli_fail(e));
            println!("✓ Deleted user '{}'", username);
        }
        "info" => {
            let Some(username) = args.first() else {
                usage_fail("kiss-mail --server <srv> info <user>")
            };
            let user = client
                .get_user(username)
                .await
                .unwrap_or_else(|e| cli_fail(e));
            println!("User: {}", user.username);
            println!("  Role:         {}", user.role);
            println!("  Status:       {}", user.status);
            if let Some(name) = user.display_name {
                println!("  Display name: {}", name);
            }
            println!("  Created:      {}", user.created_at);
            if let Some(login) = user.last_login {
                println!("  Last login:   {}", login);
            }
            println!("  Login count:  {}", user.login_count);
        }
        "passwd" | "password" => {
            let args = with_stdin_password(args).unwrap_or_else(|e| cli_fail(e));
            if args.iter().any(|a| a == "--require-change") {
                cli_fail(
                    "--require-change is only supported locally (the admin API cannot set it)",
                );
            }
            if args.len() != 2 {
                usage_fail("kiss-mail --server <srv> passwd <user> (<new-password> | --stdin)");
            }
            let user = client
                .set_password(&args[0], &args[1])
                .await
                .unwrap_or_else(|e| cli_fail(e));
            println!("✓ Password reset for user '{}'", user.username);
        }
        _ => unknown_command(cmd, " for remote mode"),
    }
    Ok(())
}

/// Remote group management commands.
async fn remote_group_cmd(
    client: &RemoteClient,
    cmd: &str,
    args: &[String],
) -> Result<(), Box<dyn std::error::Error>> {
    match cmd {
        "groups" | "group-list" => {
            let groups = client.list_groups().await.unwrap_or_else(|e| cli_fail(e));
            if groups.is_empty() {
                println!("No groups found.");
            } else {
                println!("Groups:");
                for g in groups {
                    println!("  {} ({}) - {} members", g.name, g.email, g.members.len());
                }
            }
        }
        "group-add" | "group-create" => {
            let Some(name) = args.first() else {
                usage_fail("kiss-mail --server <srv> group-add <name> [email]")
            };
            let email = args.get(1).unwrap_or(name);
            let group = client
                .create_group(name, email)
                .await
                .unwrap_or_else(|e| cli_fail(e));
            println!(
                "✓ Created group '{}' with email '{}'",
                group.name, group.email
            );
        }
        "group-del" | "group-delete" => {
            let Some(name) = args.first() else {
                usage_fail("kiss-mail --server <srv> group-del <name>")
            };
            client
                .delete_group(name)
                .await
                .unwrap_or_else(|e| cli_fail(e));
            println!("✓ Deleted group '{}'", name);
        }
        "group-add-member" => {
            let [group, user, ..] = args else {
                usage_fail("kiss-mail --server <srv> group-add-member <group> <user>")
            };
            client
                .add_group_member(group, user)
                .await
                .unwrap_or_else(|e| cli_fail(e));
            println!("✓ Added '{}' to group '{}'", user, group);
        }
        "group-rm-member" => {
            let [group, user, ..] = args else {
                usage_fail("kiss-mail --server <srv> group-rm-member <group> <user>")
            };
            client
                .remove_group_member(group, user)
                .await
                .unwrap_or_else(|e| cli_fail(e));
            println!("✓ Removed '{}' from group '{}'", user, group);
        }
        "group-info" | "group-members" => {
            let Some(name) = args.first() else {
                usage_fail(format!("kiss-mail --server <srv> {} <name>", cmd))
            };
            let g = client.get_group(name).await.unwrap_or_else(|e| cli_fail(e));
            println!("Group: {}", g.name);
            println!("  Email:       {}", g.email);
            if let Some(desc) = g.description {
                println!("  Description: {}", desc);
            }
            println!("  Owner:       {}", g.owner);
            println!("  Active:      {}", g.active);
            println!("  Members ({}):", g.members.len());
            for m in &g.members {
                let role = if *m == g.owner {
                    " (owner)"
                } else if g.managers.contains(m) {
                    " (manager)"
                } else {
                    ""
                };
                println!("    - {}{}", m, role);
            }
        }
        _ => unknown_command(cmd, " for remote mode"),
    }
    Ok(())
}

/// Remote SSO and app-password commands.
async fn remote_sso_cmd(
    client: &RemoteClient,
    cmd: &str,
    args: &[String],
) -> Result<(), Box<dyn std::error::Error>> {
    match cmd {
        "sso-status" => {
            let status = client.sso_status().await.unwrap_or_else(|e| cli_fail(e));
            println!("SSO Status:");
            println!(
                "  Enabled:        {}",
                if status.enabled { "Yes" } else { "No" }
            );
            if status.enabled {
                println!("  Provider:       {}", status.provider_name);
                println!(
                    "  App Passwords:  {}",
                    if status.allow_app_passwords {
                        "Allowed"
                    } else {
                        "Disabled"
                    }
                );
            }
        }
        "app-password" | "app-pass" => {
            let Some(username) = args.first() else {
                usage_fail("kiss-mail --server <srv> app-password <user> [label]")
            };
            let label = args.get(1).map(|s| s.as_str());
            let created = client
                .create_app_password(username, label, None)
                .await
                .unwrap_or_else(|e| cli_fail(e));
            println!("✓ Generated app password for '{}'", username);
            println!();
            println!("  Label:    {}", created.label);
            println!("  Password: {}", created.password);
            if let Some(expires) = created.expires_at {
                println!("  Expires:  {}", expires);
            }
            println!();
            println!("  Use this password in your email client instead of your SSO password.");
            println!("  Store it securely - it won't be shown again!");
        }
        "app-passwords" | "app-pass-list" => {
            let Some(username) = args.first() else {
                usage_fail("kiss-mail --server <srv> app-passwords <user>")
            };
            let passwords = client
                .list_app_passwords(username)
                .await
                .unwrap_or_else(|e| cli_fail(e));
            if passwords.is_empty() {
                println!("No app passwords for '{}'", username);
            } else {
                println!("App passwords for '{}':", username);
                for pw in passwords {
                    print_app_password(
                        &pw.id,
                        &pw.label,
                        pw.created_at,
                        pw.last_used,
                        pw.expires_at,
                    );
                }
            }
        }
        "app-pass-revoke" => {
            let [username, prefix, ..] = args else {
                usage_fail("kiss-mail --server <srv> app-pass-revoke <user> <id-or-prefix>")
            };
            let existing = client
                .list_app_passwords(username)
                .await
                .unwrap_or_else(|e| cli_fail(e));
            let id = resolve_id_prefix(existing.iter().map(|p| p.id.as_str()), prefix)
                .unwrap_or_else(|e| cli_fail(e));
            client
                .revoke_app_password(username, &id)
                .await
                .unwrap_or_else(|e| cli_fail(e));
            println!("✓ Revoked app password {}", id);
        }
        _ => unknown_command(cmd, " for remote mode"),
    }
    Ok(())
}

async fn run_admin(cmd: &str, args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let data_dir = data_dir();
    tokio::fs::create_dir_all(&data_dir).await.map_err(|e| {
        format!(
            "Could not create data directory {}: {}",
            data_dir.display(),
            e
        )
    })?;

    let crypto_manager = load_crypto_manager(&data_dir)?;
    let user_manager = Arc::new(UserManager::new(mail_domain(), data_dir.clone()));
    user_manager
        .attach_crypto(Arc::clone(&crypto_manager))
        .await;

    // A missing users.json is fine; anything else aborts before we write.
    user_manager
        .load()
        .await
        .map_err(|e| load_error("user accounts", &data_dir, "users.json", e))?;

    // Bootstrap admin if needed (the CLI acts as "admin")
    if let Some(created) = bootstrap_admin(&user_manager, &data_dir).await? {
        print_admin_created(&created, "No admin account found. Created admin account:");
    }

    let storage = Arc::new(Storage::new(data_dir.clone(), Arc::clone(&user_manager)));
    storage
        .load()
        .await
        .map_err(|e| load_error("mailboxes", &data_dir, "mailboxes.json", e))?;

    let handler = AdminHandler::new(Arc::clone(&storage));
    let cmd_args: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    let result = handler.execute(cmd, &cmd_args, BOOTSTRAP_ADMIN).await;

    if let admin::AdminResult::Error(_) = result {
        eprintln!("{}", format_result(&result));
        std::process::exit(1);
    }
    println!("{}", format_result(&result));

    // Admin commands only touch user accounts, which UserManager persists
    // itself. Never rewrite mailboxes.json from the CLI: a running server may
    // have delivered mail since we loaded it.
    if !admin::is_read_only_command(cmd) {
        print_local_write_notice();
    }

    Ok(())
}

/// Everything a local CLI command needs to remove a user's data, loaded from
/// the data directory (see [`load_local_services`]).
struct LocalServices {
    data_dir: PathBuf,
    user_manager: Arc<UserManager>,
    storage: Arc<Storage>,
    sso_manager: SsoManager,
    crypto_manager: Arc<crypto::CryptoManager>,
    group_manager: GroupManager,
}

/// Load users (with encryption keys attached), mailboxes, SSO data and
/// groups (with the user manager attached). Aborts if any existing file
/// cannot be read, including `keys.json`, so nothing is overwritten.
async fn load_local_services() -> Result<LocalServices, Box<dyn std::error::Error>> {
    let data_dir = data_dir();
    tokio::fs::create_dir_all(&data_dir).await.map_err(|e| {
        format!(
            "Could not create data directory {}: {}",
            data_dir.display(),
            e
        )
    })?;

    let crypto_manager = load_crypto_manager(&data_dir)?;
    let user_manager = Arc::new(UserManager::new(mail_domain(), data_dir.clone()));
    user_manager
        .attach_crypto(Arc::clone(&crypto_manager))
        .await;
    user_manager
        .load()
        .await
        .map_err(|e| load_error("user accounts", &data_dir, "users.json", e))?;

    let storage = Arc::new(Storage::new(data_dir.clone(), Arc::clone(&user_manager)));
    storage
        .load()
        .await
        .map_err(|e| load_error("mailboxes", &data_dir, "mailboxes.json", e))?;

    let sso_manager = SsoManager::from_env(data_dir.clone());
    sso_manager
        .load()
        .await
        .map_err(|e| load_error("SSO data", &data_dir, "sso_data.json", e))?;

    let group_manager = GroupManager::new(data_dir.clone());
    group_manager.attach_user_manager(Arc::clone(&user_manager));
    group_manager
        .load()
        .await
        .map_err(|e| load_error("groups", &data_dir, "groups.json", e))?;

    Ok(LocalServices {
        data_dir,
        user_manager,
        storage,
        sso_manager,
        crypto_manager,
        group_manager,
    })
}

/// Print cleanup failures and exit with status 2 (the main action itself
/// succeeded, but data was left behind).
fn exit_on_cleanup_failures(failures: &[String], context: &str) {
    if failures.is_empty() {
        return;
    }
    eprintln!("{}:", context);
    for failure in failures {
        eprintln!("  - {}", failure);
    }
    eprintln!("Run 'kiss-mail purge-orphans' (or restart the server) to retry the cleanup.");
    std::process::exit(2);
}

/// `del <user>`: delete the account, then its mailbox, SSO data (app
/// passwords, identity binding), encryption keys and group memberships.
///
/// The mailbox is removed by rewriting mailboxes.json from the state loaded
/// here. A server running against the same data directory keeps its own copy
/// in memory and will write the mailbox back on its next save, so it must be
/// restarted (it purges leftovers of deleted users at startup); prefer
/// `--server/--api-key` while a server runs.
async fn run_delete(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let [username] = args else {
        usage_fail("kiss-mail del <user>")
    };
    let services = load_local_services().await?;
    if let Some(created) = bootstrap_admin(&services.user_manager, &services.data_dir).await? {
        print_admin_created(&created, "No admin account found. Created admin account:");
    }

    let handler = AdminHandler::new(Arc::clone(&services.storage));
    let result = handler
        .execute("delete", &[username.as_str()], BOOTSTRAP_ADMIN)
        .await;
    if let admin::AdminResult::Error(_) = result {
        cli_fail(format_result(&result).trim_start_matches("Error: "));
    }
    println!("{}", format_result(&result));

    let failures = admin_rules::cleanup_deleted_user(
        &services.user_manager,
        &services.storage,
        &services.sso_manager,
        Some(&services.crypto_manager),
        &services.group_manager,
        username,
    )
    .await;
    eprintln!(
        "Note: If a kiss-mail server is running against this data directory, restart it now: \
         it still holds the deleted user's mailbox in memory and would write it back."
    );
    exit_on_cleanup_failures(
        &failures,
        &format!("User '{}' was deleted, but cleanup failed", username),
    );
    Ok(())
}

/// `purge-orphans`: remove data of users that no longer exist (the same
/// cleanup the server runs at startup).
async fn run_purge_orphans(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    if !args.is_empty() {
        usage_fail("kiss-mail purge-orphans");
    }
    let services = load_local_services().await?;
    let report = admin_rules::purge_orphans(
        &services.data_dir,
        &services.user_manager,
        &services.storage,
        &services.sso_manager,
        Some(&services.crypto_manager),
        &services.group_manager,
    )
    .await;
    if report.purged.is_empty() {
        println!("No leftover data of deleted users found.");
    } else {
        println!(
            "Removed leftover data of {} deleted user(s): {}",
            report.purged.len(),
            report.purged.join(", ")
        );
        print_local_write_notice();
    }
    exit_on_cleanup_failures(&report.failures, "Some cleanup steps failed");
    Ok(())
}

/// Load the user accounts and the groups (with the user manager attached, so
/// unknown usernames are rejected) for local CLI commands.
async fn load_group_manager(data_dir: &Path) -> Result<GroupManager, Box<dyn std::error::Error>> {
    let user_manager = Arc::new(UserManager::new(mail_domain(), data_dir.to_path_buf()));
    user_manager
        .load()
        .await
        .map_err(|e| load_error("user accounts", data_dir, "users.json", e))?;
    let group_manager = GroupManager::new(data_dir.to_path_buf());
    group_manager.attach_user_manager(user_manager);
    group_manager
        .load()
        .await
        .map_err(|e| load_error("groups", data_dir, "groups.json", e))?;
    Ok(group_manager)
}

/// Parsed arguments of `change-password <user> [--stdin]`.
#[derive(Debug, PartialEq, Eq)]
struct ChangePasswordArgs {
    username: String,
    /// Read the current and new password from stdin (one per line) instead
    /// of prompting.
    stdin: bool,
}

const CHANGE_PASSWORD_USAGE: &str = "kiss-mail [--server <srv>] change-password <user> [--stdin]";

/// Parse `change-password` arguments (pure, for testing).
fn parse_change_password_args(args: &[String]) -> Result<ChangePasswordArgs, String> {
    let mut username: Option<String> = None;
    let mut stdin = false;
    for arg in args {
        if arg == "--stdin" {
            stdin = true;
        } else if arg.starts_with("--") || username.is_some() {
            return Err(CHANGE_PASSWORD_USAGE.to_string());
        } else {
            username = Some(arg.clone());
        }
    }
    match username.filter(|u| !u.trim().is_empty()) {
        Some(username) => Ok(ChangePasswordArgs { username, stdin }),
        None => Err(CHANGE_PASSWORD_USAGE.to_string()),
    }
}

/// Split `--stdin` input into (current password, new password): line 1 and
/// line 2, each without its line ending.
fn parse_password_lines(input: &str) -> Result<(String, String), String> {
    let mut lines = input.lines();
    let current = lines.next().unwrap_or("");
    let new = lines.next().unwrap_or("");
    if current.is_empty() || new.is_empty() {
        return Err(
            "Expected the current password on line 1 and the new password on line 2 of stdin"
                .to_string(),
        );
    }
    Ok((current.to_string(), new.to_string()))
}

/// Turns terminal echo off on stdin while alive and restores the previous
/// terminal settings when dropped.
#[cfg(unix)]
struct EchoOff {
    original: libc::termios,
}

#[cfg(unix)]
impl EchoOff {
    /// Disable echo if stdin is a terminal; `None` otherwise (or on error).
    fn new() -> Option<Self> {
        use std::io::IsTerminal;
        if !std::io::stdin().is_terminal() {
            return None;
        }
        let mut original = std::mem::MaybeUninit::<libc::termios>::uninit();
        // SAFETY: tcgetattr only writes a termios struct through the valid
        // pointer; it is read only after success.
        if unsafe { libc::tcgetattr(libc::STDIN_FILENO, original.as_mut_ptr()) } != 0 {
            return None;
        }
        // SAFETY: tcgetattr succeeded, so the struct is initialised.
        let original = unsafe { original.assume_init() };
        let mut silent = original;
        silent.c_lflag &= !libc::ECHO;
        // Still echo the newline so the next prompt starts on its own line.
        silent.c_lflag |= libc::ECHONL;
        // SAFETY: valid fd and a fully initialised termios struct.
        if unsafe { libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &silent) } != 0 {
            return None;
        }
        Some(Self { original })
    }
}

#[cfg(unix)]
impl Drop for EchoOff {
    fn drop(&mut self) {
        // SAFETY: restores the settings read in `new` on the same fd.
        unsafe {
            libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &self.original);
        }
    }
}

/// Read a password from stdin after printing `prompt` on stderr. When stdin
/// is a terminal the input is not echoed.
fn prompt_password(prompt: &str) -> Result<String, String> {
    use std::io::Write;
    eprint!("{}", prompt);
    let _ = std::io::stderr().flush();
    #[cfg(unix)]
    let _echo_off = EchoOff::new();
    let mut line = String::new();
    std::io::stdin()
        .read_line(&mut line)
        .map_err(|e| format!("Could not read from stdin: {}", e))?;
    Ok(line.trim_end_matches(['\r', '\n']).to_string())
}

/// Get (current, new) passwords from stdin lines or interactive prompts.
fn read_change_password_input(from_stdin: bool) -> Result<(String, String), String> {
    if from_stdin {
        let mut input = String::new();
        std::io::Read::read_to_string(&mut std::io::stdin(), &mut input)
            .map_err(|e| format!("Could not read passwords from stdin: {}", e))?;
        return parse_password_lines(&input);
    }
    let current = prompt_password("Current password: ")?;
    let new = prompt_password("New password: ")?;
    let confirm = prompt_password("Confirm new password: ")?;
    if new != confirm {
        return Err("The new passwords do not match".to_string());
    }
    if current.is_empty() || new.is_empty() {
        return Err("Passwords must not be empty".to_string());
    }
    Ok((current, new))
}

/// `change-password <user> [--stdin]` against the local data directory.
async fn run_change_password(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let parsed = parse_change_password_args(args).unwrap_or_else(|e| usage_fail(e));
    let (current, new) = read_change_password_input(parsed.stdin).unwrap_or_else(|e| cli_fail(e));
    change_password_local(&data_dir(), &parsed.username, &current, &new)
        .await
        .unwrap_or_else(|e| cli_fail(e));
    println!("✓ Password changed for user '{}'", parsed.username);
    print_local_write_notice();
    Ok(())
}

/// Change `username`'s password in `data_dir`, proving the current one, and
/// re-wrap their encryption keys. Errors are user-facing messages from
/// [`PasswordChangeFailure`], so they do not reveal whether the account
/// exists (load failures of the data files are reported as such).
async fn change_password_local(
    data_dir: &Path,
    username: &str,
    current: &str,
    new: &str,
) -> Result<(), String> {
    let crypto_manager = load_crypto_manager(data_dir)?;
    let user_manager = UserManager::new(mail_domain(), data_dir.to_path_buf());
    user_manager.attach_crypto(crypto_manager).await;
    user_manager
        .load()
        .await
        .map_err(|e| load_error("user accounts", data_dir, "users.json", e).to_string())?;
    user_manager
        .change_password(username, current, new)
        .await
        .map_err(|e| PasswordChangeFailure::from(e).user_message())
}

async fn run_group_cmd(cmd: &str, args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let data_dir = data_dir();
    let _ = tokio::fs::create_dir_all(&data_dir).await;
    let domain = mail_domain();

    let group_manager = load_group_manager(&data_dir).await?;

    match cmd {
        "list" => {
            let groups = group_manager.list().await;
            if groups.is_empty() {
                println!("No groups found.");
            } else {
                println!("Groups:");
                for g in groups {
                    println!("  {} ({}) - {} members", g.name, g.email, g.members.len());
                }
            }
        }
        "create" => {
            let Some(name) = args.first() else {
                usage_fail("kiss-mail group-add <name> [email]")
            };
            // Default email based on name and domain
            let email = match args.get(1).filter(|e| !e.is_empty()) {
                Some(e) => e.clone(),
                None => format!("{}@{}", name, domain),
            };

            let g = group_manager
                .create(name, &email, BOOTSTRAP_ADMIN)
                .await
                .unwrap_or_else(|e| cli_fail(e));
            println!("Created group '{}' with email '{}'", g.name, g.email);
            print_local_write_notice();
        }
        "delete" => {
            let Some(name) = args.first() else {
                usage_fail("kiss-mail group-del <name>")
            };
            group_manager
                .delete(name)
                .await
                .unwrap_or_else(|e| cli_fail(e));
            println!("Deleted group '{}'", name);
            print_local_write_notice();
        }
        "info" | "members" => {
            let Some(name) = args.first() else {
                usage_fail("kiss-mail group-info <name>")
            };
            let Some(g) = group_manager.get(name).await else {
                cli_fail(format!("Group '{}' not found", name))
            };
            println!("Group: {}", g.name);
            println!("  Email:       {}", g.email);
            println!("  Display:     {}", g.display_name);
            println!("  Owner:       {}", g.owner);
            println!("  Visibility:  {:?}", g.visibility);
            println!("  Active:      {}", g.active);
            println!("  Members ({}):", g.members.len());
            for m in &g.members {
                let role = if g.is_owner(m) {
                    " (owner)"
                } else if g.is_manager(m) {
                    " (manager)"
                } else {
                    ""
                };
                println!("    - {}{}", m, role);
            }
        }
        "add-member" => {
            let [group, user, ..] = args else {
                usage_fail("kiss-mail group-add-member <group> <user>")
            };
            group_manager
                .add_member(group, user)
                .await
                .unwrap_or_else(|e| cli_fail(e));
            println!("Added '{}' to group '{}'", user, group);
            print_local_write_notice();
        }
        "rm-member" => {
            let [group, user, ..] = args else {
                usage_fail("kiss-mail group-rm-member <group> <user>")
            };
            group_manager
                .remove_member(group, user)
                .await
                .unwrap_or_else(|e| cli_fail(e));
            println!("Removed '{}' from group '{}'", user, group);
            print_local_write_notice();
        }
        _ => unknown_command(cmd, ""),
    }

    Ok(())
}

async fn run_ldap_cmd(cmd: &str, args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let ldap_client = LdapClient::from_env();

    if !ldap_client.is_enabled() {
        println!("LDAP is not configured.");
        println!();
        println!("To enable LDAP, set these environment variables:");
        println!("  LDAP_URL=ldap://your-ldap-server:389");
        println!("  LDAP_BASE_DN=dc=example,dc=com");
        println!("  LDAP_BIND_DN=cn=admin,dc=example,dc=com  (optional)");
        println!("  LDAP_BIND_PASSWORD=secret                (optional)");
        println!();
        println!("See 'kiss-mail help' for all LDAP options.");
        return Ok(());
    }

    match cmd {
        "status" => {
            let status = ldap_client.status();
            println!("LDAP Status:");
            println!("  Enabled:  Yes");
            println!("  URL:      {}", status.url);
            println!("  Base DN:  {}", status.base_dn);
            println!(
                "  TLS:      {}",
                if status.use_tls {
                    "Yes"
                } else if status.use_starttls {
                    "StartTLS"
                } else {
                    "No"
                }
            );
        }
        "test" => {
            println!("Testing LDAP connection...");
            let status = ldap_client.status();
            println!("  URL:      {}", status.url);
            println!("  Base DN:  {}", status.base_dn);
            println!(
                "  TLS:      {}",
                if status.use_tls {
                    "Yes"
                } else if status.use_starttls {
                    "StartTLS"
                } else {
                    "No"
                }
            );
            println!();

            match ldap_client.test_connection().await {
                Ok(msg) => {
                    println!("✓ {}", msg);
                }
                Err(e) => {
                    eprintln!("✗ Connection failed: {}", e);
                    std::process::exit(1);
                }
            }
        }
        "auth" => {
            let [username, password, ..] = args else {
                usage_fail("kiss-mail ldap-auth <username> <password>")
            };

            println!("Authenticating {} via LDAP...", username);
            match ldap_client.authenticate(username, password).await {
                ldap::LdapAuthResult::Success(user) => {
                    println!("✓ Authentication successful!");
                    println!("  DN:      {}", user.dn);
                    println!("  Email:   {}", user.email.as_deref().unwrap_or("(none)"));
                    println!(
                        "  Name:    {}",
                        user.display_name.as_deref().unwrap_or("(none)")
                    );
                }
                ldap::LdapAuthResult::InvalidCredentials => {
                    eprintln!("✗ Invalid credentials");
                    std::process::exit(1);
                }
                ldap::LdapAuthResult::UserNotFound => {
                    eprintln!("✗ User not found in LDAP");
                    std::process::exit(1);
                }
                ldap::LdapAuthResult::Error(e) => {
                    eprintln!("✗ LDAP error: {}", e);
                    std::process::exit(1);
                }
                ldap::LdapAuthResult::NotEnabled => {
                    eprintln!("LDAP is not enabled");
                    std::process::exit(1);
                }
            }
        }
        "search" => {
            let Some(username) = args.first() else {
                usage_fail("kiss-mail ldap-search <username>")
            };

            println!("Searching for {} in LDAP...", username);
            match ldap_client.get_user(username).await {
                Ok(Some(user)) => {
                    println!("✓ Found user:");
                    println!("  DN:       {}", user.dn);
                    println!("  Username: {}", user.username);
                    println!("  Email:    {}", user.email.as_deref().unwrap_or("(none)"));
                    println!(
                        "  Name:     {}",
                        user.display_name.as_deref().unwrap_or("(none)")
                    );
                }
                Ok(None) => {
                    println!("User '{}' not found in LDAP", username);
                }
                Err(e) => {
                    eprintln!("✗ Search failed: {}", e);
                    std::process::exit(1);
                }
            }
        }
        _ => unknown_command(cmd, ""),
    }

    Ok(())
}

async fn run_sso_cmd(cmd: &str, args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let data_dir = data_dir();
    let _ = tokio::fs::create_dir_all(&data_dir).await;

    let sso_manager = SsoManager::from_env(data_dir.clone());
    sso_manager
        .load()
        .await
        .map_err(|e| load_error("SSO data", &data_dir, "sso_data.json", e))?;

    match cmd {
        "status" => {
            let status = sso_manager.status();
            println!("SSO Status:");
            println!(
                "  Enabled:        {}",
                if status.enabled { "Yes" } else { "No" }
            );
            if status.enabled {
                println!("  Provider:       {}", status.provider_name);
                println!(
                    "  App Passwords:  {}",
                    if status.allow_app_passwords {
                        "Allowed"
                    } else {
                        "Disabled"
                    }
                );
            } else {
                println!();
                println!("To enable SSO, set provider environment variables:");
                println!();
                println!("  1Password:");
                println!("     ONEPASSWORD_CLIENT_ID=<client_id>");
                println!("     ONEPASSWORD_CLIENT_SECRET=<secret>");
                println!();
                println!("  Google:");
                println!("     GOOGLE_CLIENT_ID=<client_id>");
                println!("     GOOGLE_CLIENT_SECRET=<secret>");
                println!();
                println!("  Microsoft:");
                println!("     MICROSOFT_CLIENT_ID=<client_id>");
                println!("     MICROSOFT_CLIENT_SECRET=<secret>");
                println!("     MICROSOFT_TENANT_ID=<tenant_id>");
                println!();
                println!("  Generic OIDC:");
                println!("     SSO_CLIENT_ID=<client_id>");
                println!("     SSO_CLIENT_SECRET=<secret>");
                println!("     SSO_AUTH_URL=<auth_endpoint>");
                println!("     SSO_TOKEN_URL=<token_endpoint>");
            }
        }
        "generate" => {
            let Some(username) = args.first() else {
                usage_fail("kiss-mail app-password <username> [label]")
            };
            let label = args.get(1).map(|s| s.as_str()).unwrap_or("Mail Client");

            let password = sso_manager
                .generate_app_password(username, label, None)
                .await
                .unwrap_or_else(|e| cli_fail(format!("Failed to generate app password: {}", e)));
            println!("✓ Generated app password for '{}'", username);
            println!();
            println!("  Label:    {}", label);
            println!("  Password: {}", password);
            println!();
            println!("  Use this password in your email client instead of your SSO password.");
            println!("  Store it securely - it won't be shown again!");
            print_local_write_notice();
        }
        "list" => {
            let Some(username) = args.first() else {
                usage_fail("kiss-mail app-passwords <username>")
            };
            let passwords = sso_manager.list_app_passwords(username).await;

            if passwords.is_empty() {
                println!("No app passwords for '{}'", username);
            } else {
                println!("App passwords for '{}':", username);
                for pw in passwords {
                    print_app_password(
                        &pw.id,
                        &pw.label,
                        pw.created_at,
                        pw.last_used,
                        pw.expires_at,
                    );
                }
            }
        }
        "revoke" => {
            let [username, prefix, ..] = args else {
                usage_fail("kiss-mail app-pass-revoke <username> <id-or-prefix>")
            };
            let existing = sso_manager.list_app_passwords(username).await;
            let password_id = resolve_id_prefix(existing.iter().map(|p| p.id.as_str()), prefix)
                .unwrap_or_else(|e| cli_fail(e));

            match sso_manager
                .revoke_app_password(username, &password_id)
                .await
            {
                Ok(true) => {
                    println!("✓ Revoked app password");
                    print_local_write_notice();
                }
                Ok(false) => cli_fail("App password not found"),
                Err(e) => cli_fail(format!("Could not persist revocation: {}", e)),
            }
        }
        "link" => {
            let [username, provider, sub] = args else {
                usage_fail("kiss-mail sso-link <user> <provider> <subject>")
            };
            let user_manager = UserManager::new(mail_domain(), data_dir.clone());
            user_manager
                .load()
                .await
                .map_err(|e| load_error("user accounts", &data_dir, "users.json", e))?;
            if !user_manager.user_exists(username).await {
                cli_fail(format!("User '{}' not found", username));
            }
            // Logins compare the provider by its display name.
            let configured = sso_manager.status().provider_name;
            if sso_manager.is_enabled() && provider.trim() != configured {
                eprintln!(
                    "Warning: the configured SSO provider is '{}'; logins will not match '{}'",
                    configured,
                    provider.trim()
                );
            }
            sso_manager
                .link_identity(username, provider, sub)
                .await
                .unwrap_or_else(|e| cli_fail(format!("Could not link identity: {}", e)));
            println!(
                "✓ Linked '{}' to SSO identity {} / {}",
                username,
                provider.trim(),
                sub.trim()
            );
            print_local_write_notice();
        }
        "unbind" => {
            let [username] = args else {
                usage_fail("kiss-mail sso-unbind <user>")
            };
            match sso_manager.unlink_identity(username).await {
                Ok(true) => {
                    println!("✓ Removed the SSO identity binding of '{}'", username);
                    print_local_write_notice();
                }
                Ok(false) => println!("'{}' has no SSO identity binding", username),
                Err(e) => cli_fail(format!("Could not unlink identity: {}", e)),
            }
        }
        _ => unknown_command(cmd, ""),
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn print_banner(
    domain: &str,
    smtp: u16,
    imap: u16,
    pop3: u16,
    api_port: u16,
    api_enabled: bool,
    web_port: u16,
    web_enabled: bool,
    um: &UserManager,
    gm: &GroupManager,
    ldap: &LdapClient,
    sso: &SsoManager,
    antispam: &AntiSpam,
    av: &AntiVirus,
    crypto: &crypto::CryptoManager,
) {
    let stats = um.get_stats().await;
    let group_stats = gm.get_stats().await;
    let ldap_status = ldap.status();
    let sso_status = sso.status();
    let av_status = av.status();
    let ai_stats = antispam.ai_stats().await;
    let crypto_status = crypto.status();
    let crypto_stats = crypto.stats().await;

    println!();
    println!("  ╦╔═╦╔══╗  ╔╦╗╔═╗╦╦  ");
    println!("  ╠╩╗║╚═╗╚═╗║║║╠═╣║║  ");
    println!("  ╩ ╩╩╚═╝╚═╝╩ ╩╩ ╩╩╩═╝");
    println!("  Simple Email Server {}", env!("CARGO_PKG_VERSION"));
    println!();
    println!("  📧 Domain:  {}", domain);
    println!("  👥 Users:   {}", stats.total_users);
    println!("  📋 Groups:  {}", group_stats.total_groups);
    println!();
    println!("  Servers:");
    println!("    SMTP  →  localhost:{}", smtp);
    println!("    IMAP  →  localhost:{}", imap);
    println!("    POP3  →  localhost:{}", pop3);
    if api_enabled {
        println!("    API   →  localhost:{}", api_port);
    }
    if web_enabled {
        println!("    Web   →  http://localhost:{}/admin", web_port);
    }
    println!();
    println!("  Security:");
    println!(
        "    Anti-spam   ✓ Rules + AI ({} patterns learned)",
        ai_stats.total_tokens
    );
    if av_status.clamav_available {
        println!(
            "    Anti-virus  ✓ ClamAV {}",
            av_status.clamav_version.as_deref().unwrap_or("")
        );
    } else if av_status.clamav_enabled {
        println!(
            "    Anti-virus  ✓ Built-in (ClamAV not found at {})",
            av_status.clamav_address
        );
    } else {
        println!("    Anti-virus  ✓ Built-in");
    }
    if crypto_status.enabled && crypto_stats.total_keys == 0 {
        println!(
            "    Encryption  ~ Enabled, no user keys yet (mail is stored unencrypted until users have keys)"
        );
    } else if crypto_status.enabled {
        println!(
            "    Encryption  ✓ {} ({} user keys; mail for users without keys is stored unencrypted)",
            crypto_status.algorithm, crypto_stats.total_keys
        );
    } else {
        println!("    Encryption  ✗ Disabled (set KISS_MAIL_ENCRYPTION=true)");
    }
    println!();
    println!("  Identity:");
    if ldap_status.enabled {
        let tls = if ldap_status.use_tls {
            " (TLS)"
        } else if ldap_status.use_starttls {
            " (StartTLS)"
        } else {
            ""
        };
        println!("    LDAP        ✓ {}{}", ldap_status.url, tls);
    } else {
        println!("    LDAP        ✗ Not configured");
    }
    if sso_status.enabled {
        let app_pw = if sso_status.allow_app_passwords {
            " + app passwords"
        } else {
            ""
        };
        println!("    SSO         ✓ {}{}", sso_status.provider_name, app_pw);
    } else {
        println!("    SSO         ✗ Not configured");
    }
    println!();
    if api_enabled {
        println!("  Remote CLI:");
        println!(
            "    kiss-mail --server http://localhost:{} --api-key <key> <cmd>",
            api_port
        );
        println!();
    }
    println!("  Quick commands:");
    println!("    kiss-mail add <user> <pass>   Create user");
    println!("    kiss-mail list                List users");
    println!("    kiss-mail group-add <name>    Create group");
    println!("    kiss-mail stats               Show stats");
    println!();
    println!("  Press Ctrl+C (or send SIGTERM) to stop");
    println!();
}

fn print_help() {
    let (smtp, imap, pop3) = configured_ports().unwrap_or_else(|_| default_ports());
    println!(
        r#"
KISS Mail - Simple Email Server

USAGE:
    kiss-mail                            Start the mail server
    kiss-mail server                     Start the mail server (aliases: serve, run)
    kiss-mail <command>                  Run a command locally against the data directory
    kiss-mail --server <url> <command>   Run a command on remote server

REMOTE CLI:
    --server, -s <url>    Connect to remote server (or KISS_MAIL_SERVER);
                          https:// is assumed when no scheme is given
    --api-key, -k <key>   API key for authentication (or KISS_MAIL_API_KEY)
    --insecure            Allow plain http:// to a non-loopback host (credentials
                          are sent unencrypted; http://localhost is always allowed)

LOCAL COMMANDS AND A RUNNING SERVER:
    Local commands read and write the JSON files in the data directory. A
    running server does not reload them. If a kiss-mail server is running
    against the same data directory, restart it after local changes or use
    --server/--api-key instead; changes made while it runs may be overwritten.

USER COMMANDS:
    add <user> <pass> [--role <user|admin|superadmin>]
                           Create a new user
    del <user>             Delete a user and their mailbox, keys, SSO data and
                           group memberships (exits 2 if cleanup failed)
    list / user            List all users
    info <user>            Show user details
    passwd <user> <pass> [--require-change]
                           Reset a password; --require-change forces a change at
                           next login (local only)
    passwd <user> --stdin [--require-change]
                           Same, reading the password from stdin
                           (keeps it out of argv; one trailing newline is stripped)
    change-password <user> [--stdin]
                           Change your own password, proving the current one
                           (prompts without echo, or reads current/new from
                           stdin lines 1/2);
                           clears "must change password". Works with --server
                           without an API key.
    stats / status         Show server stats
    purge-orphans          Remove mailboxes, keys, SSO data and group memberships
                           of users that no longer exist (local only; the server
                           also does this at startup)

GROUP COMMANDS:
    groups                        List all groups
    group-add <name> [email]      Create a new group
    group-del <name>              Delete a group
    group-info <name>             Show group details
    group-add-member <grp> <usr>  Add user to group
    group-rm-member <grp> <usr>   Remove user from group

LDAP COMMANDS:
    ldap-test                     Test LDAP connection
    ldap-auth <user> <pass>       Test LDAP authentication
    ldap-search <user>            Search for user in LDAP
    ldap-status                   Show LDAP configuration

SSO COMMANDS:
    sso-status                    Show SSO configuration
    app-password <user> [label]   Generate app password
    app-passwords <user>          List app passwords
    app-pass-revoke <user> <id>   Revoke app password (full id or unique prefix)
    sso-link <user> <provider> <subject>
                                  Bind a user to an SSO identity (provider name as
                                  shown by sso-status; local only). Required for
                                  admin accounts unless SSO_AUTO_BIND_ADMINS=true
    sso-unbind <user>             Remove a user's SSO identity binding (local only)

GENERAL:
    help                   Show this help
    version                Show version

ENVIRONMENT:
    KISS_MAIL_DATA_DIR    Data directory (default: ./mail_data)
    KISS_MAIL_DATA        Deprecated alias for KISS_MAIL_DATA_DIR (DATA_DIR wins)
    KISS_MAIL_DOMAIN      Email domain (default: hostname)
    KISS_MAIL_SMTP_PORT   SMTP port (deprecated alias SMTP_PORT; default: 2525, or 25 if root)
    KISS_MAIL_IMAP_PORT   IMAP port (deprecated alias IMAP_PORT; default: 1143, or 143 if root)
    KISS_MAIL_POP3_PORT   POP3 port (deprecated alias POP3_PORT; default: 1100, or 110 if root)
    KISS_MAIL_ENCRYPTION  Set to 'false'/'0'/'no'/'off' to disable at-rest encryption
    KISS_MAIL_PUBLIC_URL  Public base URL of the web interface (e.g. https://mail.example.com);
                          used in "password change required" replies to mail clients
    RUST_LOG              Log filter (default: kiss_mail=info for the server,
                          kiss_mail=warn on stderr for CLI commands)

    Boolean settings accept 1/true/yes/on and 0/false/no/off (any case).

FIRST RUN:
    If no 'admin' account exists, one is created with a random password that
    is written to $KISS_MAIL_DATA_DIR/initial-admin-password (mode 0600). The
    password is only printed when stdout is a terminal. Change it with
    'kiss-mail passwd admin --stdin' and delete the file.

ADMIN API CONFIGURATION:
    KISS_MAIL_API_KEY     API key for remote access (enables API)
    KISS_MAIL_API_PORT    Admin API port (default: 8025; an invalid value aborts startup)
    KISS_MAIL_API_BIND    Admin API bind address (default: 127.0.0.1)
    KISS_MAIL_API_ENABLED Set to 'true' to enable without API key

WEB ADMIN CONFIGURATION:
    KISS_MAIL_WEB_PORT    Web admin port (default: 8080; an invalid value aborts startup)
    KISS_MAIL_WEB_BIND    Web admin bind address (default: 127.0.0.1)
    KISS_MAIL_WEB_ENABLED Set to 'false' to disable the web admin

LDAP CONFIGURATION:
    LDAP_URL              LDAP server URL (e.g., ldap://localhost:389)
    LDAP_BASE_DN          Base DN for searches (e.g., dc=example,dc=com)
    LDAP_BIND_DN          Service account DN (optional)
    LDAP_BIND_PASSWORD    Service account password (optional)
    LDAP_USER_FILTER      User search filter (default: uid={{username}})
    LDAP_USER_DN_TEMPLATE DN template (e.g., uid={{username}},ou=users,dc=example,dc=com)
    LDAP_USE_TLS          Enable TLS (true/false)
    LDAP_FALLBACK_LOCAL   Fall back to local auth if LDAP fails (default: true)

SSO CONFIGURATION (pick one provider):
    1Password:
      ONEPASSWORD_CLIENT_ID      OAuth2 client ID
      ONEPASSWORD_CLIENT_SECRET  OAuth2 client secret
    Google:
      GOOGLE_CLIENT_ID           OAuth2 client ID
      GOOGLE_CLIENT_SECRET       OAuth2 client secret
    Microsoft:
      MICROSOFT_CLIENT_ID        OAuth2 client ID
      MICROSOFT_CLIENT_SECRET    OAuth2 client secret
      MICROSOFT_TENANT_ID        Azure AD tenant ID
    Okta:
      OKTA_CLIENT_ID             OAuth2 client ID
      OKTA_CLIENT_SECRET         OAuth2 client secret
      OKTA_DOMAIN                Okta domain (e.g., dev-123456.okta.com)
    Generic OIDC:
      SSO_CLIENT_ID              OAuth2 client ID
      SSO_CLIENT_SECRET          OAuth2 client secret
      SSO_AUTH_URL               Authorization endpoint
      SSO_TOKEN_URL              Token endpoint
      SSO_USERINFO_URL           UserInfo endpoint

EXAMPLES:
    # Local commands
    kiss-mail                               # Start server
    kiss-mail add alice secret123           # Create user
    kiss-mail add bob secret456 --role admin # Create admin user
    kiss-mail group-add developers          # Create group
    kiss-mail ldap-test                     # Test LDAP connection

    # Remote commands
    kiss-mail -s mail.example.com -k myapikey list      # https://mail.example.com
    kiss-mail --server=http://localhost:8025 --api-key=secret status
    
    # Using environment variables
    export KISS_MAIL_SERVER=https://mail.example.com
    export KISS_MAIL_API_KEY=myapikey
    kiss-mail list
    kiss-mail add bob secret456

REMOTE ADMINISTRATION:
    To enable the admin API on the server:
    
      export KISS_MAIL_API_KEY=your-secret-key
      kiss-mail
    
    Then from any machine with the CLI:
    
      kiss-mail --server https://mail.example.com --api-key your-secret-key list

    The API itself speaks plain HTTP: expose it through a TLS proxy, or use
    an SSH tunnel and --server http://localhost:8025.
    
    The API provides REST endpoints at /api/* for programmatic access:
      POST /api/auth/login      Login with admin credentials
      POST /api/account/password Change your own password (no token needed)
      GET  /api/status          Server status
      GET  /api/users           List users
      POST /api/users           Create user
      GET  /api/groups          List groups
      POST /api/groups          Create group
      ...and more

CONNECTING:
    Configure your email client with (ports as currently configured):
      Server:   localhost (or your server's address)
      SMTP:     Port {smtp}
      IMAP:     Port {imap}
      POP3:     Port {pop3}
      Username: your_username
      Password: your_password
      Security: None (no TLS - put the server behind a TLS proxy)
"#,
        smtp = smtp,
        imap = imap,
        pop3 = pop3
    );
}

// ============================================================================
// Shared startup / CLI helpers
// ============================================================================

/// Build a startup error for a data file that exists but could not be loaded.
fn load_error(
    what: &str,
    data_dir: &Path,
    file: &str,
    err: std::io::Error,
) -> Box<dyn std::error::Error> {
    format!(
        "Could not load {} from {}: {}. Refusing to continue so existing data is not \
         overwritten; fix or restore the file and try again.",
        what,
        data_dir.join(file).display(),
        err
    )
    .into()
}

/// Create the crypto manager, refusing to continue if `keys.json` exists but
/// could not be loaded (continuing would leave mail undecryptable and block
/// every key change).
fn load_crypto_manager(data_dir: &Path) -> Result<Arc<crypto::CryptoManager>, String> {
    let crypto_manager = crypto::CryptoManager::new(data_dir.to_path_buf());
    if let Some(err) = crypto_manager.load_error() {
        return Err(format!(
            "Could not load encryption keys from {}: {}. Refusing to continue so existing \
             keys are not lost; fix or restore the file and try again.",
            data_dir.join("keys.json").display(),
            err
        ));
    }
    Ok(Arc::new(crypto_manager))
}

/// The account created by [`bootstrap_admin`].
struct InitialAdmin {
    username: String,
    password: String,
    /// Where the password was written (mode 0600).
    password_file: PathBuf,
}

/// Create the `admin` superadmin account if it does not exist yet.
///
/// The random password is written to `$DATA_DIR/initial-admin-password`
/// (mode 0600) before the account is created, and the account is flagged
/// `password_change_required`. Returns `Ok(Some(_))` only when the account
/// was created AND users.json was saved.
async fn bootstrap_admin(
    user_manager: &UserManager,
    data_dir: &Path,
) -> Result<Option<InitialAdmin>, String> {
    if user_manager.user_exists(BOOTSTRAP_ADMIN).await {
        return Ok(None);
    }
    let password = generate_initial_password();
    let password_file = data_dir.join(INITIAL_ADMIN_PASSWORD_FILE);
    write_secret_file(&password_file, &password)
        .await
        .map_err(|e| {
            format!(
                "Could not write initial admin password to {}: {}",
                password_file.display(),
                e
            )
        })?;

    // One save: the account is never stored without password_change_required.
    if let Err(e) = user_manager
        .create_user_with(
            BOOTSTRAP_ADMIN,
            &password,
            Some(UserRole::SuperAdmin),
            |u| u.password_change_required = true,
        )
        .await
    {
        let _ = tokio::fs::remove_file(&password_file).await;
        return Err(format!("Could not create admin account: {}", e));
    }

    tracing::warn!(
        "Created admin account '{}'; initial password written to {}",
        BOOTSTRAP_ADMIN,
        password_file.display()
    );
    Ok(Some(InitialAdmin {
        username: BOOTSTRAP_ADMIN.to_string(),
        password,
        password_file,
    }))
}

/// Atomically write `secret` (plus a newline) to `path` with mode 0600.
async fn write_secret_file(path: &Path, secret: &str) -> std::io::Result<()> {
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        tokio::fs::create_dir_all(dir).await?;
    }
    storage::write_atomic(path, format!("{}\n", secret).into_bytes()).await?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).await?;
    }
    Ok(())
}

/// A random 24-character base62 password.
fn generate_initial_password() -> String {
    use rand::RngExt;
    rand::rng()
        .sample_iter(&rand::distr::Alphanumeric)
        .take(INITIAL_ADMIN_PASSWORD_LEN)
        .map(char::from)
        .collect()
}

/// Report a newly created bootstrap admin. The password itself is only shown
/// when stdout is an interactive terminal (never in captured logs).
fn print_admin_created(created: &InitialAdmin, headline: &str) {
    use std::io::IsTerminal;

    println!();
    println!("{}", headline);
    println!("   Username: {}", created.username);
    if std::io::stdout().is_terminal() {
        println!("   Password: {}", created.password);
    }
    println!(
        "   Password file: {} (mode 0600)",
        created.password_file.display()
    );
    println!();
    println!("   Change the password, then delete the file:");
    println!("      kiss-mail passwd {} --stdin", created.username);
    println!();
}

/// If `args` contains `--stdin`, read the new password from stdin and put it
/// in the password position (see [`splice_stdin_password`]).
fn with_stdin_password(args: &[String]) -> Result<Vec<String>, String> {
    if !args.iter().any(|a| a == "--stdin") {
        return Ok(args.to_vec());
    }
    let mut input = String::new();
    std::io::Read::read_to_string(&mut std::io::stdin(), &mut input)
        .map_err(|e| format!("Could not read password from stdin: {}", e))?;
    splice_stdin_password(args, &input)
}

/// Replace `--stdin` in `passwd <user> --stdin [flags]` with the password read
/// from `input` (one trailing newline is stripped), giving
/// `<user> <password> [flags]`.
fn splice_stdin_password(args: &[String], input: &str) -> Result<Vec<String>, String> {
    const USAGE: &str = "Usage: passwd <user> --stdin";
    let mut rest: Vec<String> = args.iter().filter(|a| *a != "--stdin").cloned().collect();
    let positionals: Vec<usize> = rest
        .iter()
        .enumerate()
        .filter(|(_, a)| !a.starts_with("--"))
        .map(|(i, _)| i)
        .collect();
    let user_idx = match positionals.as_slice() {
        [] => return Err(USAGE.to_string()),
        [i] => *i,
        _ => {
            return Err(format!(
                "Give the new password either as an argument or with --stdin, not both. {}",
                USAGE
            ));
        }
    };
    let password = match input.strip_suffix('\n') {
        Some(line) => line.strip_suffix('\r').unwrap_or(line),
        None => input,
    };
    if password.is_empty() {
        return Err("No password read from stdin".to_string());
    }
    rest.insert(user_idx + 1, password.to_string());
    Ok(rest)
}

/// Printed after a local CLI command changed files in the data directory.
fn print_local_write_notice() {
    eprintln!(
        "Note: If a kiss-mail server is running against this data directory, restart it \
         or use --server/--api-key; changes made while it runs may be overwritten."
    );
}

/// Print an error and exit with status 1.
fn cli_fail(err: impl std::fmt::Display) -> ! {
    eprintln!("Error: {}", err);
    std::process::exit(1);
}

/// Print a usage line and exit with status 1.
fn usage_fail(usage: impl std::fmt::Display) -> ! {
    eprintln!("Usage: {}", usage);
    std::process::exit(1);
}

/// Report an unknown command and exit with status 1.
fn unknown_command(cmd: &str, context: &str) -> ! {
    eprintln!("Unknown command{}: {}", context, cmd);
    eprintln!("Run 'kiss-mail help' for usage.");
    std::process::exit(1);
}

fn enabled_label(enabled: bool) -> &'static str {
    if enabled { "Enabled" } else { "Disabled" }
}

/// Resolve an app-password id from a full id or a unique prefix of one.
fn resolve_id_prefix<'a>(
    ids: impl IntoIterator<Item = &'a str>,
    prefix: &str,
) -> Result<String, String> {
    if prefix.is_empty() {
        return Err("App password id cannot be empty".to_string());
    }
    let ids: Vec<&str> = ids.into_iter().collect();
    if let Some(exact) = ids.iter().find(|id| **id == prefix) {
        return Ok(exact.to_string());
    }
    let matches: Vec<&&str> = ids.iter().filter(|id| id.starts_with(prefix)).collect();
    match matches.len() {
        0 => Err(format!("App password '{}' not found", prefix)),
        1 => Ok(matches[0].to_string()),
        n => Err(format!(
            "App password id prefix '{}' is ambiguous ({} matches); use more characters",
            prefix, n
        )),
    }
}

/// Print one app password entry (shared by local and remote listings).
fn print_app_password(
    id: &str,
    label: &str,
    created_at: chrono::DateTime<chrono::Utc>,
    last_used: Option<chrono::DateTime<chrono::Utc>>,
    expires_at: Option<chrono::DateTime<chrono::Utc>>,
) {
    let status = match expires_at {
        Some(expires) if chrono::Utc::now() > expires => " (EXPIRED)",
        _ => "",
    };
    let last_used = last_used
        .map(|d| d.format("%Y-%m-%d %H:%M").to_string())
        .unwrap_or_else(|| "Never".to_string());
    println!("  {} - {}{}", id, label, status);
    println!("    Created:   {}", created_at.format("%Y-%m-%d %H:%M"));
    println!("    Last used: {}", last_used);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn strings(args: &[&str]) -> Vec<String> {
        args.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn id_prefix_resolution() {
        let ids = ["abcd1234-0000", "abce9999-1111", "zzzz"];
        assert_eq!(resolve_id_prefix(ids, "zzzz"), Ok("zzzz".to_string()));
        assert_eq!(
            resolve_id_prefix(ids, "abcd"),
            Ok("abcd1234-0000".to_string())
        );
        assert!(resolve_id_prefix(ids, "abc").is_err()); // ambiguous
        assert!(resolve_id_prefix(ids, "nope").is_err());
        assert!(resolve_id_prefix(ids, "").is_err());
    }

    #[test]
    fn stdin_password_is_spliced_after_user() {
        assert_eq!(
            splice_stdin_password(&strings(&["alice", "--stdin"]), "s3cret-pass\n"),
            Ok(strings(&["alice", "s3cret-pass"]))
        );
        // Only one trailing newline is stripped (CRLF counts as one)
        assert_eq!(
            splice_stdin_password(&strings(&["--stdin", "alice"]), "pw  \r\n"),
            Ok(strings(&["alice", "pw  "]))
        );
        assert_eq!(
            splice_stdin_password(&strings(&["alice", "--stdin"]), "pw\n\n"),
            Ok(strings(&["alice", "pw\n"]))
        );
        // Flags after the user are kept after the password
        assert_eq!(
            splice_stdin_password(&strings(&["alice", "--stdin", "--require-change"]), "pw"),
            Ok(strings(&["alice", "pw", "--require-change"]))
        );
    }

    #[test]
    fn stdin_password_rejects_bad_input() {
        assert!(splice_stdin_password(&strings(&["--stdin"]), "pw\n").is_err());
        assert!(splice_stdin_password(&strings(&["alice", "pw", "--stdin"]), "pw\n").is_err());
        assert!(splice_stdin_password(&strings(&["alice", "--stdin"]), "\n").is_err());
        assert!(splice_stdin_password(&strings(&["alice", "--stdin"]), "").is_err());
    }

    #[test]
    fn change_password_args_parse() {
        assert_eq!(
            parse_change_password_args(&strings(&["alice", "--stdin"])),
            Ok(ChangePasswordArgs {
                username: "alice".into(),
                stdin: true
            })
        );
        assert_eq!(
            parse_change_password_args(&strings(&["--stdin", "alice"])),
            Ok(ChangePasswordArgs {
                username: "alice".into(),
                stdin: true
            })
        );
        assert_eq!(
            parse_change_password_args(&strings(&["alice"])),
            Ok(ChangePasswordArgs {
                username: "alice".into(),
                stdin: false
            })
        );
        assert!(parse_change_password_args(&strings(&[])).is_err());
        assert!(parse_change_password_args(&strings(&["--stdin"])).is_err());
        // Passwords are never accepted as arguments.
        assert!(parse_change_password_args(&strings(&["alice", "secret"])).is_err());
        assert!(parse_change_password_args(&strings(&["alice", "--force"])).is_err());
    }

    #[test]
    fn change_password_stdin_lines() {
        assert_eq!(
            parse_password_lines("old pass\nnew-password\n"),
            Ok(("old pass".to_string(), "new-password".to_string()))
        );
        assert_eq!(
            parse_password_lines("old\r\nnew\r\nignored\n"),
            Ok(("old".to_string(), "new".to_string()))
        );
        assert!(parse_password_lines("only-one\n").is_err());
        assert!(parse_password_lines("\nnew\n").is_err());
        assert!(parse_password_lines("").is_err());
    }

    #[test]
    fn positional_password_is_untouched_without_stdin_flag() {
        let args = strings(&["alice", "new-password"]);
        assert_eq!(with_stdin_password(&args), Ok(args.clone()));
    }

    #[test]
    fn initial_password_is_24_base62_chars() {
        let a = generate_initial_password();
        let b = generate_initial_password();
        assert_eq!(a.len(), INITIAL_ADMIN_PASSWORD_LEN);
        assert!(a.chars().all(|c| c.is_ascii_alphanumeric()));
        assert_ne!(a, b);
    }

    #[tokio::test]
    async fn bootstrap_admin_creates_once_and_saves() {
        let dir = tempfile::tempdir().unwrap();
        let um = UserManager::new("example.com".to_string(), dir.path().to_path_buf());
        let created = bootstrap_admin(&um, dir.path())
            .await
            .unwrap()
            .expect("created");
        assert_eq!(created.username, "admin");
        assert_eq!(created.password.len(), INITIAL_ADMIN_PASSWORD_LEN);
        assert_eq!(
            created.password_file,
            dir.path().join(INITIAL_ADMIN_PASSWORD_FILE)
        );
        assert!(dir.path().join("users.json").exists());

        // Password file holds the password and is private
        let on_disk = std::fs::read_to_string(&created.password_file).unwrap();
        assert_eq!(on_disk.trim_end(), created.password);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&created.password_file)
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }

        assert!(bootstrap_admin(&um, dir.path()).await.unwrap().is_none());

        let reloaded = UserManager::new("example.com".to_string(), dir.path().to_path_buf());
        reloaded.load().await.unwrap();
        let admin = reloaded.get_user("admin").await.expect("admin saved");
        assert!(admin.password_change_required);
        assert_eq!(admin.role, UserRole::SuperAdmin);
        assert!(admin.verify_password(&created.password));
    }

    #[tokio::test]
    async fn cli_change_password_rewraps_keys() {
        let dir = tempfile::tempdir().unwrap();
        {
            let um = UserManager::new("example.com".to_string(), dir.path().to_path_buf());
            let crypto = Arc::new(crypto::CryptoManager::with_enabled(
                dir.path().to_path_buf(),
                true,
            ));
            um.attach_crypto(Arc::clone(&crypto)).await;
            um.create_user("alice", "Old-password-1", None)
                .await
                .unwrap();
            assert!(crypto.has_keys("alice").await);
        }

        change_password_local(dir.path(), "alice", "Old-password-1", "New-password-2")
            .await
            .unwrap();

        // A fresh manager (as the server would load it) unlocks with the new
        // password only.
        let fresh = crypto::CryptoManager::with_enabled(dir.path().to_path_buf(), true);
        assert!(fresh.unlock_keys("alice", "New-password-2").await.is_ok());
        assert!(fresh.unlock_keys("alice", "Old-password-1").await.is_err());
        let um = UserManager::new("example.com".to_string(), dir.path().to_path_buf());
        um.load().await.unwrap();
        assert!(!um.get_user("alice").await.unwrap().password_change_required);
    }

    #[tokio::test]
    async fn cli_change_password_errors_are_generic() {
        let dir = tempfile::tempdir().unwrap();
        let um = UserManager::new("example.com".to_string(), dir.path().to_path_buf());
        um.create_user("alice", "Old-password-1", None)
            .await
            .unwrap();

        let generic = PasswordChangeFailure::BadCredentials.user_message();
        let wrong = change_password_local(dir.path(), "alice", "nope-nope", "New-password-2")
            .await
            .unwrap_err();
        let missing = change_password_local(dir.path(), "ghost", "nope-nope", "New-password-2")
            .await
            .unwrap_err();
        assert_eq!(wrong, generic);
        assert_eq!(missing, generic);

        // Policy errors are specific (they say nothing about the account).
        let weak = change_password_local(dir.path(), "alice", "Old-password-1", "short")
            .await
            .unwrap_err();
        assert_ne!(weak, generic);
        assert!(weak.contains("at least"), "{}", weak);

        // Externally managed accounts get their own message.
        um.update_user("alice", |u| u.external_auth = Some("ldap".to_string()))
            .await
            .unwrap();
        let external =
            change_password_local(dir.path(), "alice", "Old-password-1", "New-password-2")
                .await
                .unwrap_err();
        assert_eq!(
            external,
            PasswordChangeFailure::ExternallyManaged.user_message()
        );
    }

    #[tokio::test]
    async fn corrupt_users_file_is_a_load_error_not_empty_state() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("users.json"), "{not json").unwrap();
        let um = UserManager::new("example.com".to_string(), dir.path().to_path_buf());
        assert!(um.load().await.is_err());
        // Missing file is fine (first run)
        let empty = tempfile::tempdir().unwrap();
        let um = UserManager::new("example.com".to_string(), empty.path().to_path_buf());
        assert!(um.load().await.is_ok());
    }

    #[test]
    fn corrupt_keys_file_aborts_startup() {
        let dir = tempfile::tempdir().unwrap();
        assert!(load_crypto_manager(dir.path()).is_ok());
        std::fs::write(dir.path().join("keys.json"), "{not json").unwrap();
        let err = load_crypto_manager(dir.path()).err().expect("load error");
        assert!(err.contains("keys.json"), "{}", err);
    }

    /// A mail server task that never finishes.
    fn pending_mail_servers() -> MailServers {
        let mut set = MailServers::new();
        set.spawn(async {
            std::future::pending::<()>().await;
            ("SMTP", Ok(()))
        });
        set
    }

    #[tokio::test]
    async fn optional_server_finishing_does_not_stop_supervisor() {
        let result = tokio::time::timeout(
            Duration::from_millis(200),
            supervise(
                pending_mail_servers(),
                async {},
                std::future::pending::<()>(),
            ),
        )
        .await;
        assert!(result.is_err(), "supervisor returned early: {:?}", result);
    }

    #[tokio::test]
    async fn mail_server_failure_returns_named_error() {
        let mut mail = pending_mail_servers();
        mail.spawn(async { ("IMAP", Err("address in use".to_string())) });
        let result = tokio::time::timeout(
            Duration::from_secs(5),
            supervise(
                mail,
                std::future::pending::<()>(),
                std::future::pending::<()>(),
            ),
        )
        .await
        .expect("supervisor should return");
        let err = result.expect_err("mail failure must be an error");
        assert!(err.contains("IMAP"), "{}", err);
        assert!(err.contains("address in use"), "{}", err);
    }

    #[tokio::test]
    async fn mail_server_stopping_cleanly_is_still_an_error() {
        let mut mail = MailServers::new();
        mail.spawn(async { ("POP3", Ok(())) });
        let err = tokio::time::timeout(
            Duration::from_secs(5),
            supervise(
                mail,
                std::future::pending::<()>(),
                std::future::pending::<()>(),
            ),
        )
        .await
        .expect("supervisor should return")
        .expect_err("a required server stopping is an error");
        assert!(err.contains("POP3 server stopped unexpectedly"), "{}", err);
    }

    #[tokio::test]
    async fn shutdown_signal_returns_ok() {
        let result = tokio::time::timeout(
            Duration::from_secs(5),
            supervise(
                pending_mail_servers(),
                std::future::pending::<()>(),
                async {},
            ),
        )
        .await
        .expect("supervisor should return");
        assert_eq!(result, Ok(()));
    }
}
