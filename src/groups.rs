//! Group management module.
//!
//! Provides email distribution lists and user groups.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};
use tokio::sync::RwLock;

use crate::users::{BOOTSTRAP_ADMIN, UserManager, UserRole, canonical_username};

/// Group visibility/access level
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub enum GroupVisibility {
    /// Anyone can see and send to this group
    Public,
    /// Only members can see; members/managers can send, others only if
    /// `settings.allow_external` is set
    #[default]
    Internal,
    /// Only members can see and send
    Private,
    /// Hidden from directory, only owner/admins can manage (send rules as Internal)
    Hidden,
}

/// Group type
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub enum GroupType {
    /// Distribution list - emails sent to group go to all members
    #[default]
    DistributionList,
    /// Security group - for access control (future use)
    SecurityGroup,
    /// Alias - single email forwarding to another address
    Alias,
}

/// Group settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupSettings {
    /// Allow external senders (non-members)
    pub allow_external: bool,
    /// Moderated - messages require approval.
    ///
    /// Not enforced: stored for future use only.
    pub moderated: bool,
    /// Reply-to behavior.
    ///
    /// Not enforced: stored for future use only.
    pub reply_to_group: bool,
    /// Subject prefix (e.g., "[dev-team]").
    ///
    /// Not enforced: stored for future use only.
    pub subject_prefix: Option<String>,
    /// Footer added to messages.
    ///
    /// Not enforced: stored for future use only.
    pub footer: Option<String>,
    /// Max message size in bytes.
    ///
    /// Not enforced: stored for future use only.
    pub max_message_size: Option<usize>,
    /// Allowed sender domains (empty = all)
    pub allowed_domains: Vec<String>,
}

impl Default for GroupSettings {
    fn default() -> Self {
        Self {
            allow_external: false,
            moderated: false,
            reply_to_group: true,
            subject_prefix: None,
            footer: None,
            max_message_size: None,
            allowed_domains: Vec::new(),
        }
    }
}

/// A user group
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Group {
    /// Group name/identifier (e.g., "developers")
    pub name: String,
    /// Display name (e.g., "Development Team")
    pub display_name: String,
    /// Description
    pub description: String,
    /// Group email address (e.g., "developers@example.com")
    pub email: String,
    /// Group type
    pub group_type: GroupType,
    /// Visibility
    pub visibility: GroupVisibility,
    /// Owner username
    pub owner: String,
    /// Member usernames
    pub members: HashSet<String>,
    /// Manager usernames (can add/remove members)
    pub managers: HashSet<String>,
    /// Group settings
    pub settings: GroupSettings,
    /// Creation time
    pub created_at: DateTime<Utc>,
    /// Last modified time
    pub updated_at: DateTime<Utc>,
    /// Is group active
    pub active: bool,
}

impl Group {
    /// Create a new group. The owner is recorded but not added as a member
    /// or manager (groups are created by server administrators).
    pub fn new(name: String, email: String, owner: String) -> Self {
        let now = Utc::now();
        Self {
            display_name: name.clone(),
            name,
            description: String::new(),
            email,
            group_type: GroupType::default(),
            visibility: GroupVisibility::default(),
            owner: canonical_username(&owner),
            members: HashSet::new(),
            managers: HashSet::new(),
            settings: GroupSettings::default(),
            created_at: now,
            updated_at: now,
            active: true,
        }
    }

    /// Canonicalise owner, member and manager usernames (e.g. after loading
    /// data written by an older version).
    fn canonicalise(&mut self) {
        self.owner = canonical_username(&self.owner);
        self.members = self.members.iter().map(|m| canonical_username(m)).collect();
        self.managers = self
            .managers
            .iter()
            .map(|m| canonical_username(m))
            .collect();
    }

    /// Check if user is a member
    pub fn is_member(&self, username: &str) -> bool {
        self.members.contains(&canonical_username(username))
    }

    /// Check if user is the owner
    pub fn is_owner(&self, username: &str) -> bool {
        self.owner == canonical_username(username)
    }

    /// Check if user is a manager
    pub fn is_manager(&self, username: &str) -> bool {
        let username = canonical_username(username);
        self.managers.contains(&username) || self.owner == username
    }

    /// Check if a sender can post to this group, given an envelope sender
    /// address split into local part and domain, and the server's local domain.
    ///
    /// Membership is only granted when the sender is on `local_domain`
    /// (case-insensitive), so an external `alice@evil.example` is not treated as
    /// local member `alice`. This is the hook SMTP should call before expanding
    /// a group recipient.
    pub fn can_send_from(
        &self,
        sender_local: &str,
        sender_domain: &str,
        local_domain: &str,
    ) -> bool {
        let is_local = sender_domain.eq_ignore_ascii_case(local_domain);
        // A non-local sender never matches a member username.
        let username = if is_local {
            canonical_username(sender_local)
        } else {
            String::new()
        };
        self.can_send(&username, Some(sender_domain))
    }

    /// Check if user can send to this group.
    ///
    /// `username` is a local username (empty for external senders).
    /// `settings.allowed_domains`, when non-empty, restricts external senders
    /// only: `sender_domain` must be in the list. Local senders (non-empty
    /// `username`) are judged by visibility and membership alone, so a group
    /// whose list omits the local domain still accepts its own members.
    pub fn can_send(&self, username: &str, sender_domain: Option<&str>) -> bool {
        if !self.active {
            return false;
        }

        // Check visibility-based permissions
        let can_send_by_visibility = match self.visibility {
            GroupVisibility::Public => true,
            GroupVisibility::Internal | GroupVisibility::Hidden => {
                self.settings.allow_external
                    || (!username.is_empty()
                        && (self.is_member(username) || self.is_manager(username)))
            }
            GroupVisibility::Private => !username.is_empty() && self.is_member(username),
        };

        if !can_send_by_visibility {
            return false;
        }

        // Allowed domains restrict external senders only.
        if username.is_empty() && !self.settings.allowed_domains.is_empty() {
            if let Some(domain) = sender_domain {
                return self
                    .settings
                    .allowed_domains
                    .iter()
                    .any(|d| d.eq_ignore_ascii_case(domain));
            }
            return false;
        }

        true
    }

    /// Add a member (username is canonicalised)
    pub fn add_member(&mut self, username: String) -> bool {
        let added = self.members.insert(canonical_username(&username));
        if added {
            self.updated_at = Utc::now();
        }
        added
    }

    /// Remove a member (and their manager role). The owner stays the owner
    /// even if removed from the member list; whether the owner may be removed
    /// is decided by [`GroupManager::remove_member`].
    pub fn remove_member(&mut self, username: &str) -> bool {
        let username = canonical_username(username);
        let removed = self.members.remove(&username);
        if removed {
            self.managers.remove(&username);
            self.updated_at = Utc::now();
        }
        removed
    }

    /// Get all recipients for this group as local usernames (not full email
    /// addresses); callers must append the local domain if they need addresses.
    pub fn get_recipients(&self) -> Vec<String> {
        self.members.iter().cloned().collect()
    }
}

/// Group management errors
#[derive(Debug, Clone)]
pub enum GroupError {
    /// Group not found
    NotFound(String),
    /// Group already exists
    AlreadyExists(String),
    /// Invalid group name
    InvalidName(String),
    /// The named user account does not exist
    UserNotFound(String),
    /// The user is not a member of the group
    NotMember(String),
    /// Storage error
    StorageError(String),
}

impl std::fmt::Display for GroupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound(name) => write!(f, "Group not found: {}", name),
            Self::AlreadyExists(name) => write!(f, "Group already exists: {}", name),
            Self::InvalidName(msg) => write!(f, "Invalid group name: {}", msg),
            Self::UserNotFound(name) => write!(f, "user {} does not exist", name),
            Self::NotMember(name) => write!(f, "{} is not a member of the group", name),
            Self::StorageError(msg) => write!(f, "Storage error: {}", msg),
        }
    }
}

impl std::error::Error for GroupError {}

/// Group manager
///
/// Every method has server-administrator semantics (the CLI, admin API and
/// admin web are the only callers); there are no per-user permission checks.
///
/// Mutations use a copy-commit pattern: under `commit_lock` the current map
/// is cloned, the copy is changed and written to `groups.json`, and only
/// after a successful write is it installed in memory (together with a
/// rebuilt email map). A failed write therefore never leaves memory and disk
/// out of step. Readers take `groups` (and `email_map`) briefly and never
/// wait on disk I/O.
///
/// Lock ordering: `commit_lock`, then `groups`, then `email_map`. Methods
/// that only translate an email to a name (e.g.
/// [`GroupManager::get_by_email`]) release the `email_map` guard before
/// touching `groups`.
#[derive(Debug)]
pub struct GroupManager {
    /// Groups by name
    groups: Arc<RwLock<HashMap<String, Group>>>,
    /// Email to group name mapping (always rebuilt from `groups`)
    email_map: Arc<RwLock<HashMap<String, String>>>,
    /// Data directory
    data_dir: PathBuf,
    /// Serializes mutations (and with them writes of groups.json).
    commit_lock: tokio::sync::Mutex<()>,
    /// When attached, usernames added to groups must exist and group
    /// addresses must not collide with local users (see
    /// [`GroupManager::attach_user_manager`]).
    users: OnceLock<Arc<UserManager>>,
}

/// Validate a group email address (must look like `local@domain`).
fn validate_group_email(email: &str) -> Result<(), GroupError> {
    let email = email.trim();
    match email.split_once('@') {
        Some((local, domain)) if !local.is_empty() && !domain.is_empty() => Ok(()),
        _ => Err(GroupError::InvalidName(format!(
            "Invalid group email address: {}",
            email
        ))),
    }
}

/// Validate a group name (1-64 characters: alphanumeric, dash, underscore).
fn validate_group_name(name: &str) -> Result<(), GroupError> {
    if name.is_empty() || name.len() > 64 {
        return Err(GroupError::InvalidName(
            "Name must be 1-64 characters".to_string(),
        ));
    }
    if !name
        .chars()
        .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
    {
        return Err(GroupError::InvalidName(
            "Name can only contain alphanumeric, dash, underscore".to_string(),
        ));
    }
    Ok(())
}

/// Email (lowercase) -> group name lookup for a group map.
fn email_map_of(groups: &HashMap<String, Group>) -> HashMap<String, String> {
    groups
        .iter()
        .map(|(name, g)| (g.email.to_lowercase(), name.clone()))
        .collect()
}

/// Whether `email` is already used by a group other than `except`.
fn email_taken(groups: &HashMap<String, Group>, email_lower: &str, except: Option<&str>) -> bool {
    groups
        .iter()
        .any(|(name, g)| g.email.to_lowercase() == email_lower && Some(name.as_str()) != except)
}

impl GroupManager {
    /// Create a new group manager
    pub fn new(data_dir: PathBuf) -> Self {
        Self {
            groups: Arc::new(RwLock::new(HashMap::new())),
            email_map: Arc::new(RwLock::new(HashMap::new())),
            data_dir,
            commit_lock: tokio::sync::Mutex::new(()),
            users: OnceLock::new(),
        }
    }

    /// Attach the user manager. From then on `add_member` and
    /// `create_with_members` reject usernames that do not exist
    /// ([`GroupError::UserNotFound`]), group addresses that belong to a local
    /// user are refused, and `remove_user_everywhere` can hand orphaned
    /// groups to another administrator. Without it (tests, tools) no such
    /// checks are made. Only the first call has an effect.
    pub fn attach_user_manager(&self, um: Arc<UserManager>) {
        if self.users.set(um).is_err() {
            tracing::debug!("GroupManager: user manager already attached");
        }
    }

    /// Fail with `UserNotFound` for the first username that does not exist
    /// (only when a user manager is attached).
    async fn check_users_exist<'a>(
        &self,
        usernames: impl IntoIterator<Item = &'a str>,
    ) -> Result<(), GroupError> {
        let Some(um) = self.users.get() else {
            return Ok(());
        };
        for name in usernames {
            if !um.user_exists(name).await {
                return Err(GroupError::UserNotFound(canonical_username(name)));
            }
        }
        Ok(())
    }

    /// Fail with `AlreadyExists` when `email` is the address of an existing
    /// local user (`<user>@<default domain>`; only with a user manager).
    async fn check_email_not_user(&self, email: &str) -> Result<(), GroupError> {
        let Some(um) = self.users.get() else {
            return Ok(());
        };
        let Some((local, domain)) = email.trim().rsplit_once('@') else {
            return Ok(());
        };
        if domain.eq_ignore_ascii_case(um.default_domain()) && um.user_exists(local).await {
            return Err(GroupError::AlreadyExists(format!(
                "address in use by user {}",
                canonical_username(local)
            )));
        }
        Ok(())
    }

    /// Group members, managers and owners that are not existing accounts, as
    /// (group, username) pairs, sorted; each is logged as a warning. Nothing
    /// is removed. Empty when no user manager is attached.
    pub async fn validate_members(&self) -> Vec<(String, String)> {
        let Some(um) = self.users.get() else {
            return Vec::new();
        };
        let candidates: Vec<(String, String)> = {
            let groups = self.groups.read().await;
            let mut out = Vec::new();
            for (name, g) in groups.iter() {
                let mut users: HashSet<&String> = g.members.iter().collect();
                users.extend(g.managers.iter());
                users.insert(&g.owner);
                out.extend(users.into_iter().map(|u| (name.clone(), u.clone())));
            }
            out
        };
        let mut unknown = Vec::new();
        for (group, user) in candidates {
            if !um.user_exists(&user).await {
                unknown.push((group, user));
            }
        }
        unknown.sort();
        for (group, user) in &unknown {
            tracing::warn!(
                "Group '{}' references user '{}', which does not exist",
                group,
                user
            );
        }
        unknown
    }

    /// Who takes over the groups of deleted user `username`: the bootstrap
    /// `admin` account if it exists (and is not `username`), otherwise the
    /// first existing super administrator (by name). `None` without a user
    /// manager or when nobody qualifies.
    async fn takeover_owner(&self, username: &str) -> Option<String> {
        let um = self.users.get()?;
        if username != BOOTSTRAP_ADMIN && um.user_exists(BOOTSTRAP_ADMIN).await {
            return Some(BOOTSTRAP_ADMIN.to_string());
        }
        let mut supers: Vec<String> = um
            .list_users()
            .await
            .into_iter()
            .filter(|u| u.role == UserRole::SuperAdmin && u.username != username)
            .map(|u| u.username)
            .collect();
        supers.sort();
        supers.into_iter().next()
    }

    /// Remove a (deleted) user from the members and managers of every group
    /// and save once. Groups the user owned are handed to the bootstrap
    /// `admin` account if it exists (and is not the user being removed),
    /// otherwise to an existing super administrator; if nobody can take over,
    /// the group keeps its owner but is deactivated (it stops accepting mail)
    /// and a warning is logged. Returns the number of groups changed.
    /// Idempotent: a second call changes nothing.
    pub async fn remove_user_everywhere(&self, username: &str) -> Result<usize, GroupError> {
        let username = canonical_username(username);
        let new_owner = self.takeover_owner(&username).await;

        let changed = self
            .commit(|groups| {
                let mut changed = 0;
                for group in groups.values_mut() {
                    let mut touched = group.members.remove(&username);
                    touched |= group.managers.remove(&username);
                    if group.owner == username {
                        match &new_owner {
                            Some(owner) => {
                                tracing::info!(
                                    "Group '{}': owner '{}' was deleted; ownership passes to '{}'",
                                    group.name,
                                    username,
                                    owner
                                );
                                group.owner = owner.clone();
                                touched = true;
                            }
                            None if group.active => {
                                tracing::warn!(
                                    "Group '{}' is owned by deleted user '{}' and no administrator can take it over; the group is deactivated",
                                    group.name,
                                    username
                                );
                                group.active = false;
                                touched = true;
                            }
                            None => {}
                        }
                    }
                    if touched {
                        group.updated_at = Utc::now();
                        changed += 1;
                    }
                }
                Ok((changed, changed > 0))
            })
            .await?;

        if changed > 0 {
            tracing::info!("Removed user '{}' from {} group(s)", username, changed);
        }
        Ok(changed)
    }

    /// Load groups from disk
    pub async fn load(&self) -> Result<(), std::io::Error> {
        let path = self.data_dir.join("groups.json");
        let Some(mut loaded) = crate::storage::read_json::<HashMap<String, Group>>(&path).await?
        else {
            return Ok(());
        };
        for group in loaded.values_mut() {
            group.canonicalise();
        }
        let map = email_map_of(&loaded);
        let count = loaded.len();

        let _commit = self.commit_lock.lock().await;
        // Lock order: groups, then email_map.
        let mut groups = self.groups.write().await;
        let mut email_map = self.email_map.write().await;
        *groups = loaded;
        *email_map = map;
        drop(email_map);
        drop(groups);

        tracing::info!("Loaded {} groups", count);
        Ok(())
    }

    /// Write a group map to `groups.json` atomically.
    async fn write_file(&self, groups: &HashMap<String, Group>) -> Result<(), std::io::Error> {
        tokio::fs::create_dir_all(&self.data_dir).await?;
        let data = serde_json::to_vec_pretty(groups)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        crate::storage::write_atomic(&self.data_dir.join("groups.json"), data).await
    }

    /// Apply a change durably (copy-commit, see [`GroupManager`]). `change`
    /// returns the value to hand back and whether it modified the map; an
    /// unchanged map is not rewritten.
    async fn commit<R>(
        &self,
        change: impl FnOnce(&mut HashMap<String, Group>) -> Result<(R, bool), GroupError>,
    ) -> Result<R, GroupError> {
        let _commit = self.commit_lock.lock().await;
        let mut next = self.groups.read().await.clone();
        let (result, changed) = change(&mut next)?;
        if !changed {
            return Ok(result);
        }
        if let Err(e) = self.write_file(&next).await {
            tracing::error!("Failed to save groups: {}", e);
            return Err(GroupError::StorageError(e.to_string()));
        }
        let map = email_map_of(&next);
        // Lock order: groups, then email_map.
        let mut groups = self.groups.write().await;
        let mut email_map = self.email_map.write().await;
        *groups = next;
        *email_map = map;
        Ok(result)
    }

    /// Create a new, empty group. `owner` is recorded but not added as a
    /// member or manager.
    pub async fn create(&self, name: &str, email: &str, owner: &str) -> Result<Group, GroupError> {
        self.create_with_members(name, email, owner, None, &[])
            .await
    }

    /// Like [`GroupManager::create`], additionally setting a description and
    /// adding `members`. With a user manager attached every member must
    /// exist and the address must not belong to a local user; this is
    /// checked before anything is created, and the group (description and
    /// members included) is saved in one write, so a failure never leaves a
    /// half-created group.
    pub async fn create_with_members(
        &self,
        name: &str,
        email: &str,
        owner: &str,
        description: Option<&str>,
        members: &[String],
    ) -> Result<Group, GroupError> {
        validate_group_name(name)?;
        validate_group_email(email)?;
        self.check_users_exist(members.iter().map(String::as_str))
            .await?;
        self.check_email_not_user(email).await?;

        let name_lower = name.to_lowercase();
        let email_lower = email.trim().to_lowercase();

        let mut group = Group::new(name_lower.clone(), email_lower.clone(), owner.to_string());
        if let Some(desc) = description {
            group.description = desc.to_string();
        }
        for member in members {
            group.add_member(member.clone());
        }

        let group = self
            .commit(|groups| {
                if groups.contains_key(&name_lower) {
                    return Err(GroupError::AlreadyExists(name.to_string()));
                }
                if email_taken(groups, &email_lower, None) {
                    return Err(GroupError::AlreadyExists(format!(
                        "Email {} already in use",
                        email
                    )));
                }
                groups.insert(name_lower.clone(), group.clone());
                Ok((group, true))
            })
            .await?;

        tracing::info!("Created group '{}' owned by '{}'", name, group.owner);
        Ok(group)
    }

    /// Delete a group.
    pub async fn delete(&self, name: &str) -> Result<(), GroupError> {
        let name_lower = name.to_lowercase();
        self.commit(|groups| match groups.remove(&name_lower) {
            Some(_) => Ok(((), true)),
            None => Err(GroupError::NotFound(name.to_string())),
        })
        .await?;
        tracing::info!("Deleted group '{}'", name);
        Ok(())
    }

    /// Get a group by name
    pub async fn get(&self, name: &str) -> Option<Group> {
        self.groups.read().await.get(&name.to_lowercase()).cloned()
    }

    /// Get a group by email address
    pub async fn get_by_email(&self, email: &str) -> Option<Group> {
        let email_lower = email.to_lowercase();
        // Clone the name and release the email_map guard before taking the
        // groups lock (see lock ordering note on GroupManager).
        let name = self.email_map.read().await.get(&email_lower).cloned()?;
        self.groups.read().await.get(&name).cloned()
    }

    /// Check if an email address is a group
    #[cfg(test)]
    pub async fn is_group_email(&self, email: &str) -> bool {
        self.email_map
            .read()
            .await
            .contains_key(&email.to_lowercase())
    }

    /// Expand a group email to member usernames (see [`Group::get_recipients`])
    pub async fn expand_recipients(&self, email: &str) -> Option<Vec<String>> {
        self.get_by_email(email)
            .await
            .filter(|g| g.active)
            .map(|g| g.get_recipients())
    }

    /// Add a member to a group. The username is canonicalised and, with a
    /// user manager attached, must exist (`UserNotFound`). Adding an existing
    /// member is a no-op.
    pub async fn add_member(&self, group_name: &str, username: &str) -> Result<(), GroupError> {
        // Checked before committing (UserManager has its own locks).
        self.check_users_exist([username]).await?;

        let name_lower = group_name.to_lowercase();
        let username = canonical_username(username);
        let added = self
            .commit(|groups| {
                let group = groups
                    .get_mut(&name_lower)
                    .ok_or_else(|| GroupError::NotFound(group_name.to_string()))?;
                let added = group.add_member(username.clone());
                Ok((added, added))
            })
            .await?;

        if added {
            tracing::info!("Added '{}' to group '{}'", username, group_name);
        }
        Ok(())
    }

    /// Remove a member from a group (an owner on the member list may be
    /// removed too; they keep ownership). Removing a username that is not on
    /// the member list is a `NotMember` error.
    pub async fn remove_member(&self, group_name: &str, username: &str) -> Result<(), GroupError> {
        let name_lower = group_name.to_lowercase();
        let username = canonical_username(username);
        self.commit(|groups| {
            let group = groups
                .get_mut(&name_lower)
                .ok_or_else(|| GroupError::NotFound(group_name.to_string()))?;
            if !group.remove_member(&username) {
                return Err(GroupError::NotMember(username.clone()));
            }
            Ok(((), true))
        })
        .await?;

        tracing::info!("Removed '{}' from group '{}'", username, group_name);
        Ok(())
    }

    /// List all groups.
    pub async fn list(&self) -> Vec<Group> {
        self.groups.read().await.values().cloned().collect()
    }

    /// Update a group's email and/or description. `None` leaves a field
    /// unchanged. The new email is validated (and, with a user manager, must
    /// not belong to a local user) and reflected in the email lookup map.
    pub async fn update_details(
        &self,
        name: &str,
        email: Option<&str>,
        description: Option<&str>,
    ) -> Result<(), GroupError> {
        if let Some(e) = email {
            validate_group_email(e)?;
        }
        let name_lower = name.to_lowercase();
        let new_email = email.map(|e| e.trim().to_lowercase());

        if let Some(new_email) = &new_email {
            let current = self.get(name).await.map(|g| g.email.to_lowercase());
            if current.as_ref() != Some(new_email) {
                self.check_email_not_user(new_email).await?;
            }
        }

        self.commit(|groups| {
            if let Some(new_email) = &new_email
                && email_taken(groups, new_email, Some(&name_lower))
            {
                return Err(GroupError::AlreadyExists(format!(
                    "Email {} already in use",
                    new_email
                )));
            }
            let group = groups
                .get_mut(&name_lower)
                .ok_or_else(|| GroupError::NotFound(name.to_string()))?;

            let mut changed = false;
            if let Some(new_email) = new_email
                && group.email.to_lowercase() != new_email
            {
                group.email = new_email;
                changed = true;
            }
            if let Some(desc) = description
                && group.description != desc
            {
                group.description = desc.to_string();
                changed = true;
            }
            if changed {
                group.updated_at = Utc::now();
            }
            Ok(((), changed))
        })
        .await
    }

    /// Get group stats
    pub async fn get_stats(&self) -> GroupStats {
        GroupStats {
            total_groups: self.groups.read().await.len(),
        }
    }
}

/// Group statistics
#[derive(Debug, Clone)]
pub struct GroupStats {
    pub total_groups: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    /// Create `name` (owned by `owner`) with `members`.
    async fn group_with(manager: &GroupManager, name: &str, owner: &str, members: &[&str]) {
        let members: Vec<String> = members.iter().map(|m| m.to_string()).collect();
        manager
            .create_with_members(
                name,
                &format!("{}@example.com", name),
                owner,
                None,
                &members,
            )
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn create_records_owner_without_membership() {
        let dir = tempdir().unwrap();
        let manager = GroupManager::new(dir.path().to_path_buf());
        let g = manager
            .create("Ops", "Ops@Example.com", "Admin")
            .await
            .unwrap();
        assert_eq!(g.name, "ops");
        assert_eq!(g.email, "ops@example.com");
        assert_eq!(g.owner, "admin");
        assert!(g.members.is_empty());
        assert!(g.managers.is_empty());
        assert!(
            manager
                .expand_recipients("ops@example.com")
                .await
                .unwrap()
                .is_empty()
        );
        // Removing the (non-member) owner reports "not a member".
        assert!(matches!(
            manager.remove_member("ops", "admin").await,
            Err(GroupError::NotMember(_))
        ));
    }

    #[tokio::test]
    async fn create_with_members_sets_description_in_one_write() {
        let dir = tempdir().unwrap();
        {
            let manager = GroupManager::new(dir.path().to_path_buf());
            let members = vec!["Bob".to_string()];
            let g = manager
                .create_with_members(
                    "docs",
                    "docs@example.com",
                    "admin",
                    Some("Documentation team"),
                    &members,
                )
                .await
                .unwrap();
            assert_eq!(g.description, "Documentation team");
            assert!(g.is_member("bob"));
        }
        let manager = GroupManager::new(dir.path().to_path_buf());
        manager.load().await.unwrap();
        let g = manager.get("docs").await.unwrap();
        assert_eq!(g.description, "Documentation team");
        assert!(g.is_member("bob"));
    }

    #[tokio::test]
    async fn member_management_and_persistence() {
        let dir = tempdir().unwrap();
        {
            let manager = GroupManager::new(dir.path().to_path_buf());
            manager
                .create("team", "team@example.com", "alice")
                .await
                .unwrap();
            manager.add_member("team", "  Bob ").await.unwrap();
            manager.add_member("team", "carol").await.unwrap();
            // Adding twice is a no-op.
            manager.add_member("team", "BOB").await.unwrap();
            manager.remove_member("team", "carol").await.unwrap();
            assert!(matches!(
                manager.remove_member("team", "nobody").await,
                Err(GroupError::NotMember(_))
            ));
            assert!(matches!(
                manager.add_member("nope", "bob").await,
                Err(GroupError::NotFound(_))
            ));
        }
        let manager = GroupManager::new(dir.path().to_path_buf());
        manager.load().await.unwrap();
        let g = manager.get("team").await.unwrap();
        assert_eq!(g.members.len(), 1);
        assert!(g.is_member("bob"));
        assert!(!g.is_manager("bob"));
        assert_eq!(
            manager.expand_recipients("TEAM@example.com").await.unwrap(),
            vec!["bob".to_string()]
        );
    }

    #[tokio::test]
    async fn delete_removes_group_and_address() {
        let dir = tempdir().unwrap();
        let manager = GroupManager::new(dir.path().to_path_buf());
        manager
            .create("team", "team@example.com", "alice")
            .await
            .unwrap();
        manager.delete("TEAM").await.unwrap();
        assert!(manager.get("team").await.is_none());
        assert!(!manager.is_group_email("team@example.com").await);
        assert!(matches!(
            manager.delete("team").await,
            Err(GroupError::NotFound(_))
        ));
        // The address is free again.
        manager
            .create("team2", "team@example.com", "alice")
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn owner_member_can_be_removed_and_keeps_ownership() {
        let dir = tempdir().unwrap();
        let manager = GroupManager::new(dir.path().to_path_buf());
        group_with(&manager, "team", "alice", &["alice"]).await;
        manager.remove_member("team", "alice").await.unwrap();
        let g = manager.get("team").await.unwrap();
        assert!(!g.is_member("alice"));
        assert_eq!(g.owner, "alice");
    }

    /// A group manager with a user manager attached that knows `users`
    /// (each `(name, role)`).
    async fn manager_with_users(dir: &std::path::Path, users: &[(&str, UserRole)]) -> GroupManager {
        let um = Arc::new(UserManager::new(
            "example.com".to_string(),
            dir.to_path_buf(),
        ));
        for (u, role) in users {
            um.create_user(u, "password123", Some(*role)).await.unwrap();
        }
        let manager = GroupManager::new(dir.to_path_buf());
        manager.attach_user_manager(um);
        manager
    }

    fn plain_users(names: &[&'static str]) -> Vec<(&'static str, UserRole)> {
        names.iter().map(|n| (*n, UserRole::User)).collect()
    }

    #[tokio::test]
    async fn unknown_users_are_rejected_when_user_manager_attached() {
        let dir = tempdir().unwrap();
        let manager = manager_with_users(dir.path(), &plain_users(&["alice", "bob"])).await;
        manager
            .create("team", "team@example.com", "alice")
            .await
            .unwrap();

        let err = manager.add_member("team", "Ghost").await.unwrap_err();
        assert!(matches!(&err, GroupError::UserNotFound(u) if u == "ghost"));
        assert_eq!(err.to_string(), "user ghost does not exist");
        manager.add_member("team", "BOB").await.unwrap();

        // Members are validated before anything is created.
        let members = vec!["bob".to_string(), "ghost".to_string()];
        assert!(matches!(
            manager
                .create_with_members("ops", "ops@example.com", "admin", None, &members)
                .await,
            Err(GroupError::UserNotFound(_))
        ));
        assert!(manager.get("ops").await.is_none());
        let members = vec!["bob".to_string(), "Alice".to_string()];
        let g = manager
            .create_with_members("ops", "ops@example.com", "admin", None, &members)
            .await
            .unwrap();
        assert_eq!(g.members.len(), 2);
        assert!(g.is_member("alice"));

        // Without a user manager there is no check.
        let plain = GroupManager::new(dir.path().join("plain"));
        plain.create("t", "t@example.com", "x").await.unwrap();
        plain.add_member("t", "ghost").await.unwrap();
    }

    #[tokio::test]
    async fn group_address_may_not_belong_to_a_local_user() {
        let dir = tempdir().unwrap();
        let manager = manager_with_users(dir.path(), &plain_users(&["alice"])).await;
        let err = manager
            .create("team", "Alice@Example.COM", "admin")
            .await
            .unwrap_err();
        assert!(matches!(&err, GroupError::AlreadyExists(m) if m.contains("user alice")));
        assert!(manager.get("team").await.is_none());
        // Another domain with the same local part is fine.
        manager
            .create("team", "alice@lists.example.org", "admin")
            .await
            .unwrap();
        // So is a free address, but changing it to the user's is refused.
        manager
            .create("other", "other@example.com", "admin")
            .await
            .unwrap();
        assert!(matches!(
            manager
                .update_details("other", Some("alice@example.com"), None)
                .await,
            Err(GroupError::AlreadyExists(_))
        ));
        assert_eq!(
            manager.get("other").await.unwrap().email,
            "other@example.com"
        );
    }

    #[tokio::test]
    async fn remove_user_everywhere_reassigns_owned_groups_to_admin() {
        let dir = tempdir().unwrap();
        let manager =
            manager_with_users(dir.path(), &plain_users(&["admin", "alice", "bob"])).await;
        group_with(&manager, "a-team", "alice", &["alice", "bob"]).await;
        group_with(&manager, "b-team", "bob", &["bob", "alice"]).await;
        group_with(&manager, "other", "bob", &["bob"]).await;

        assert_eq!(manager.remove_user_everywhere("Alice").await.unwrap(), 2);
        let a = manager.get("a-team").await.unwrap();
        assert_eq!(a.owner, "admin");
        assert!(a.active);
        assert!(!a.is_member("alice") && !a.managers.contains("alice"));
        assert!(a.is_member("bob"));
        assert!(!manager.get("b-team").await.unwrap().is_member("alice"));
        // Nothing left to do (idempotent).
        assert_eq!(manager.remove_user_everywhere("alice").await.unwrap(), 0);

        // Saved, and reloaded intact.
        let reloaded = GroupManager::new(dir.path().to_path_buf());
        reloaded.load().await.unwrap();
        assert_eq!(reloaded.get("a-team").await.unwrap().owner, "admin");
    }

    #[tokio::test]
    async fn remove_user_everywhere_falls_back_to_a_superadmin() {
        let dir = tempdir().unwrap();
        let manager = manager_with_users(
            dir.path(),
            &[
                ("alice", UserRole::User),
                ("zed", UserRole::SuperAdmin),
                ("root", UserRole::SuperAdmin),
            ],
        )
        .await;
        group_with(&manager, "a-team", "alice", &["alice"]).await;
        assert_eq!(manager.remove_user_everywhere("alice").await.unwrap(), 1);
        let g = manager.get("a-team").await.unwrap();
        assert_eq!(g.owner, "root");
        assert!(g.active);
    }

    #[tokio::test]
    async fn remove_user_everywhere_for_the_admin_keeps_the_owner_and_deactivates() {
        let dir = tempdir().unwrap();
        // The bootstrap admin itself is deleted and no super admin exists.
        let manager = manager_with_users(dir.path(), &plain_users(&["admin", "bob"])).await;
        group_with(&manager, "ops", "admin", &["admin", "bob"]).await;

        assert_eq!(manager.remove_user_everywhere("admin").await.unwrap(), 1);
        let g = manager.get("ops").await.unwrap();
        // Never handed to the account being removed; owner kept, group off.
        assert_eq!(g.owner, "admin");
        assert!(!g.is_member("admin"));
        assert!(g.is_member("bob"));
        assert!(!g.active);
        assert!(manager.expand_recipients("ops@example.com").await.is_none());
        // Re-running changes nothing.
        assert_eq!(manager.remove_user_everywhere("admin").await.unwrap(), 0);
    }

    #[tokio::test]
    async fn failed_save_leaves_memory_unchanged() {
        let dir = tempdir().unwrap();
        // data_dir is a regular file, so writing groups.json must fail.
        let not_a_dir = dir.path().join("file");
        std::fs::write(&not_a_dir, b"x").unwrap();
        let manager = GroupManager::new(not_a_dir);

        assert!(matches!(
            manager.create("team", "team@example.com", "admin").await,
            Err(GroupError::StorageError(_))
        ));
        assert!(manager.get("team").await.is_none());
        assert!(!manager.is_group_email("team@example.com").await);
        assert_eq!(manager.get_stats().await.total_groups, 0);
    }

    #[tokio::test]
    async fn failed_save_keeps_previous_members() {
        let dir = tempdir().unwrap();
        let data = dir.path().join("data");
        let manager = GroupManager::new(data.clone());
        group_with(&manager, "team", "admin", &["bob"]).await;

        // Replace the data directory with a file: later writes fail.
        std::fs::remove_dir_all(&data).unwrap();
        std::fs::write(&data, b"x").unwrap();

        assert!(matches!(
            manager.add_member("team", "carol").await,
            Err(GroupError::StorageError(_))
        ));
        assert!(matches!(
            manager.remove_member("team", "bob").await,
            Err(GroupError::StorageError(_))
        ));
        assert!(matches!(
            manager.delete("team").await,
            Err(GroupError::StorageError(_))
        ));
        let g = manager.get("team").await.unwrap();
        assert!(g.is_member("bob") && !g.is_member("carol"));
        assert!(manager.is_group_email("team@example.com").await);
    }

    #[tokio::test]
    async fn validate_members_reports_unknown_users_without_dropping() {
        let dir = tempdir().unwrap();
        // Written without a user manager (e.g. by an older version).
        let plain = GroupManager::new(dir.path().to_path_buf());
        group_with(&plain, "team", "alice", &["alice", "ghost"]).await;

        let manager = manager_with_users(dir.path(), &plain_users(&["alice"])).await;
        manager.load().await.unwrap();
        assert_eq!(
            manager.validate_members().await,
            vec![("team".to_string(), "ghost".to_string())]
        );
        assert!(manager.get("team").await.unwrap().is_member("ghost"));
        assert!(plain.validate_members().await.is_empty());
    }

    #[tokio::test]
    async fn test_set_email_updates_lookup() {
        let dir = tempdir().unwrap();
        let manager = GroupManager::new(dir.path().to_path_buf());
        manager.create("a", "a@example.com", "admin").await.unwrap();
        manager.create("b", "b@example.com", "admin").await.unwrap();

        manager
            .update_details("a", Some("alpha@example.com"), None)
            .await
            .unwrap();
        assert_eq!(
            manager
                .get_by_email("alpha@example.com")
                .await
                .unwrap()
                .name,
            "a"
        );
        assert!(manager.get_by_email("a@example.com").await.is_none());

        // Duplicate email rejected
        assert!(matches!(
            manager
                .update_details("a", Some("b@example.com"), None)
                .await,
            Err(GroupError::AlreadyExists(_))
        ));
        // Invalid email rejected
        assert!(
            manager
                .update_details("a", Some("not-an-email"), None)
                .await
                .is_err()
        );
        // Unknown group
        assert!(matches!(
            manager
                .update_details("zzz", Some("z@example.com"), None)
                .await,
            Err(GroupError::NotFound(_))
        ));
        // Duplicate name / email on create
        assert!(matches!(
            manager.create("A", "x@example.com", "admin").await,
            Err(GroupError::AlreadyExists(_))
        ));
        assert!(matches!(
            manager.create("c", "B@example.com", "admin").await,
            Err(GroupError::AlreadyExists(_))
        ));
    }

    #[tokio::test]
    async fn test_create_rejects_invalid_name_and_email() {
        let dir = tempdir().unwrap();
        let manager = GroupManager::new(dir.path().to_path_buf());
        for (name, email) in [
            ("x", ""),
            ("x", "nodomain"),
            ("", "x@example.com"),
            ("bad name", "x@example.com"),
        ] {
            assert!(
                manager.create(name, email, "admin").await.is_err(),
                "{} {}",
                name,
                email
            );
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_concurrent_create_and_lookup_no_deadlock() {
        let dir = tempdir().unwrap();
        let manager = Arc::new(GroupManager::new(dir.path().to_path_buf()));

        let work = async {
            let mut handles = Vec::new();
            for i in 0..20usize {
                let m = Arc::clone(&manager);
                handles.push(tokio::spawn(async move {
                    m.create(&format!("g{}", i), &format!("g{}@example.com", i), "admin")
                        .await
                        .unwrap();
                }));
                let m = Arc::clone(&manager);
                handles.push(tokio::spawn(async move {
                    for j in 0..20 {
                        let _ = m.get_by_email(&format!("g{}@example.com", j)).await;
                    }
                }));
                let m = Arc::clone(&manager);
                handles.push(tokio::spawn(async move {
                    let _ = m.delete(&format!("g{}", i.saturating_sub(1))).await;
                }));
            }
            for h in handles {
                h.await.unwrap();
            }
        };

        tokio::time::timeout(std::time::Duration::from_secs(10), work)
            .await
            .expect("group manager deadlocked");
    }

    #[test]
    fn test_can_send_from() {
        let mut g = Group::new("team".into(), "team@example.com".into(), "alice".into());
        g.add_member("bob".into());

        // Local member may send
        assert!(g.can_send_from("bob", "example.com", "example.com"));
        assert!(g.can_send_from("Bob", "EXAMPLE.com", "example.com"));
        // External sender with a member's local part may not
        assert!(!g.can_send_from("bob", "evil.example", "example.com"));
        // Non-member local user may not (Internal, allow_external=false)
        assert!(!g.can_send_from("carol", "example.com", "example.com"));

        g.settings.allow_external = true;
        assert!(g.can_send_from("anyone", "other.example", "example.com"));

        g.settings.allowed_domains = vec!["Partner.example".into()];
        assert!(g.can_send_from("x", "partner.example", "example.com"));
        assert!(!g.can_send_from("x", "other.example", "example.com"));

        g.visibility = GroupVisibility::Private;
        g.settings.allowed_domains.clear();
        assert!(!g.can_send_from("anyone", "other.example", "example.com"));
        assert!(g.can_send_from("bob", "example.com", "example.com"));

        g.active = false;
        assert!(!g.can_send_from("bob", "example.com", "example.com"));
    }

    #[test]
    fn allowed_domains_restricts_only_external_senders() {
        let mut g = Group::new("team".into(), "team@example.com".into(), "alice".into());
        g.add_member("bob".into());
        g.settings.allow_external = true;
        // The local domain is deliberately not in the list.
        g.settings.allowed_domains = vec!["partner.example".into()];

        // Local members and the owner may still post.
        assert!(g.can_send_from("bob", "example.com", "example.com"));
        assert!(g.can_send_from("Alice", "Example.COM", "example.com"));
        // External senders are limited to the allowed domains.
        assert!(g.can_send_from("x", "partner.example", "example.com"));
        assert!(!g.can_send_from("x", "other.example", "example.com"));
        // A member's local part on a foreign domain is still external.
        assert!(!g.can_send_from("bob", "other.example", "example.com"));
        // An unauthenticated sender claiming the local domain is judged as
        // external (SMTP passes an empty username), so it is rejected.
        assert!(!g.can_send("", Some("example.com")));
        // Without allow_external, non-members stay blocked regardless.
        g.settings.allow_external = false;
        assert!(!g.can_send_from("x", "partner.example", "example.com"));
        assert!(g.can_send_from("bob", "example.com", "example.com"));
    }
}
