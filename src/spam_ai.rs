//! AI-driven spam detection using Naive Bayes classification.
//!
//! This module implements a self-learning Bayesian spam filter that:
//! - Learns from emails marked as spam/ham
//! - Uses TF-IDF-style tokenization
//! - Calculates spam probability using Bayes' theorem
//! - Persists learned data to disk

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// Save learned data after this many `learn_*` calls...
const SAVE_EVERY_N_LEARNS: u32 = 20;
/// ...or when dirty and at least this long since the last save.
const SAVE_MAX_INTERVAL: Duration = Duration::from_secs(60);

/// Messages larger than this are never learned from.
pub const MAX_LEARN_MESSAGE_BYTES: usize = 256 * 1024;
/// At most this many distinct tokens are learned from one message.
pub const MAX_TOKENS_PER_LEARN: usize = 1000;
/// Vocabulary cap: when exceeded, the lowest-count tokens are evicted.
pub const MAX_VOCABULARY: usize = 200_000;
/// Fraction of the vocabulary cap freed per prune (amortises eviction cost).
const PRUNE_FRACTION: usize = 10; // 1/10 = 10%

/// Whether a message is eligible for learning (size cap). Callers decide
/// separately whether the sender is trusted enough to learn from.
pub fn should_learn_from(email: &str) -> bool {
    email.len() <= MAX_LEARN_MESSAGE_BYTES
}

/// Known URL-shortener hosts (matched exactly against the parsed URL host,
/// optionally with a `www.` prefix).
pub(crate) const URL_SHORTENER_HOSTS: &[&str] = &[
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
];

/// Extract lowercase hosts of all `http://` / `https://` URLs in `text`.
///
/// The authority ends at the first character outside
/// `[A-Za-z0-9.\-:\[\]@]`; trailing punctuation is trimmed. Userinfo
/// (`user@`) and port are stripped. Matching of the scheme is ASCII
/// case-insensitive.
pub(crate) fn url_hosts(text: &str) -> Vec<String> {
    let lower = text.to_ascii_lowercase();
    let mut hosts = Vec::new();
    let mut rest = lower.as_str();
    while let Some(pos) = rest.find("http") {
        let after = &rest[pos + 4..];
        let after = if let Some(a) = after.strip_prefix("s://") {
            a
        } else if let Some(a) = after.strip_prefix("://") {
            a
        } else {
            rest = after;
            continue;
        };
        let end = after
            .find(|c: char| {
                !(c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':' | '[' | ']' | '@'))
            })
            .unwrap_or(after.len());
        let authority = after[..end].trim_end_matches(['.', '-', ':', '@']);
        let host = authority.rsplit('@').next().unwrap_or(authority);
        let host = match host.rfind(':') {
            Some(i) if host[i + 1..].chars().all(|c| c.is_ascii_digit()) => &host[..i],
            _ => host,
        };
        let host = host.trim_end_matches(['.', '-', ':']);
        if !host.is_empty() {
            hosts.push(host.to_string());
        }
        rest = &after[end..];
    }
    hosts
}

/// Whether `host` is a known URL shortener (exact host match).
pub(crate) fn is_url_shortener(host: &str) -> bool {
    let host = host.strip_prefix("www.").unwrap_or(host);
    URL_SHORTENER_HOSTS.contains(&host)
}

/// Whether the ordered word list contains `phrase` (space-separated words)
/// as consecutive words.
fn contains_phrase(words: &[&str], phrase: &str) -> bool {
    let parts: Vec<&str> = phrase.split(' ').collect();
    if parts.len() == 1 {
        return words.contains(&parts[0]);
    }
    words.windows(parts.len()).any(|w| w == parts.as_slice())
}

/// Spam classification result
#[derive(Debug, Clone)]
pub struct SpamClassification {
    /// Probability that the email is spam (0.0 - 1.0)
    pub spam_probability: f64,
    /// Top words contributing to spam score
    pub spam_indicators: Vec<(String, f64)>,
    /// Top words contributing to ham score  
    pub ham_indicators: Vec<(String, f64)>,
    /// Confidence level (how certain the classifier is)
    pub confidence: f64,
}

/// Token statistics for Bayesian learning
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct TokenStats {
    /// Times this token appeared in spam
    spam_count: u64,
    /// Times this token appeared in ham (non-spam)
    ham_count: u64,
}

/// Bayesian spam classifier with persistent learning
#[derive(Debug)]
pub struct SpamClassifier {
    /// Token frequency data
    tokens: Arc<RwLock<HashMap<String, TokenStats>>>,
    /// Total spam emails seen
    total_spam: Arc<RwLock<u64>>,
    /// Total ham emails seen
    total_ham: Arc<RwLock<u64>>,
    /// Minimum token occurrences to be considered (default: 3)
    pub min_occurrences: u64,
    /// Data directory for persistence
    data_dir: PathBuf,
    /// Whether the model has been modified since last save
    dirty: Arc<RwLock<bool>>,
    /// `learn_*` calls since the last successful save
    learns_since_save: AtomicU32,
    /// Time of the last successful save (or creation)
    last_save: std::sync::Mutex<Instant>,
    /// Serializes saves so snapshots land on disk in order
    save_lock: tokio::sync::Mutex<()>,
    /// Vocabulary cap (defaults to [`MAX_VOCABULARY`])
    max_vocabulary: usize,
}

impl SpamClassifier {
    /// Create a new spam classifier
    pub fn new(data_dir: PathBuf) -> Self {
        Self {
            tokens: Arc::new(RwLock::new(HashMap::new())),
            total_spam: Arc::new(RwLock::new(0)),
            total_ham: Arc::new(RwLock::new(0)),
            min_occurrences: 3,
            data_dir,
            dirty: Arc::new(RwLock::new(false)),
            learns_since_save: AtomicU32::new(0),
            last_save: std::sync::Mutex::new(Instant::now()),
            save_lock: tokio::sync::Mutex::new(()),
            max_vocabulary: MAX_VOCABULARY,
        }
    }

    /// Load learned data from disk
    pub async fn load(&self) -> Result<(), std::io::Error> {
        let path = self.data_dir.join("spam_classifier.json");
        let Some(saved) = crate::storage::read_json::<SavedClassifier>(&path).await? else {
            // Initialize with seed data
            self.seed_initial_data().await;
            return Ok(());
        };

        *self.tokens.write().await = saved.tokens;
        *self.total_spam.write().await = saved.total_spam;
        *self.total_ham.write().await = saved.total_ham;

        tracing::info!(
            "Loaded spam classifier: {} tokens, {} spam, {} ham",
            self.tokens.read().await.len(),
            saved.total_spam,
            saved.total_ham
        );

        Ok(())
    }

    /// Save learned data to disk (if modified). Atomic, 0600, fsync'd.
    pub async fn save(&self) -> Result<(), std::io::Error> {
        let _guard = self.save_lock.lock().await;
        if !*self.dirty.read().await {
            return Ok(());
        }

        tokio::fs::create_dir_all(&self.data_dir).await?;
        let path = self.data_dir.join("spam_classifier.json");

        // Snapshot under the tokens lock (learners hold it while updating)
        // and clear `dirty` at the same point, so learns that happen during
        // the write re-mark it.
        let saved = {
            let tokens = self.tokens.read().await;
            let saved = SavedClassifier {
                tokens: tokens.clone(),
                total_spam: *self.total_spam.read().await,
                total_ham: *self.total_ham.read().await,
            };
            *self.dirty.write().await = false;
            saved
        };
        let learns = self.learns_since_save.swap(0, Ordering::SeqCst);

        let result = async {
            let data = serde_json::to_vec(&saved)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
            crate::storage::write_atomic(&path, data).await
        }
        .await;

        match result {
            Ok(()) => {
                if let Ok(mut t) = self.last_save.lock() {
                    *t = Instant::now();
                }
                Ok(())
            }
            Err(e) => {
                *self.dirty.write().await = true;
                self.learns_since_save.fetch_add(learns, Ordering::SeqCst);
                Err(e)
            }
        }
    }

    /// Save if enough learning has happened since the last save: every
    /// [`SAVE_EVERY_N_LEARNS`] learns, or when dirty and more than
    /// [`SAVE_MAX_INTERVAL`] has passed. Returns whether a save was attempted.
    pub async fn maybe_save(&self) -> bool {
        if !*self.dirty.read().await {
            return false;
        }
        let learns = self.learns_since_save.load(Ordering::SeqCst);
        let elapsed = self
            .last_save
            .lock()
            .map(|t| t.elapsed())
            .unwrap_or(SAVE_MAX_INTERVAL);
        if learns < SAVE_EVERY_N_LEARNS && elapsed < SAVE_MAX_INTERVAL {
            return false;
        }
        if let Err(e) = self.save().await {
            tracing::warn!("Failed to save spam classifier: {}", e);
        }
        true
    }

    /// Classify an email as spam or ham
    pub async fn classify(&self, email: &str) -> SpamClassification {
        let tokens = self.tokenize(email);
        let total_spam = *self.total_spam.read().await;
        let total_ham = *self.total_ham.read().await;

        // Not enough training data
        if total_spam < 10 || total_ham < 10 {
            return SpamClassification {
                spam_probability: 0.5,
                spam_indicators: vec![],
                ham_indicators: vec![],
                confidence: 0.0,
            };
        }

        let token_data = self.tokens.read().await;
        let mut log_spam_prob = 0.0f64;
        let mut log_ham_prob = 0.0f64;
        let mut spam_indicators = Vec::new();
        let mut ham_indicators = Vec::new();

        // Prior probabilities (with Laplace smoothing)
        let prior_spam = (total_spam as f64 + 1.0) / (total_spam + total_ham + 2) as f64;
        let prior_ham = (total_ham as f64 + 1.0) / (total_spam + total_ham + 2) as f64;

        log_spam_prob += prior_spam.ln();
        log_ham_prob += prior_ham.ln();

        for token in &tokens {
            if let Some(stats) = token_data.get(token) {
                // Skip rare tokens
                if stats.spam_count + stats.ham_count < self.min_occurrences {
                    continue;
                }

                // Probability of token given spam (with Laplace smoothing)
                let p_token_spam = (stats.spam_count as f64 + 1.0) / (total_spam as f64 + 2.0);
                let p_token_ham = (stats.ham_count as f64 + 1.0) / (total_ham as f64 + 2.0);

                log_spam_prob += p_token_spam.ln();
                log_ham_prob += p_token_ham.ln();

                // Track indicators
                let spam_ratio = p_token_spam / (p_token_spam + p_token_ham);
                if spam_ratio > 0.7 {
                    spam_indicators.push((token.clone(), spam_ratio));
                } else if spam_ratio < 0.3 {
                    ham_indicators.push((token.clone(), 1.0 - spam_ratio));
                }
            }
        }

        // Convert log probabilities to probability using log-sum-exp trick
        let max_log = log_spam_prob.max(log_ham_prob);
        let spam_exp = (log_spam_prob - max_log).exp();
        let ham_exp = (log_ham_prob - max_log).exp();
        let spam_probability = spam_exp / (spam_exp + ham_exp);

        // Calculate confidence based on how far from 0.5 we are
        let confidence = (spam_probability - 0.5).abs() * 2.0;

        // Sort indicators by strength
        spam_indicators.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        ham_indicators.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

        // Keep top 10 indicators
        spam_indicators.truncate(10);
        ham_indicators.truncate(10);

        SpamClassification {
            spam_probability,
            spam_indicators,
            ham_indicators,
            confidence,
        }
    }

    /// Train the classifier with a spam email. Returns `false` (and learns
    /// nothing) if the message exceeds [`MAX_LEARN_MESSAGE_BYTES`].
    pub async fn learn_spam(&self, email: &str) -> bool {
        self.learn(email, true).await
    }

    /// Train the classifier with a ham (non-spam) email. Returns `false`
    /// (and learns nothing) if the message exceeds [`MAX_LEARN_MESSAGE_BYTES`].
    pub async fn learn_ham(&self, email: &str) -> bool {
        self.learn(email, false).await
    }

    async fn learn(&self, email: &str, spam: bool) -> bool {
        if !should_learn_from(email) {
            tracing::debug!(
                "Not learning from {}-byte message (limit {})",
                email.len(),
                MAX_LEARN_MESSAGE_BYTES
            );
            return false;
        }
        let tokens = Self::cap_learn_tokens(self.tokenize(email));
        let mut token_data = self.tokens.write().await;

        for token in tokens {
            let stats = token_data.entry(token).or_default();
            if spam {
                stats.spam_count = stats.spam_count.saturating_add(1);
            } else {
                stats.ham_count = stats.ham_count.saturating_add(1);
            }
        }
        if token_data.len() > self.max_vocabulary {
            prune_vocabulary(&mut token_data, self.max_vocabulary);
        }

        if spam {
            *self.total_spam.write().await += 1;
        } else {
            *self.total_ham.write().await += 1;
        }
        *self.dirty.write().await = true;
        drop(token_data);
        self.learns_since_save.fetch_add(1, Ordering::SeqCst);
        true
    }

    /// Keep at most [`MAX_TOKENS_PER_LEARN`] distinct tokens, always keeping
    /// the (bounded) feature tokens and dropping excess words.
    fn cap_learn_tokens(tokens: Vec<String>) -> Vec<String> {
        let mut seen = std::collections::HashSet::new();
        let (features, words): (Vec<String>, Vec<String>) = tokens
            .into_iter()
            .filter(|t| seen.insert(t.clone()))
            .partition(|t| t.starts_with("__"));
        let room = MAX_TOKENS_PER_LEARN.saturating_sub(features.len());
        let mut out = features;
        out.truncate(MAX_TOKENS_PER_LEARN);
        out.extend(words.into_iter().take(room));
        out
    }

    /// Tokenize email into words/features
    fn tokenize(&self, email: &str) -> Vec<String> {
        let email_lower = email.to_lowercase();
        let mut tokens = Vec::new();
        let mut seen = std::collections::HashSet::new();

        // Extract words (3-20 chars, alphanumeric)
        for word in email_lower.split(|c: char| !c.is_alphanumeric() && c != '\'') {
            let word = word.trim_matches('\'');
            if word.len() >= 3 && word.len() <= 20 && !seen.contains(word) {
                // Skip pure numbers
                if !word.chars().all(|c| c.is_numeric()) {
                    tokens.push(word.to_string());
                    seen.insert(word.to_string());
                }
            }
        }

        // Extract special features (needs original case for CAPS ratio)
        self.extract_features(email, &email_lower, &mut tokens, &mut seen);

        tokens
    }

    /// Extract special features from email.
    ///
    /// `original` is the message as received (used for case-sensitive
    /// features); `email` is its lowercased form.
    fn extract_features(
        &self,
        original: &str,
        email: &str,
        tokens: &mut Vec<String>,
        seen: &mut std::collections::HashSet<String>,
    ) {
        // Ordered word sequence (for bigrams / phrase matching on word boundaries)
        let words: Vec<&str> = email
            .split(|c: char| !c.is_alphanumeric() && c != '\'')
            .map(|w| w.trim_matches('\''))
            .filter(|w| !w.is_empty())
            .collect();

        // URL features
        let hosts = url_hosts(email);
        if !hosts.is_empty() {
            tokens.push(format!("__URL_COUNT_{}", hosts.len().min(10)));
        }

        // URL shorteners (exact host match, so "t.co" doesn't hit "microsoft.com")
        if hosts.iter().any(|h| is_url_shortener(h)) && seen.insert("__SHORT_URL".to_string()) {
            tokens.push("__SHORT_URL".to_string());
        }

        // CAPS features (computed on the original-case text)
        let caps_ratio = original.chars().filter(|c| c.is_uppercase()).count() as f64
            / original
                .chars()
                .filter(|c| c.is_alphabetic())
                .count()
                .max(1) as f64;
        if caps_ratio > 0.3 {
            tokens.push("__HIGH_CAPS".to_string());
        }

        // Exclamation marks
        let exclaim_count = email.matches('!').count();
        if exclaim_count > 3 {
            tokens.push(format!("__EXCLAIM_{}", exclaim_count.min(10)));
        }

        // Dollar signs (money)
        if email.contains('$') {
            tokens.push("__HAS_DOLLAR".to_string());
        }

        // Urgency words
        let urgency_words = [
            "urgent",
            "immediately",
            "act now",
            "limited time",
            "expires",
            "deadline",
        ];
        for word in &urgency_words {
            if contains_phrase(&words, word) && seen.insert(format!("__URGENT_{}", word)) {
                tokens.push(format!("__URGENT_{}", word));
            }
        }

        // Phishing patterns
        let phishing_words = [
            "verify",
            "confirm",
            "suspend",
            "account",
            "password",
            "login",
            "click here",
        ];
        let mut phishing_count = 0;
        for word in &phishing_words {
            if email.contains(word) {
                phishing_count += 1;
            }
        }
        if phishing_count >= 3 {
            tokens.push("__PHISHING_PATTERN".to_string());
        }

        // HTML features
        if email.contains("<html") || email.contains("<body") {
            tokens.push("__HAS_HTML".to_string());
        }
        if email.contains("style=") || email.contains("<style") {
            tokens.push("__HAS_STYLE".to_string());
        }

        // Image-heavy (common in spam)
        let img_count = email.matches("<img").count();
        if img_count > 2 {
            tokens.push(format!("__IMG_COUNT_{}", img_count.min(10)));
        }

        // Base64 content (attachments)
        if email.contains("base64") {
            tokens.push("__HAS_BASE64".to_string());
        }

        // Missing headers (suspicious)
        if !email.contains("message-id:") {
            tokens.push("__NO_MESSAGE_ID".to_string());
        }
        if !email.contains("date:") {
            tokens.push("__NO_DATE".to_string());
        }

        // Sender patterns
        if email.contains("@") {
            // Extract domain from From header
            let from_start = if email.starts_with("from:") {
                Some(0)
            } else {
                email.find("\nfrom:").map(|p| p + 1)
            };
            if let Some(from_start) = from_start {
                let from_line = email[from_start..].lines().next().unwrap_or("");
                if let Some(at_pos) = from_line.find('@') {
                    // Char-based (never splits a multibyte character)
                    let domain: String = from_line[at_pos + 1..]
                        .chars()
                        .take_while(|c| c.is_alphanumeric() || *c == '.' || *c == '-')
                        .take(253)
                        .collect();

                    // Suspicious TLDs
                    let suspicious_tlds = [
                        ".xyz", ".top", ".work", ".click", ".loan", ".racing", ".win",
                    ];
                    for tld in &suspicious_tlds {
                        if domain.ends_with(tld) {
                            tokens.push(format!("__SUSPICIOUS_TLD_{}", tld));
                            break;
                        }
                    }
                }
            }
        }

        // Bigrams for common spam phrases
        let spam_bigrams = [
            ("free", "money"),
            ("click", "here"),
            ("act", "now"),
            ("limited", "time"),
            ("you", "won"),
            ("dear", "friend"),
            ("bank", "account"),
            ("credit", "card"),
            ("nigerian", "prince"),
            ("wire", "transfer"),
        ];

        // Real adjacent-word bigrams
        for pair in words.windows(2) {
            if spam_bigrams.contains(&(pair[0], pair[1])) {
                let tok = format!("__BIGRAM_{}_{}", pair[0], pair[1]);
                if seen.insert(tok.clone()) {
                    tokens.push(tok);
                }
            }
        }
    }

    /// Seed initial training data with common spam/ham patterns
    async fn seed_initial_data(&self) {
        tracing::info!("Seeding spam classifier with initial training data");

        // Common spam words and patterns
        let spam_seeds = [
            "viagra",
            "cialis",
            "lottery",
            "winner",
            "congratulations",
            "million",
            "dollars",
            "inheritance",
            "beneficiary",
            "nigeria",
            "prince",
            "urgent",
            "wire",
            "transfer",
            "casino",
            "gambling",
            "pills",
            "pharmacy",
            "discount",
            "cheap",
            "free",
            "click",
            "subscribe",
            "unsubscribe",
            "opt-out",
            "limited",
            "offer",
            "expires",
            "act",
            "now",
            "immediately",
            "guarantee",
            "credit",
            "debt",
            "loan",
            "mortgage",
            "refinance",
            "weight",
            "loss",
            "diet",
            "enhancement",
            "enlargement",
            "__SHORT_URL",
            "__HIGH_CAPS",
            "__PHISHING_PATTERN",
            "__NO_MESSAGE_ID",
            "__SUSPICIOUS_TLD_.xyz",
            "__SUSPICIOUS_TLD_.top",
            "__BIGRAM_free_money",
            "__BIGRAM_click_here",
            "__BIGRAM_act_now",
            "__BIGRAM_dear_friend",
        ];

        // Common ham words
        let ham_seeds = [
            "meeting",
            "schedule",
            "project",
            "report",
            "document",
            "attached",
            "please",
            "thanks",
            "thank",
            "regards",
            "sincerely",
            "best",
            "review",
            "feedback",
            "update",
            "status",
            "discussion",
            "team",
            "monday",
            "tuesday",
            "wednesday",
            "thursday",
            "friday",
            "week",
            "invoice",
            "receipt",
            "order",
            "shipping",
            "delivery",
            "tracking",
            "conference",
            "call",
            "agenda",
            "minutes",
            "presentation",
            "github",
            "commit",
            "merge",
            "pull",
            "request",
            "issue",
            "bug",
            "deployment",
            "release",
            "version",
            "update",
            "patch",
        ];

        let mut tokens = self.tokens.write().await;

        // Seed spam tokens
        for word in &spam_seeds {
            let stats = tokens.entry(word.to_string()).or_default();
            stats.spam_count += 50;
            stats.ham_count += 5;
        }

        // Seed ham tokens
        for word in &ham_seeds {
            let stats = tokens.entry(word.to_string()).or_default();
            stats.spam_count += 5;
            stats.ham_count += 50;
        }

        *self.total_spam.write().await = 100;
        *self.total_ham.write().await = 100;
        *self.dirty.write().await = true;

        drop(tokens);
        if let Err(e) = self.save().await {
            tracing::warn!("Failed to save seeded spam classifier: {}", e);
        }

        tracing::info!("Spam classifier seeded with initial data");
    }

    /// Get classifier statistics
    pub async fn stats(&self) -> ClassifierStats {
        ClassifierStats {
            total_tokens: self.tokens.read().await.len(),
        }
    }
}

/// Evict the lowest-count tokens so the vocabulary drops to 90% of `cap`
/// (freeing 10% at once so pruning is amortised over many learns).
fn prune_vocabulary(tokens: &mut HashMap<String, TokenStats>, cap: usize) {
    let target = cap - cap / PRUNE_FRACTION;
    if tokens.len() <= target {
        return;
    }
    let remove = tokens.len() - target;
    let mut counts: Vec<u64> = tokens
        .values()
        .map(|s| s.spam_count.saturating_add(s.ham_count))
        .collect();
    // Count threshold: the `remove`-th smallest total.
    let (_, &mut threshold, _) = counts.select_nth_unstable(remove - 1);
    let below = counts.iter().filter(|&&c| c < threshold).count();
    let mut at_threshold_to_remove = remove.saturating_sub(below);
    tokens.retain(|_, s| {
        let c = s.spam_count.saturating_add(s.ham_count);
        if c < threshold {
            false
        } else if c == threshold && at_threshold_to_remove > 0 {
            at_threshold_to_remove -= 1;
            false
        } else {
            true
        }
    });
    tracing::debug!(
        "Pruned spam classifier vocabulary to {} tokens (cap {})",
        tokens.len(),
        cap
    );
}

/// Saved classifier data for persistence
#[derive(Serialize, Deserialize)]
struct SavedClassifier {
    tokens: HashMap<String, TokenStats>,
    total_spam: u64,
    total_ham: u64,
}

/// Classifier statistics
#[derive(Debug, Clone)]
pub struct ClassifierStats {
    pub total_tokens: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_classifier_basics() {
        let dir = tempdir().unwrap();
        let classifier = SpamClassifier::new(dir.path().to_path_buf());
        classifier.load().await.unwrap();

        // Train with some spam
        for _ in 0..20 {
            classifier
                .learn_spam("Buy cheap viagra now! Click here for free money! Act immediately!")
                .await;
            classifier
                .learn_spam("Congratulations! You won the lottery! Wire transfer required.")
                .await;
        }

        // Train with some ham
        for _ in 0..20 {
            classifier
                .learn_ham("Hi, please review the attached document for our meeting tomorrow.")
                .await;
            classifier
                .learn_ham("The project status update is ready. Let me know your feedback.")
                .await;
        }

        // Test classification
        let spam_result = classifier
            .classify("FREE MONEY! Click here NOW to claim your prize!!!")
            .await;
        assert!(
            spam_result.spam_probability > 0.5,
            "Should classify as likely spam"
        );

        let ham_result = classifier
            .classify("Please review the attached report and send your feedback.")
            .await;
        assert!(
            ham_result.spam_probability < 0.5,
            "Should classify as likely ham"
        );
    }

    #[tokio::test]
    async fn test_persistence() {
        let dir = tempdir().unwrap();

        // Create and train
        {
            let classifier = SpamClassifier::new(dir.path().to_path_buf());
            classifier.load().await.unwrap();

            for _ in 0..10 {
                classifier.learn_spam("spam test message").await;
                classifier.learn_ham("ham test message").await;
            }

            classifier.save().await.unwrap();
        }

        // Load and verify
        {
            let classifier = SpamClassifier::new(dir.path().to_path_buf());
            classifier.load().await.unwrap();

            assert!(*classifier.total_spam.read().await > 100); // Seeded + trained
            assert!(*classifier.total_ham.read().await > 100);
        }
    }

    fn features(text: &str) -> Vec<String> {
        let c = SpamClassifier::new(PathBuf::from("unused"));
        c.tokenize(text)
    }

    #[test]
    fn test_caps_feature_uses_original_case() {
        assert!(features("BUY NOW THIS IS AMAZING").contains(&"__HIGH_CAPS".to_string()));
        assert!(!features("buy now this is amazing").contains(&"__HIGH_CAPS".to_string()));
    }

    #[test]
    fn test_bigrams_require_adjacency() {
        let t = features("Click here to win");
        assert!(t.contains(&"__BIGRAM_click_here".to_string()));
        let t = features("Click the button over there");
        assert!(!t.iter().any(|x| x.starts_with("__BIGRAM_click")));
        // "now" inside "acknowledge" / "act" inside "contact" must not count
        let t = features("contact us to acknowledge");
        assert!(!t.iter().any(|x| x.starts_with("__BIGRAM_act")));
    }

    #[test]
    fn test_urgency_word_boundaries() {
        assert!(features("this is urgent").contains(&"__URGENT_urgent".to_string()));
        assert!(!features("this is non-urgentish").contains(&"__URGENT_urgent".to_string()));
        assert!(features("act now please").contains(&"__URGENT_act now".to_string()));
        assert!(!features("contact nowhere").contains(&"__URGENT_act now".to_string()));
    }

    #[test]
    fn test_url_hosts_and_shorteners() {
        let hosts = url_hosts(
            "a HTTPS://User@Bit.LY:443/x b http://www.microsoft.com/t.co c https://t.co/z",
        );
        assert_eq!(hosts, vec!["bit.ly", "www.microsoft.com", "t.co"]);
        assert!(is_url_shortener("t.co"));
        assert!(is_url_shortener("www.bit.ly"));
        assert!(!is_url_shortener("microsoft.com"));
        assert!(!is_url_shortener("reddit.co"));
        let t = features("visit https://www.microsoft.com/ today");
        assert!(!t.contains(&"__SHORT_URL".to_string()));
        let t = features("visit https://t.co/abc today");
        assert!(t.contains(&"__SHORT_URL".to_string()));
    }

    #[test]
    fn test_url_hosts_end_at_non_host_chars() {
        assert_eq!(url_hosts("go to http://evil.ru, now"), vec!["evil.ru"]);
        assert_eq!(url_hosts("(see https://example.com)."), vec!["example.com"]);
        assert_eq!(url_hosts("x http://a.example.com;y"), vec!["a.example.com"]);
        assert_eq!(
            url_hosts("http://host.example.com!!"),
            vec!["host.example.com"]
        );
        assert_eq!(url_hosts("http://u:p@10.0.0.1:8080/x"), vec!["10.0.0.1"]);
        assert_eq!(url_hosts("http://[::1]:80/"), vec!["[::1]"]);
        assert_eq!(url_hosts("http://example.com.-"), vec!["example.com"]);
    }

    #[tokio::test]
    async fn learn_ignores_oversized_messages() {
        let c = SpamClassifier::new(PathBuf::from("unused"));
        let big = "word ".repeat(MAX_LEARN_MESSAGE_BYTES / 5 + 1);
        assert!(!should_learn_from(&big));
        assert!(!c.learn_spam(&big).await);
        assert_eq!(*c.total_spam.read().await, 0);
        assert!(c.tokens.read().await.is_empty());
        assert!(c.learn_ham("small message here").await);
        assert_eq!(*c.total_ham.read().await, 1);
    }

    #[tokio::test]
    async fn learn_caps_tokens_per_message() {
        let c = SpamClassifier::new(PathBuf::from("unused"));
        let text: String = (0..5000).map(|i| format!("tok{} ", i)).collect();
        assert!(text.len() <= MAX_LEARN_MESSAGE_BYTES);
        c.learn_spam(&text).await;
        let tokens = c.tokens.read().await;
        assert!(tokens.len() <= MAX_TOKENS_PER_LEARN, "{}", tokens.len());
        // Feature tokens survive the cap.
        assert!(tokens.contains_key("__NO_DATE"));
    }

    #[tokio::test]
    async fn vocabulary_cap_evicts_lowest_count_tokens() {
        let mut c = SpamClassifier::new(PathBuf::from("unused"));
        c.max_vocabulary = 100;
        // A frequent token that must survive.
        for _ in 0..5 {
            c.learn_ham("keepme").await;
        }
        for batch in 0..10 {
            let text: String = (0..30).map(|i| format!("w{}x{} ", batch, i)).collect();
            c.learn_spam(&text).await;
            assert!(c.tokens.read().await.len() <= 100);
        }
        let tokens = c.tokens.read().await;
        assert!(tokens.contains_key("keepme"));
    }

    #[test]
    fn prune_vocabulary_hits_target() {
        let mut m: HashMap<String, TokenStats> = HashMap::new();
        for i in 0..1100u64 {
            m.insert(
                format!("t{}", i),
                TokenStats {
                    spam_count: i % 7,
                    ham_count: 0,
                },
            );
        }
        prune_vocabulary(&mut m, 1000);
        assert_eq!(m.len(), 900);
        // Lowest counts go first: no zero-count token survives.
        assert_eq!(m.values().filter(|s| s.spam_count == 0).count(), 0);
    }

    #[test]
    fn test_from_domain_multibyte_no_panic() {
        let long = "ü".repeat(60);
        let raw = format!("From: x@{}\nSubject: hi\n\nbody", long);
        let _ = features(&raw);
        let t = features("From: spammer@evil.xyz\nSubject: hi\n\nbody");
        assert!(t.contains(&"__SUSPICIOUS_TLD_.xyz".to_string()));
    }
}
