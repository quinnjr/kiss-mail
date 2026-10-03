//! Anti-spam detection module.
//!
//! Implements a hybrid spam detection system combining:
//! - Rule-based scoring (heuristics)
//! - AI/Bayesian classification (learned patterns)

use crate::spam_ai::{SpamClassification, SpamClassifier, is_url_shortener, url_hosts};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// Spam detection result
#[derive(Debug, Clone)]
pub struct SpamResult {
    /// Rule-based score
    pub score: f32,
    /// AI probability (0.0 - 1.0)
    pub ai_probability: f64,
    /// Combined spam determination
    pub is_spam: bool,
    /// Rule-based reasons
    pub reasons: Vec<String>,
    /// AI spam indicators
    pub ai_spam_indicators: Vec<(String, f64)>,
    /// AI ham indicators
    pub ai_ham_indicators: Vec<(String, f64)>,
    /// AI confidence
    pub ai_confidence: f64,
}

impl SpamResult {
    pub fn new() -> Self {
        Self {
            score: 0.0,
            ai_probability: 0.5,
            is_spam: false,
            reasons: Vec::new(),
            ai_spam_indicators: Vec::new(),
            ai_ham_indicators: Vec::new(),
            ai_confidence: 0.0,
        }
    }

    pub fn add_score(&mut self, points: f32, reason: &str) {
        self.score += points;
        if points > 0.0 {
            self.reasons.push(format!("{} (+{:.1})", reason, points));
        }
    }

    pub fn set_ai_classification(&mut self, classification: SpamClassification) {
        self.ai_probability = classification.spam_probability;
        self.ai_spam_indicators = classification.spam_indicators;
        self.ai_ham_indicators = classification.ham_indicators;
        self.ai_confidence = classification.confidence;
    }

    /// Decide `is_spam`.
    ///
    /// The message is spam if ANY of these hold:
    /// 1. weighted average `rules/10 * (1 - ai_weight) + ai_probability * ai_weight`
    ///    (defaults: 40% rules, 60% AI) is `>= ai_threshold`;
    /// 2. the rule score alone is `>= rule_threshold` (default 5.0) — hard override;
    /// 3. the AI is very sure: `ai_probability > 0.9 && ai_confidence > 0.8`.
    pub fn finalize(&mut self, rule_threshold: f32, ai_threshold: f64, ai_weight: f64) {
        // Combine rule-based and AI scores
        // - Rule score is normalized to 0-1 range (assuming max score of 10)
        // - AI probability is already 0-1
        // - Combined using weighted average

        let rule_normalized = (self.score / 10.0).clamp(0.0, 1.0) as f64;
        let combined = rule_normalized * (1.0 - ai_weight) + self.ai_probability * ai_weight;

        // Spam if:
        // 1. Combined score exceeds threshold, OR
        // 2. Rule score alone exceeds threshold (hard rules), OR
        // 3. AI is very confident it's spam (>0.9 with high confidence)
        self.is_spam = combined >= ai_threshold
            || self.score >= rule_threshold
            || (self.ai_probability > 0.9 && self.ai_confidence > 0.8);
    }
}

/// Rate limiter for tracking sender frequency
#[derive(Debug)]
struct RateLimitEntry {
    count: u32,
    first_seen: Instant,
}

/// Sender rate tracking state
#[derive(Debug)]
struct RateLimitState {
    entries: HashMap<String, RateLimitEntry>,
    /// Last time expired entries were pruned
    last_prune: Instant,
}

/// Minimum interval between prunes of the rate-limit map
const RATE_LIMIT_PRUNE_INTERVAL: Duration = Duration::from_secs(60);

/// Anti-spam checker
#[derive(Debug)]
pub struct AntiSpam {
    /// Rule-based spam score threshold (default: 5.0)
    pub threshold: f32,
    /// AI spam probability threshold (default: 0.7)
    pub ai_threshold: f64,
    /// Weight given to AI vs rules (0.0 = rules only, 1.0 = AI only, default: 0.6)
    pub ai_weight: f64,
    /// Rate limit window in seconds
    rate_limit_window: Duration,
    /// Max emails per window
    rate_limit_max: u32,
    /// Sender rate tracking
    rate_limits: Arc<RwLock<RateLimitState>>,
    /// Blocked keywords (case-insensitive)
    blocked_keywords: Vec<String>,
    /// Suspicious URL patterns (substring match on lowercased content).
    /// URL shorteners are matched separately on the parsed URL host.
    suspicious_url_patterns: Vec<String>,
    /// AI spam classifier
    ai_classifier: Arc<SpamClassifier>,
}

impl AntiSpam {
    pub fn new(data_dir: PathBuf) -> Self {
        Self {
            threshold: 5.0,
            ai_threshold: 0.7,
            ai_weight: 0.6, // 60% AI, 40% rules
            rate_limit_window: Duration::from_secs(60),
            rate_limit_max: 10,
            rate_limits: Arc::new(RwLock::new(RateLimitState {
                entries: HashMap::new(),
                last_prune: Instant::now(),
            })),
            ai_classifier: Arc::new(SpamClassifier::new(data_dir)),
            blocked_keywords: vec![
                // Common spam keywords
                "viagra".to_string(),
                "cialis".to_string(),
                "casino".to_string(),
                "lottery".to_string(),
                "winner".to_string(),
                "nigerian prince".to_string(),
                "wire transfer".to_string(),
                "bank account".to_string(),
                "credit card".to_string(),
                "act now".to_string(),
                "limited time".to_string(),
                "free money".to_string(),
                "make money fast".to_string(),
                "work from home".to_string(),
                "double your".to_string(),
                "million dollars".to_string(),
                "you have won".to_string(),
                "congratulations".to_string(),
                "claim your prize".to_string(),
                "urgent response".to_string(),
                "dear friend".to_string(),
                "100% free".to_string(),
                "no obligation".to_string(),
                "risk free".to_string(),
            ],
            suspicious_url_patterns: vec!["click here".to_string(), "click now".to_string()],
        }
    }

    /// Load AI classifier data
    pub async fn load(&self) -> Result<(), std::io::Error> {
        self.ai_classifier.load().await
    }

    /// Check an email for spam indicators
    pub async fn check(&self, from: &str, to: &[String], raw_email: &str) -> SpamResult {
        let mut result = SpamResult::new();
        let raw_lower = raw_email.to_lowercase();

        // 1. AI Classification (Bayesian)
        let ai_classification = self.ai_classifier.classify(raw_email).await;
        result.set_ai_classification(ai_classification);

        // 2. Check rate limiting
        if self.check_rate_limit(from).await {
            result.add_score(3.0, "Rate limit exceeded");
        }

        // 3. Check sender address
        self.check_sender(from, &mut result);

        // 4. Check recipients
        self.check_recipients(to, &mut result);

        // 5. Check headers
        self.check_headers(&raw_lower, &mut result);

        // 6. Check content for spam keywords
        self.check_keywords(&raw_lower, &mut result);

        // 7. Check for suspicious URLs
        self.check_urls(&raw_lower, &mut result);

        // 8. Check formatting/structure
        self.check_structure(raw_email, &raw_lower, &mut result);

        // 9. Check for common spam patterns
        self.check_patterns(&raw_lower, &mut result);

        // Finalize with combined rule + AI scoring
        result.finalize(self.threshold, self.ai_threshold, self.ai_weight);

        if result.is_spam {
            tracing::warn!(
                "Spam detected from {} (rules: {:.1}, AI: {:.1}%): {:?}",
                from,
                result.score,
                result.ai_probability * 100.0,
                result.reasons
            );
        } else {
            tracing::debug!(
                "Spam score for {}: rules={:.1}, AI={:.1}%",
                from,
                result.score,
                result.ai_probability * 100.0
            );
        }

        result
    }

    /// Train the AI classifier with a spam email.
    ///
    /// Learned data is persisted in batches (every 20 learns, or when more
    /// than 60s have passed since the last save), not on every call.
    /// Returns `false` if the message was not learned (over the size cap;
    /// see [`crate::spam_ai::should_learn_from`]). Per-message token and
    /// total vocabulary caps are enforced by the classifier.
    pub async fn learn_spam(&self, email: &str) -> bool {
        let learned = self.ai_classifier.learn_spam(email).await;
        if learned {
            self.ai_classifier.maybe_save().await;
        }
        learned
    }

    /// Train the AI classifier with a ham (non-spam) email.
    ///
    /// Persistence and caps as for [`AntiSpam::learn_spam`].
    pub async fn learn_ham(&self, email: &str) -> bool {
        let learned = self.ai_classifier.learn_ham(email).await;
        if learned {
            self.ai_classifier.maybe_save().await;
        }
        learned
    }

    /// Persist any unsaved learned data now (e.g. on shutdown).
    pub async fn flush(&self) -> Result<(), std::io::Error> {
        self.ai_classifier.save().await
    }

    /// Get AI classifier statistics
    pub async fn ai_stats(&self) -> crate::spam_ai::ClassifierStats {
        self.ai_classifier.stats().await
    }

    async fn check_rate_limit(&self, sender: &str) -> bool {
        let sender_key = sender.to_lowercase();
        let mut state = self.rate_limits.write().await;
        let now = Instant::now();

        // Clean up old entries (at most once per minute)
        if now.duration_since(state.last_prune) >= RATE_LIMIT_PRUNE_INTERVAL {
            let window = self.rate_limit_window;
            state
                .entries
                .retain(|_, entry| now.duration_since(entry.first_seen) < window);
            state.last_prune = now;
        }
        let limits = &mut state.entries;

        if let Some(entry) = limits.get_mut(&sender_key) {
            if now.duration_since(entry.first_seen) < self.rate_limit_window {
                entry.count += 1;
                return entry.count > self.rate_limit_max;
            } else {
                // Reset window
                entry.count = 1;
                entry.first_seen = now;
            }
        } else {
            limits.insert(
                sender_key,
                RateLimitEntry {
                    count: 1,
                    first_seen: now,
                },
            );
        }

        false
    }

    fn check_sender(&self, from: &str, result: &mut SpamResult) {
        let from_lower = from.to_lowercase();

        // Empty sender
        if from.is_empty() {
            result.add_score(2.0, "Empty sender address");
        }

        // No @ in sender
        if !from.contains('@') {
            result.add_score(2.0, "Invalid sender format");
        }

        // Suspicious TLDs
        let suspicious_tlds = [".xyz", ".top", ".work", ".click", ".loan", ".racing"];
        for tld in &suspicious_tlds {
            if from_lower.ends_with(tld) {
                result.add_score(1.5, &format!("Suspicious TLD: {}", tld));
                break;
            }
        }

        // Numbers in domain (common in spam)
        if let Some(domain) = from_lower.split('@').nth(1) {
            let num_count = domain.chars().filter(|c| c.is_numeric()).count();
            if num_count > 3 {
                result.add_score(1.0, "Many numbers in sender domain");
            }
        }

        // Very long local part
        if let Some(local) = from.split('@').next() {
            if local.len() > 64 {
                result.add_score(1.0, "Unusually long sender local part");
            }
        }
    }

    fn check_recipients(&self, to: &[String], result: &mut SpamResult) {
        // Too many recipients
        if to.len() > 10 {
            result.add_score(2.0, "Too many recipients");
        }

        // Check for BCC indicators (recipients not in To/Cc headers)
        if to.is_empty() {
            result.add_score(1.5, "No recipients specified");
        }
    }

    /// `raw_lower` is the lowercased message.
    fn check_headers(&self, raw_lower: &str, result: &mut SpamResult) {
        let (headers, _) = crate::mime::split_headers_body(raw_lower);

        // Missing common headers
        if !headers.contains("date:") {
            result.add_score(1.0, "Missing Date header");
        }
        if !headers.contains("message-id:") {
            result.add_score(0.5, "Missing Message-ID header");
        }
        if !headers.contains("subject:") {
            result.add_score(0.5, "Missing Subject header");
        }

        // Suspicious headers
        if headers.contains("x-mailer: phpmailer") {
            result.add_score(1.0, "PHPMailer detected");
        }
        if headers.contains("x-priority: 1") || headers.contains("importance: high") {
            result.add_score(0.5, "High priority flag");
        }

        // Multiple received headers from same host (potential relay)
        let received_count = headers.matches("received:").count();
        if received_count > 10 {
            result.add_score(1.0, "Excessive relay hops");
        }

        // Check for forged headers
        if headers.contains("x-originating-ip: 127.0.0.1") {
            result.add_score(1.5, "Suspicious originating IP");
        }
    }

    fn check_keywords(&self, content: &str, result: &mut SpamResult) {
        let mut keyword_hits = 0;

        for keyword in &self.blocked_keywords {
            if content.contains(keyword) {
                keyword_hits += 1;
                if keyword_hits <= 3 {
                    result.add_score(0.5, &format!("Spam keyword: {}", keyword));
                }
            }
        }

        // Additional penalty for multiple keyword hits
        if keyword_hits > 3 {
            result.add_score((keyword_hits - 3) as f32 * 0.3, "Multiple spam keywords");
        }
    }

    fn check_urls(&self, content: &str, result: &mut SpamResult) {
        // Parse URL hosts once; every URL check below uses them.
        let hosts = url_hosts(content);

        if hosts.len() > 5 {
            result.add_score(1.0, "Many URLs in message");
        }

        // URL shorteners and suspicious TLDs, matched on the parsed host
        if let Some(h) = hosts.iter().find(|h| is_url_shortener(h)) {
            result.add_score(1.0, &format!("URL shortener: {}", h));
        }
        for tld in [".ru", ".cn"] {
            if hosts.iter().any(|h| h.ends_with(tld)) {
                result.add_score(1.0, &format!("Suspicious URL TLD: {}", tld));
            }
        }

        // Other suspicious patterns
        for pattern in &self.suspicious_url_patterns {
            if content.contains(pattern) {
                result.add_score(1.0, &format!("Suspicious URL pattern: {}", pattern));
            }
        }

        // IP-literal URL hosts (common in phishing)
        if hosts.iter().any(|h| {
            h.trim_start_matches('[')
                .trim_end_matches(']')
                .parse::<std::net::IpAddr>()
                .is_ok()
        }) {
            result.add_score(2.0, "IP-based URL detected");
        }
    }

    /// Find the (unfolded) Subject header value in the original message,
    /// matching the header name ASCII case-insensitively.
    fn find_subject(raw: &str) -> Option<String> {
        let (headers, _) = crate::mime::split_headers_body(raw);
        let headers = crate::mime::parse_headers(headers);
        crate::mime::header(&headers, "subject").map(str::to_string)
    }

    /// `raw` is the original message, `content_lower` its lowercased form.
    fn check_structure(&self, raw: &str, content_lower: &str, result: &mut SpamResult) {
        // ALL CAPS subject
        if let Some(subject) = Self::find_subject(raw).as_deref() {
            let caps_ratio = subject.chars().filter(|c| c.is_uppercase()).count() as f32
                / subject.chars().filter(|c| c.is_alphabetic()).count().max(1) as f32;

            if caps_ratio > 0.7 && subject.len() > 10 {
                result.add_score(1.0, "Subject mostly uppercase");
            }
        }

        // Check for excessive punctuation (!!!!, ????, etc)
        let exclamation_count = raw.matches('!').count();
        let question_count = raw.matches('?').count();
        let dollar_count = raw.matches('$').count();

        if exclamation_count > 5 {
            result.add_score(0.5, "Excessive exclamation marks");
        }
        if dollar_count > 3 {
            result.add_score(0.5, "Multiple dollar signs");
        }
        if question_count > 10 {
            result.add_score(0.3, "Many question marks");
        }

        // Very short body (typical of spam probes)
        let (_, body) = crate::mime::split_headers_body(raw);
        if body.trim().len() < 20 && body.contains("http") {
            result.add_score(1.5, "Short body with URL");
        }

        // HTML-only email (no text alternative)
        if content_lower.contains("content-type: text/html")
            && !content_lower.contains("content-type: text/plain")
            && !content_lower.contains("multipart/alternative")
        {
            result.add_score(0.5, "HTML-only email");
        }

        // Invisible/hidden text (common spam trick)
        if content_lower.contains("font-size:0")
            || content_lower.contains("font-size: 0")
            || content_lower.contains("display:none")
            || content_lower.contains("visibility:hidden")
        {
            result.add_score(2.0, "Hidden text detected");
        }
    }

    fn check_patterns(&self, content: &str, result: &mut SpamResult) {
        // Common spam phrases
        let spam_phrases = [
            ("dear valued customer", 1.5),
            ("verify your account", 1.5),
            ("suspended your account", 2.0),
            ("confirm your identity", 1.5),
            ("unusual activity", 1.0),
            ("click the link below", 1.0),
            ("act immediately", 1.0),
            ("your account will be", 1.0),
            ("within 24 hours", 0.5),
            ("within 48 hours", 0.5),
            ("you have been selected", 1.5),
            ("exclusive offer", 0.5),
            ("free gift", 1.0),
            ("no credit check", 1.5),
            ("as seen on", 0.5),
            ("order now", 0.5),
            ("supplies are limited", 0.5),
            ("what are you waiting for", 0.5),
            ("call now", 0.5),
            ("apply now", 0.5),
            ("increase your", 0.5),
            ("lower your", 0.5),
            ("eliminate debt", 1.5),
            ("refinance", 0.5),
            ("pharmacy", 1.0),
            ("prescription", 0.5),
        ];

        for (phrase, score) in &spam_phrases {
            if content.contains(phrase) {
                result.add_score(*score, &format!("Spam phrase: {}", phrase));
            }
        }

        // Base64 encoded executable attachments
        if content.contains("content-transfer-encoding: base64")
            && (content.contains(".exe")
                || content.contains(".scr")
                || content.contains(".bat")
                || content.contains(".cmd")
                || content.contains(".js\"")
                || content.contains(".vbs"))
        {
            result.add_score(5.0, "Executable attachment detected");
        }

        // Phishing patterns
        if (content.contains("paypal")
            || content.contains("amazon")
            || content.contains("apple")
            || content.contains("microsoft"))
            && (content.contains("verify")
                || content.contains("confirm")
                || content.contains("suspended"))
        {
            result.add_score(2.0, "Possible phishing attempt");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_clean_email() {
        let dir = tempdir().unwrap();
        let antispam = AntiSpam::new(dir.path().to_path_buf());
        let _ = antispam.load().await;

        let result = antispam
            .check(
                "user@example.com",
                &["recipient@example.com".to_string()],
                "From: user@example.com\r\nTo: recipient@example.com\r\nSubject: Hello\r\nDate: Mon, 1 Jan 2024 00:00:00 +0000\r\nMessage-ID: <123@example.com>\r\n\r\nHello, how are you?",
            )
            .await;

        assert!(!result.is_spam);
        assert!(result.score < 5.0);
    }

    #[tokio::test]
    async fn test_spam_email() {
        let dir = tempdir().unwrap();
        let antispam = AntiSpam::new(dir.path().to_path_buf());
        let _ = antispam.load().await;

        let result = antispam
            .check(
                "spammer@suspicious.xyz",
                &["victim@example.com".to_string()],
                "Subject: YOU HAVE WON!!!! CLAIM YOUR PRIZE NOW!!!!\r\n\r\nDear Friend,\r\n\r\nCongratulations! You have won the lottery! Click here to claim your million dollars: http://bit.ly/scam\r\n\r\nAct now! Limited time offer! Wire transfer required.",
            )
            .await;

        assert!(result.is_spam);
    }

    #[test]
    fn test_check_structure_non_ascii_header_no_panic() {
        let dir = tempdir().unwrap();
        let antispam = AntiSpam::new(dir.path().to_path_buf());
        // 'İ' lowercases to a longer UTF-8 sequence; the old code sliced the
        // original with an index from the lowercased copy.
        let raw = "X-Name: İİİİİİİİ ǅ ẞ\r\nSubject: THIS IS A VERY LOUD SUBJECT\r\n\r\nbody";
        let lower = raw.to_lowercase();
        let mut result = SpamResult::new();
        antispam.check_structure(raw, &lower, &mut result);
        assert!(
            result.reasons.iter().any(|r| r.contains("uppercase")),
            "{:?}",
            result.reasons
        );
        assert_eq!(
            AntiSpam::find_subject("SUBJECT: Hi\r\n\r\nSubject: body").as_deref(),
            Some("Hi")
        );
        assert_eq!(
            AntiSpam::find_subject("Subject: Hello\r\n World\r\n\r\nbody").as_deref(),
            Some("Hello World")
        );
        assert_eq!(AntiSpam::find_subject("From: a\n\nSubject: in body"), None);
    }

    #[test]
    fn test_check_urls_shortener_exact_host() {
        let dir = tempdir().unwrap();
        let antispam = AntiSpam::new(dir.path().to_path_buf());

        let mut r = SpamResult::new();
        antispam.check_urls(
            "see https://www.microsoft.com/t.co/x and http://reddit.co",
            &mut r,
        );
        assert!(
            !r.reasons.iter().any(|x| x.contains("shortener")),
            "{:?}",
            r.reasons
        );

        let mut r = SpamResult::new();
        antispam.check_urls("go to https://t.co/abc", &mut r);
        assert!(r.reasons.iter().any(|x| x.contains("shortener")));
    }

    #[test]
    fn test_check_urls_ip_hosts_and_count() {
        let dir = tempdir().unwrap();
        let antispam = AntiSpam::new(dir.path().to_path_buf());

        for url in [
            "http://192.168.1.5/login",
            "https://8.8.8.8/x",
            "http://user@10.0.0.1:8080/",
            "http://[2001:db8::1]/",
        ] {
            let mut r = SpamResult::new();
            antispam.check_urls(url, &mut r);
            assert!(
                r.reasons.iter().any(|x| x.contains("IP-based URL")),
                "{}: {:?}",
                url,
                r.reasons
            );
        }
        // Hostnames that merely start with digits are not IPs.
        let mut r = SpamResult::new();
        antispam.check_urls("http://10.example.com/ http://172x.net/", &mut r);
        assert!(!r.reasons.iter().any(|x| x.contains("IP-based URL")));

        // Count is the number of parsed URLs.
        let mut r = SpamResult::new();
        let many: String = (0..6)
            .map(|i| format!("https://h{}.example.com ", i))
            .collect();
        antispam.check_urls(&many, &mut r);
        assert!(r.reasons.iter().any(|x| x.contains("Many URLs")));
        let mut r = SpamResult::new();
        antispam.check_urls("http:// http:// http:// http:// http:// http://", &mut r);
        assert!(!r.reasons.iter().any(|x| x.contains("Many URLs")));
    }

    #[tokio::test]
    async fn test_unsubscribe_not_spam_keyword() {
        let dir = tempdir().unwrap();
        let antispam = AntiSpam::new(dir.path().to_path_buf());
        let mut r = SpamResult::new();
        antispam.check_keywords("click to unsubscribe from this newsletter", &mut r);
        assert_eq!(r.score, 0.0);
    }

    #[tokio::test]
    async fn test_learning_persistence_is_debounced() {
        let dir = tempdir().unwrap();
        let antispam = AntiSpam::new(dir.path().to_path_buf());
        antispam.load().await.unwrap();
        let path = dir.path().join("spam_classifier.json");
        let total_spam = || -> u64 {
            let v: serde_json::Value =
                serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
            v["total_spam"].as_u64().unwrap()
        };
        let initial = total_spam();
        let initial_ham = {
            let v: serde_json::Value =
                serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
            v["total_ham"].as_u64().unwrap()
        };
        for _ in 0..19 {
            antispam.learn_spam("buy cheap pills now").await;
        }
        assert_eq!(total_spam(), initial, "should not save on every learn");
        antispam.learn_spam("buy cheap pills now").await;
        assert_eq!(total_spam(), initial + 20, "should save after 20 learns");

        antispam.learn_ham("meeting notes attached").await;
        antispam.flush().await.unwrap();
        let v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(v["total_ham"].as_u64().unwrap(), initial_ham + 1);
    }
}
