use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};
use tokio::task::AbortHandle;

use crate::{
    models::{
        language::{get_supported_languages, Language},
        submission::SubmissionRecord,
    },
    services::sandbox::SandboxConfig,
};

#[derive(Clone)]
pub struct AppState {
    pub languages: Arc<HashMap<u32, Language>>,
    pub submissions: Arc<RwLock<HashMap<String, SubmissionRecord>>>,
    pub abort_handles: Arc<RwLock<HashMap<String, AbortHandle>>>,
    pub sandbox: SandboxConfig,
    pub allowed_origins: Arc<Vec<String>>,
    pub allowed_hosts: Arc<Vec<String>>,
    pub auth_token: Option<String>,
}

impl AppState {
    pub fn new() -> Self {
        let mut lang_map = HashMap::new();
        for lang in get_supported_languages() {
            lang_map.insert(lang.id, lang);
        }

        let sandbox = SandboxConfig::init();
        let (allowed_origins, allowed_hosts, auth_token) = Self::parse_url_auth();

        Self {
            languages: Arc::new(lang_map),
            submissions: Arc::new(RwLock::new(HashMap::new())),
            abort_handles: Arc::new(RwLock::new(HashMap::new())),
            sandbox,
            allowed_origins: Arc::new(allowed_origins),
            allowed_hosts: Arc::new(allowed_hosts),
            auth_token,
        }
    }

    fn parse_url_auth() -> (Vec<String>, Vec<String>, Option<String>) {
        let raw_urls = std::env::var("PUBLIC_URL")
            .or_else(|_| std::env::var("ALLOWED_ORIGIN"))
            .or_else(|_| std::env::var("ALLOWED_ORIGINS"))
            .or_else(|_| std::env::var("ALLOWED_URL"))
            .unwrap_or_else(|_| "http://localhost:3000,http://localhost:3001,http://127.0.0.1:3000".to_string());

        let auth_token = std::env::var("AUTH_TOKEN")
            .or_else(|_| std::env::var("CODEBOX_AUTH_TOKEN"))
            .ok()
            .filter(|t| !t.trim().is_empty());

        let mut origins = Vec::new();
        let mut hosts = vec![
            "localhost".to_string(),
            "localhost:3000".to_string(),
            "127.0.0.1".to_string(),
            "127.0.0.1:3000".to_string(),
        ];

        for part in raw_urls.split(',') {
            let trimmed = part.trim();
            if trimmed.is_empty() {
                continue;
            }
            let clean = trimmed.trim_end_matches('/');
            origins.push(clean.to_string());

            if let Some(without_scheme) = clean.strip_prefix("http://").or_else(|| clean.strip_prefix("https://")) {
                let host_part = without_scheme.split('/').next().unwrap_or(without_scheme);
                hosts.push(host_part.to_string());
                if let Some((domain, _port)) = host_part.split_once(':') {
                    hosts.push(domain.to_string());
                }
            } else {
                hosts.push(clean.to_string());
            }
        }

        origins.sort();
        origins.dedup();
        hosts.sort();
        hosts.dedup();

        (origins, hosts, auth_token)
    }
}

