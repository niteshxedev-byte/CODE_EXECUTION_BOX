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
}

impl AppState {
    pub fn new() -> Self {
        let mut lang_map = HashMap::new();
        for lang in get_supported_languages() {
            lang_map.insert(lang.id, lang);
        }

        let sandbox = SandboxConfig::init();

        Self {
            languages: Arc::new(lang_map),
            submissions: Arc::new(RwLock::new(HashMap::new())),
            abort_handles: Arc::new(RwLock::new(HashMap::new())),
            sandbox,
        }
    }
}

