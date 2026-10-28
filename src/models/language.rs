use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Language {
    pub id: u32,
    pub name: String,
    pub is_archived: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compiler_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_file: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compile_cmd: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run_cmd: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extension: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LanguageSummary {
    pub id: u32,
    pub name: String,
    pub is_archived: bool,
}

impl From<&Language> for LanguageSummary {
    fn from(lang: &Language) -> Self {
        Self {
            id: lang.id,
            name: lang.name.clone(),
            is_archived: lang.is_archived,
        }
    }
}

pub fn get_supported_languages() -> Vec<Language> {
    vec![
        Language {
            id: 71,
            name: "Python (3.x)".to_string(),
            is_archived: false,
            compiler_version: Some("Python 3.x".to_string()),
            source_file: Some("script.py".to_string()),
            compile_cmd: None,
            run_cmd: Some("python3 script.py".to_string()),
            extension: Some("py".to_string()),
        },
        Language {
            id: 63,
            name: "JavaScript (Node.js)".to_string(),
            is_archived: false,
            compiler_version: Some("Node.js".to_string()),
            source_file: Some("index.js".to_string()),
            compile_cmd: None,
            run_cmd: Some("node index.js".to_string()),
            extension: Some("js".to_string()),
        },
        Language {
            id: 73,
            name: "Rust (rustc)".to_string(),
            is_archived: false,
            compiler_version: Some("rustc 1.98.1".to_string()),
            source_file: Some("main.rs".to_string()),
            compile_cmd: Some("rustc -O -o main main.rs".to_string()),
            run_cmd: Some("./main".to_string()),
            extension: Some("rs".to_string()),
        },
        Language {
            id: 50,
            name: "C (GCC)".to_string(),
            is_archived: false,
            compiler_version: Some("GCC".to_string()),
            source_file: Some("main.c".to_string()),
            compile_cmd: Some("gcc -O2 -o main main.c".to_string()),
            run_cmd: Some("./main".to_string()),
            extension: Some("c".to_string()),
        },
        Language {
            id: 54,
            name: "C++ (G++)".to_string(),
            is_archived: false,
            compiler_version: Some("G++ (std=c++17)".to_string()),
            source_file: Some("main.cpp".to_string()),
            compile_cmd: Some("g++ -O2 -std=c++17 -o main main.cpp".to_string()),
            run_cmd: Some("./main".to_string()),
            extension: Some("cpp".to_string()),
        },
        Language {
            id: 46,
            name: "Bash".to_string(),
            is_archived: false,
            compiler_version: Some("GNU Bash".to_string()),
            source_file: Some("script.sh".to_string()),
            compile_cmd: None,
            run_cmd: Some("bash script.sh".to_string()),
            extension: Some("sh".to_string()),
        },
        Language {
            id: 62,
            name: "Java (OpenJDK)".to_string(),
            is_archived: false,
            compiler_version: Some("OpenJDK".to_string()),
            source_file: Some("Main.java".to_string()),
            compile_cmd: Some("javac Main.java".to_string()),
            run_cmd: Some("java Main".to_string()),
            extension: Some("java".to_string()),
        },
    ]
}
