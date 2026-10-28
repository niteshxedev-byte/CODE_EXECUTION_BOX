use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Status {
    pub id: u32,
    pub description: String,
}

impl Status {
    pub fn in_queue() -> Self {
        Self {
            id: 1,
            description: "In Queue".to_string(),
        }
    }

    pub fn processing() -> Self {
        Self {
            id: 2,
            description: "Processing".to_string(),
        }
    }

    pub fn accepted() -> Self {
        Self {
            id: 3,
            description: "Accepted".to_string(),
        }
    }

    pub fn wrong_answer() -> Self {
        Self {
            id: 4,
            description: "Wrong Answer".to_string(),
        }
    }

    pub fn time_limit_exceeded() -> Self {
        Self {
            id: 5,
            description: "Time Limit Exceeded".to_string(),
        }
    }

    pub fn compilation_error() -> Self {
        Self {
            id: 6,
            description: "Compilation Error".to_string(),
        }
    }

    pub fn runtime_error(detail: &str) -> Self {
        Self {
            id: 7,
            description: format!("Runtime Error ({detail})"),
        }
    }

    pub fn internal_error(detail: &str) -> Self {
        Self {
            id: 8,
            description: format!("Internal Error: {detail}"),
        }
    }

    pub fn exec_format_error() -> Self {
        Self {
            id: 9,
            description: "Exec Format Error".to_string(),
        }
    }

    pub fn cancelled() -> Self {
        Self {
            id: 10,
            description: "Cancelled".to_string(),
        }
    }
}

pub fn get_all_statuses() -> Vec<Status> {
    vec![
        Status::in_queue(),
        Status::processing(),
        Status::accepted(),
        Status::wrong_answer(),
        Status::time_limit_exceeded(),
        Status::compilation_error(),
        Status {
            id: 7,
            description: "Runtime Error (Non-zero exit code)".to_string(),
        },
        Status {
            id: 8,
            description: "Internal Error".to_string(),
        },
        Status::exec_format_error(),
        Status::cancelled(),
    ]
}
