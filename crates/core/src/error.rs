use thiserror::Error;

#[derive(Debug, Error)]
pub enum TcError {
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON: {0}")]
    Json(#[from] serde_json::Error),

    #[error("YAML: {0}")]
    Yaml(String),

    #[error("config: {0}")]
    Config(String),

    #[error("unsupported: {0}")]
    Unsupported(String),

    #[error("blocked: {0}")]
    Blocked(String),

    #[error("invalid state: {0}")]
    InvalidState(String),

    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, TcError>;
