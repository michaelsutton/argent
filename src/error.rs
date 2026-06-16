use std::fmt;
use std::path::PathBuf;

#[derive(Debug)]
pub struct ArgentError {
    pub path: Option<PathBuf>,
    pub message: String,
}

impl ArgentError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            path: None,
            message: message.into(),
        }
    }

    pub fn at(path: impl Into<PathBuf>, message: impl Into<String>) -> Self {
        Self {
            path: Some(path.into()),
            message: message.into(),
        }
    }
}

impl fmt::Display for ArgentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(path) = &self.path {
            write!(f, "{}: {}", path.display(), self.message)
        } else {
            f.write_str(&self.message)
        }
    }
}

impl std::error::Error for ArgentError {}

impl From<std::io::Error> for ArgentError {
    fn from(value: std::io::Error) -> Self {
        Self::new(value.to_string())
    }
}

pub type Result<T> = std::result::Result<T, ArgentError>;
