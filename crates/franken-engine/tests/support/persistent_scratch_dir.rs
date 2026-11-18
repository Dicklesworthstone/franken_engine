//! Rule-1-compliant non-deleting scratch directory for integration tests.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

pub struct ScratchDir {
    path: PathBuf,
}

impl ScratchDir {
    pub fn new(prefix: &str) -> Self {
        static NEXT_ID: AtomicU64 = AtomicU64::new(0);
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock after unix epoch")
            .as_nanos();
        let seq = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "fe_test_{prefix}_{}_{nonce}_{seq}",
            std::process::id()
        ));
        std::fs::create_dir_all(&path).expect("create persistent scratch dir");
        Self { path }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}
