//! Watch mode: stream filesystem events and report drift in near-real
//! time. Uses `notify` for the platform watcher; events are debounced by
//! draining the channel and reporting the touched relative paths.

use crate::{Result, FABRIC_DIR};
use notify::{RecursiveMode, Watcher};
use std::path::Path;

/// Same rule as snapshot/drift: fabric internals and .git are excluded
/// by component, not by prefix (so `.github` still reports).
fn is_tracked(rel: &Path) -> bool {
    rel.components().all(|c| {
        let s = c.as_os_str().to_string_lossy();
        s != FABRIC_DIR && s != ".git"
    })
}
use std::sync::mpsc::channel;
use std::time::Duration;

/// Run a blocking watch loop over `root`, printing changed paths.
/// `on_event` receives deduplicated relative paths per debounce window.
pub fn watch_loop<F: FnMut(Vec<String>)>(root: &Path, mut on_event: F) -> Result<()> {
    let (tx, rx) = channel();
    let mut watcher = notify::recommended_watcher(move |res| {
        let _ = tx.send(res);
    })
    .map_err(|e| crate::Error::Sync(format!("watcher: {e}")))?;
    watcher
        .watch(root, RecursiveMode::Recursive)
        .map_err(|e| crate::Error::Sync(format!("watch {root:?}: {e}")))?;

    loop {
        // Block for the first event, then drain a 250ms debounce window.
        let first = rx.recv();
        if first.is_err() {
            return Ok(()); // watcher dropped
        }
        let mut paths = std::collections::HashSet::new();
        let deadline = std::time::Instant::now() + Duration::from_millis(250);
        loop {
            match rx.recv_timeout(deadline.saturating_duration_since(std::time::Instant::now())) {
                Ok(Ok(event)) => {
                    for p in event.paths {
                        if let Ok(rel) = p.strip_prefix(root) {
                            if is_tracked(rel) {
                                paths.insert(rel.to_string_lossy().replace('\\', "/"));
                            }
                        }
                    }
                }
                Ok(Err(_)) => {}
                Err(_) => break, // window elapsed
            }
            if std::time::Instant::now() >= deadline {
                break;
            }
        }
        // Include the first event too.
        if let Ok(Ok(event)) = &first {
            for p in &event.paths {
                if let Ok(rel) = p.strip_prefix(root) {
                    if is_tracked(rel) {
                        paths.insert(rel.to_string_lossy().replace('\\', "/"));
                    }
                }
            }
        }
        if !paths.is_empty() {
            let mut v: Vec<String> = paths.into_iter().collect();
            v.sort();
            on_event(v);
        }
    }
}
