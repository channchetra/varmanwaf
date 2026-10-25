// Copyright 2024-2025 Tree xie.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Filesystem helpers shared by the file backend and the quota ledger.

use std::path::{Path, PathBuf};
use walkdir::WalkDir;

/// Removes empty directories below `dir`, deepest first.
///
/// `remove_dir` fails on a non-empty directory, which is exactly the guard
/// wanted: concurrent writers keep their parent alive, and stale empty
/// directories are cleaned up.
pub(crate) fn remove_empty_dirs(dir: &Path) {
    let mut dirs: Vec<PathBuf> = WalkDir::new(dir)
        .into_iter()
        .filter_map(|item| item.ok())
        .filter(|item| item.file_type().is_dir())
        .map(|item| item.into_path())
        .collect();
    dirs.sort_by_key(|path| std::cmp::Reverse(path.components().count()));
    for dir in dirs {
        let _ = std::fs::remove_dir(&dir);
    }
}
