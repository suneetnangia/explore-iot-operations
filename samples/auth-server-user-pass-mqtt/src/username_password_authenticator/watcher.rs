// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![deny(rust_2018_idioms)]
#![warn(clippy::all, clippy::pedantic)]
#![allow(
    clippy::default_trait_access,
    clippy::let_unit_value,
    clippy::missing_errors_doc,
    clippy::must_use_candidate,
    clippy::module_name_repetitions,
    clippy::let_underscore_untyped,
    let_underscore_drop
)]

use std::{
    fmt::Debug,
    path::{Path, PathBuf},
    sync::{Arc, OnceLock},
    time::Duration,
};

use notify_debouncer_mini::{
    new_debouncer,
    notify::{INotifyWatcher, RecursiveMode},
    Debouncer,
};
use parking_lot::RwLock;
use tokio::sync::mpsc::Sender;
use anyhow::Result;

pub type Parser<T> = Box<dyn Fn(&Path) -> Result<T> + Send + Sync>;
pub type FileWatcherInstance<T> = Arc<FileWatcher<T>>;

pub struct FileWatcher<T> {
    pub contents: RwLock<T>,
    path: PathBuf,
    file_reader: Parser<T>,
    sender: Option<Sender<()>>,
    watcher: OnceLock<Debouncer<INotifyWatcher>>,
}

impl<T> FileWatcher<T>
where
    T: Send + Sync + 'static,
{
    pub fn new<P: AsRef<Path>>(
        path: P,
        parser: Parser<T>,
        sender: Option<Sender<()>>,
    ) -> Result<Arc<Self>> {
        let config = parser(path.as_ref())?;
        let watcher = Arc::new(Self {
            path: path.as_ref().to_path_buf(),
            file_reader: parser,
            sender,
            contents: RwLock::new(config),
            watcher: OnceLock::new(),
        });
        watcher.init_watcher()?;

        Ok(watcher)
    }

    fn init_watcher(self: &Arc<Self>) -> Result<()> {
        let inner = self.clone();
        let handler = move |res| match res {
            Ok(_events) => {
                inner.on_change();
            }
            Err(e) => log::error!("watch error: {e:?}"),
        };

        let mut debouncer = new_debouncer(Duration::from_secs(1), None, handler)?;
        debouncer
            .watcher()
            .watch(&self.path, RecursiveMode::NonRecursive)?;

        self.watcher
            .set(debouncer)
            .map_err(|_| anyhow::anyhow!("Error occurred in watcher."))?;
        Ok(())
    }

    fn on_change(&self) {
        log::debug!("detected change in {}", self.path.display());

        if let Err(e) = self.set_contents() {
            log::error!("set config error: {e:?}");
        } else if let Some(sender) = self.sender.as_ref() {
            let _result = sender.try_send(());
        }
    }

    fn set_contents(&self) -> Result<()> {
        let mut contents = self.contents.write();
        let new_contents: T = (self.file_reader)(&self.path)?;
        *contents = new_contents;
        Ok(())
    }
}

impl<T> Debug for FileWatcher<T>
where
    T: Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let contents = self.contents.read();
        let contents: &T = &contents;
        f.debug_struct("FileWatcher")
            .field("contents", contents)
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}